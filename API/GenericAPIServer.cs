// Copyright (C) 2017-2025 Ixian
// This file is part of Ixian DLT - www.github.com/ixian-platform/Ixian-Core
//
// Ixian Core is free software: you can redistribute it and/or modify
// it under the terms of the MIT License as published
// by the Open Source Initiative.
//
// Ixian Core is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// MIT License for more details.

using IXICore.Activity;
using IXICore.Meta;
using IXICore.Network;
using IXICore.RegNames;
using IXICore.Utils;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using static IXICore.Transaction;

namespace IXICore
{
    //! RPC error codes
    public enum RPCErrorCode
    {
        //! Standard JSON-RPC 2.0 errors
        RPC_INVALID_REQUEST = -32600,
        RPC_METHOD_NOT_FOUND = -32601,
        RPC_INVALID_PARAMS = -32602,
        RPC_INTERNAL_ERROR = -32603,
        RPC_PARSE_ERROR = -32700,

        //! General application defined errors
        RPC_MISC_ERROR = -1,  //! std::exception thrown in command handling
        RPC_FORBIDDEN_BY_SAFE_MODE = -2,  //! Server is in safe mode, and command is not allowed in safe mode
        RPC_TYPE_ERROR = -3,  //! Unexpected type was passed as parameter
        RPC_INVALID_ADDRESS_OR_KEY = -5,  //! Invalid address or key
        RPC_OUT_OF_MEMORY = -7,  //! Ran out of memory during operation
        RPC_INVALID_PARAMETER = -8,  //! Invalid, missing or duplicate parameter
        RPC_DATABASE_ERROR = -20, //! Database error
        RPC_DESERIALIZATION_ERROR = -22, //! Error parsing or validating structure in raw format
        RPC_VERIFY_ERROR = -25, //! General error during transaction or block submission
        RPC_VERIFY_REJECTED = -26, //! Transaction or block was rejected by network rules
        RPC_VERIFY_ALREADY_IN_CHAIN = -27, //! Transaction already in chain
        RPC_IN_WARMUP = -28, //! Client still warming up

        //! P2P client errors
        RPC_CLIENT_NOT_CONNECTED = -9,  //! not connected
        RPC_CLIENT_IN_INITIAL_DOWNLOAD = -10, //! Still downloading initial blocks
        RPC_CLIENT_NODE_ALREADY_ADDED = -23, //! Node is already added
        RPC_CLIENT_NODE_NOT_ADDED = -24, //! Node has not been added before

        //! Wallet errors
        RPC_WALLET_ERROR = -4,  //! Unspecified problem with wallet (key not found etc.)
        RPC_WALLET_INSUFFICIENT_FUNDS = -6,  //! Not enough funds in wallet or account
        RPC_WALLET_INVALID_ACCOUNT_NAME = -11, //! Invalid account name
        RPC_WALLET_KEYPOOL_RAN_OUT = -12, //! Keypool ran out, call keypoolrefill first
        RPC_WALLET_UNLOCK_NEEDED = -13, //! Enter the wallet passphrase with walletpassphrase first
        RPC_WALLET_PASSPHRASE_INCORRECT = -14, //! The wallet passphrase entered was incorrect
        RPC_WALLET_WRONG_ENC_STATE = -15, //! Command given in wrong wallet encryption state (encrypting an encrypted wallet etc.)
        RPC_WALLET_ENCRYPTION_FAILED = -16, //! Failed to encrypt the wallet
        RPC_WALLET_ALREADY_UNLOCKED = -17, //! Wallet is already unlocked
    };

    public class JsonRpcRequest
    {
        public string id = null;
        public string method = null;
        public Dictionary<string, object> @params = null;
    }

    public class JsonError
    {
        public int code = 0;
        public string message = null;
    }

    public class JsonResponse
    {
        public object result = null;
        public JsonError error = null;
        public string id = null;
    }

    public class GenericAPIServer
    {
        protected HttpListener listener;
        protected Thread apiControllerThread;
        protected bool continueRunning;
        protected List<string> listenURLs;
        protected List<string> allowedIPs;
        protected ThreadLiveCheck TLC;

        protected Dictionary<string, string> authorizedUsers;

        protected IActivityStorage activityStorage;

        // Start the API server
        public void start(List<string> listen_URLs, Dictionary<string, string> authorized_users = null, List<string> allowed_IPs = null, IActivityStorage activity_storage = null)
        {
            continueRunning = true;

            listenURLs = listen_URLs;

            authorizedUsers = authorized_users;
            allowedIPs = allowed_IPs;

            activityStorage = activity_storage;

            apiControllerThread = new Thread(apiLoop);
            apiControllerThread.Name = "API_Controller_Thread";
            TLC = new ThreadLiveCheck();
            apiControllerThread.Start();
        }

        // Stop the API server
        public void stop()
        {
            continueRunning = false;
            try
            {
                // Stop the listener
                listener.Stop();
            }
            catch (Exception)
            {
                Logging.info("API server already stopped.");
            }
        }

        // Override the onUpdate handler
        protected virtual void onUpdate(HttpListenerContext context)
        {
            try
            {
                string post_data = "";
                string method_name = "";
                Dictionary<string, object> method_params = null;

                HttpListenerRequest request = context.Request;
                using (var reader = new StreamReader(request.InputStream, request.ContentEncoding))
                {
                    post_data = reader.ReadToEnd();
                }


                if (post_data.Length > 0)
                {
                    JsonRpcRequest post_data_json = JsonConvert.DeserializeObject<JsonRpcRequest>(post_data);
                    method_name = post_data_json.method;
                    method_params = post_data_json.@params;
                }
                else
                {
                    if (context.Request.Url.Segments.Length < 2)
                    {
                        // We will now show an embedded wallet if the API is called with no parameters
                        sendWallet(context);
                        return;
                    }

                    method_name = context.Request.Url.Segments[1].Replace("/", "");
                    method_params = new Dictionary<string, object>();
                    foreach (string key in context.Request.QueryString.Keys)
                    {
                        if (key != null && key != "")
                        {
                            string[] values = context.Request.QueryString.GetValues(key);
                            if (values == null || values.Length == 0)
                            {
                                values = new string[1] { "" };
                            }
                            if (key.EndsWith("[]"))
                            {
                                method_params.Add(key, values);
                            }
                            else
                            {
                                method_params.Add(key, values[0]);
                            }
                        }
                    }
                }

                if (method_name == null)
                {
                    context.Response.ContentType = "application/json";
                    JsonError error = new JsonError { code = (int)RPCErrorCode.RPC_INVALID_REQUEST, message = "Unknown action." };
                    sendResponse(context.Response, new JsonResponse { error = error });
                    return;
                }

                try
                {
                    Logging.trace("Processing request " + context.Request.Url);
                    if (!processRequest(context, method_name, method_params))
                    {
                        processGenericRequest(context, method_name, method_params);
                    }
                }
                catch (Exception e)
                {
                    context.Response.ContentType = "application/json";
                    JsonError error = new JsonError { code = (int)RPCErrorCode.RPC_INTERNAL_ERROR, message = "Unknown error occurred, see log for details." };
                    sendResponse(context.Response, new JsonResponse { error = error });
                    Logging.error("Exception occurred in API server while processing '{0}'. {1}", context.Request.Url, e);
                }
            }
            catch (Exception e)
            {
                context.Response.ContentType = "application/json";
                JsonError error = new JsonError { code = (int)RPCErrorCode.RPC_INTERNAL_ERROR, message = "Unknown error occurred, see log for details." };
                sendResponse(context.Response, new JsonResponse { error = error });
                Logging.error("Exception occurred in API server. {0}", e);
            }
        }

        public JsonResponse processDefaultRequest(HttpListenerContext context, string methodName, Dictionary<string, object> parameters)
        {
            JsonResponse response = null;

            if (methodName.Equals("shutdown", StringComparison.OrdinalIgnoreCase))
            {
                response = onShutdown();
            }

            if (methodName.Equals("reconnect", StringComparison.OrdinalIgnoreCase))
            {
                response = onReconnect(parameters);
            }

            if (methodName.Equals("connect", StringComparison.OrdinalIgnoreCase))
            {
                response = onConnect(parameters);
            }

            if (methodName.Equals("isolate", StringComparison.OrdinalIgnoreCase))
            {
                response = onIsolate();
            }

            if (methodName.Equals("addtransaction", StringComparison.OrdinalIgnoreCase))
            {
                response = onAddTransaction(parameters);
            }

            if (methodName.Equals("createrawtransaction", StringComparison.OrdinalIgnoreCase))
            {
                response = onCreateRawTransaction(parameters);
            }

            if (methodName.Equals("decoderawtransaction", StringComparison.OrdinalIgnoreCase))
            {
                response = onDecodeRawTransaction(parameters);
            }

            if (methodName.Equals("signrawtransaction", StringComparison.OrdinalIgnoreCase))
            {
                response = onSignRawTransaction(parameters);
            }

            if (methodName.Equals("sendrawtransaction", StringComparison.OrdinalIgnoreCase))
            {
                response = onSendRawTransaction(parameters);
            }

            if (methodName.Equals("calculatetransactionfee", StringComparison.OrdinalIgnoreCase))
            {
                if (parameters.ContainsKey("autofee"))
                {
                    response = new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMETER, message = "Automatic fee generation is invalid for `calculatetransactionfee`." } };
                }
                else
                {
                    response = onCalculateTransactionFee(parameters);
                }
            }

            /*if (methodName.Equals("addmultisigtransaction", StringComparison.OrdinalIgnoreCase))
            {
                response = onAddMultiSigTransaction(parameters);
            }

            if (methodName.Equals("addmultisigtxsignature", StringComparison.OrdinalIgnoreCase))
            {
                response = onAddMultiSigTxSignature(parameters);
            }

            if (methodName.Equals("addmultisigkey", StringComparison.OrdinalIgnoreCase))
            {
                response = onAddMultiSigKey(parameters);
            }

            if (methodName.Equals("delmultisigkey", StringComparison.OrdinalIgnoreCase))
            {
                response = onDelMultiSigKey(parameters);
            }

            if (methodName.Equals("changemultisigs", StringComparison.OrdinalIgnoreCase))
            {
                response = onChangeMultiSigs(parameters);
            }*/

            if (methodName.Equals("gettotalbalance", StringComparison.OrdinalIgnoreCase))
            {
                response = onGetTotalBalance(parameters);
            }

            if (methodName.Equals("mywallet", StringComparison.OrdinalIgnoreCase))
            {
                response = onMyWallet(parameters);
            }

            if (methodName.Equals("mypubkey", StringComparison.OrdinalIgnoreCase))
            {
                response = onMyPubKey(parameters);
            }

            if (methodName.Equals("clients", StringComparison.OrdinalIgnoreCase))
            {
                response = onClients();
            }

            if (methodName.Equals("servers", StringComparison.OrdinalIgnoreCase))
            {
                response = onServers();
            }

            if (methodName.Equals("status", StringComparison.OrdinalIgnoreCase))
            {
                response = onStatus(parameters);
            }

            if (methodName.Equals("blockheight", StringComparison.OrdinalIgnoreCase))
            {
                response = onBlockHeight();
            }

            if (methodName.Equals("activity", StringComparison.OrdinalIgnoreCase))
            {
                response = onActivity(parameters);
            }

            if (methodName.Equals("activity2", StringComparison.OrdinalIgnoreCase))
            {
                response = onActivity2(parameters);
            }

            if (methodName.Equals("generatenewaddress", StringComparison.OrdinalIgnoreCase))
            {
                response = onGenerateNewAddress(parameters);
            }

            if (methodName.Equals("getwalletbackup", StringComparison.OrdinalIgnoreCase))
            {
                response = onGetWalletBackup(parameters);
            }

            if (methodName.Equals("getviewingwallet", StringComparison.OrdinalIgnoreCase))
            {
                response = onGetViewingWallet(parameters);
            }

            if (methodName.Equals("loadwallet", StringComparison.OrdinalIgnoreCase))
            {
                response = onLoadWallet(parameters);
            }

            if (methodName.Equals("unloadwallet", StringComparison.OrdinalIgnoreCase))
            {
                response = onUnloadWallet(parameters);
            }

            if (methodName.Equals("sign", StringComparison.OrdinalIgnoreCase))
            {
                response = onSign(parameters);
            }

            if (methodName.Equals("verify", StringComparison.OrdinalIgnoreCase))
            {
                response = onVerify(parameters);
            }

            if (methodName.Equals("listwallets", StringComparison.OrdinalIgnoreCase))
            {
                response = onListWallets();
            }

            if (methodName.Equals("validateaddress", StringComparison.OrdinalIgnoreCase))
            {
                response = onValidateAddress(parameters);
            }

            if (methodName.Equals("blacklistpeer", StringComparison.OrdinalIgnoreCase))
            {
                response = onBlacklistPeer(parameters);
            }

            if (methodName.Equals("clearpeerblacklist", StringComparison.OrdinalIgnoreCase))
            {
                response = onClearPeerBlacklist();
            }

            if (methodName.Equals("getpresence", StringComparison.OrdinalIgnoreCase))
            {
                response = onGetPresence(parameters);
            }

            if (methodName.Equals("pauseClient", StringComparison.OrdinalIgnoreCase))
            {
                NetworkClientManager.pause();
                response = new JsonResponse { result = "Network Client paused.", error = null };
            }

            if (methodName.Equals("resumeClient", StringComparison.OrdinalIgnoreCase))
            {
                NetworkClientManager.resume();
                response = new JsonResponse { result = "Network Client resumed.", error = null };
            }

            if (methodName.Equals("registerName", StringComparison.OrdinalIgnoreCase))
            {
                response = onRegisterName(parameters);
            }

            if (methodName.Equals("extendName", StringComparison.OrdinalIgnoreCase))
            {
                response = onExtendName(parameters);
            }

            if (methodName.Equals("updateNameCapacity", StringComparison.OrdinalIgnoreCase))
            {
                response = onUpdateNameCapacity(parameters);
            }

            if (methodName.Equals("recoverName", StringComparison.OrdinalIgnoreCase))
            {
                response = onRecoverName(parameters);
            }

            if (methodName.Equals("updateNameRecord", StringComparison.OrdinalIgnoreCase))
            {
                response = onUpdateNameRecord(parameters);
            }

            if (methodName.Equals("decodeNameData", StringComparison.OrdinalIgnoreCase))
            {
                response = onDecodeNameData(parameters);
            }

            if (methodName.Equals("decodeTransaction", StringComparison.OrdinalIgnoreCase))
            {
                response = onDecodeTransaction(parameters);
            }

            if (methodName.Equals("pl", StringComparison.OrdinalIgnoreCase))
            {
                response = onPl();
            }

            if (methodName.Equals("relaySectors", StringComparison.OrdinalIgnoreCase))
            {
                response = onRelaySectors();
            }


            if (methodName.Equals("getSectorNodes", StringComparison.OrdinalIgnoreCase))
            {
                response = onGetSectorNodes(parameters);
            }

            return response;
        }

        // Used as fallback in case processRequest returns false. In addition to handling the default requests, it also serves the web UI
        protected virtual bool processGenericRequest(HttpListenerContext context, string methodName, Dictionary<string, object> parameters)
        {
            JsonResponse response = processDefaultRequest(context, methodName, parameters);

            bool resources = false;

            if (methodName.Equals("resources", StringComparison.OrdinalIgnoreCase))
            {
                onResources(context);
                resources = true;
            }

            bool processed_request = false;

            if (!resources)
            {
                // Set the content type to plain to prevent xml parsing errors in various browsers
                context.Response.ContentType = "application/json";

                if (response == null)
                {
                    response = new JsonResponse() { error = new JsonError() { code = (int)RPCErrorCode.RPC_METHOD_NOT_FOUND, message = "Unknown API request '" + methodName + "'" } };
                    processed_request = false;
                }
                else
                {
                    processed_request = true;
                }

                sendResponse(context.Response, response);
            }
            else
            {
                processed_request = true;
            }
            context.Response.Close();
            return processed_request;
        }

        protected virtual bool processRequest(HttpListenerContext context, string methodName, Dictionary<string, object> parameters)
        {
            return false;
        }

        protected bool isAuthorized(HttpListenerContext context)
        {
            if (authorizedUsers == null)
            {
                return true;
            }

            // No authorized users provided, allow access to everyone
            if (authorizedUsers.Count < 1)
            {
                return true;
            }

            if (context.User == null)
            {
                return false;
            }

            HttpListenerBasicIdentity identity = (HttpListenerBasicIdentity)context.User.Identity;

            if (authorizedUsers.ContainsKey(identity.Name))
            {
                if (authorizedUsers[identity.Name] == identity.Password)
                {
                    return true;
                }
            }

            return false;
        }

        protected void apiLoop()
        {
            // Start a listener on the loopback interface
            listener = new HttpListener();
            try
            {
                foreach (string url in listenURLs)
                {
                    listener.Prefixes.Add(url);
                }

                if (authorizedUsers != null && authorizedUsers.Count > 0)
                {
                    listener.AuthenticationSchemes = AuthenticationSchemes.Basic;
                }

                listener.Start();
            }
            catch (Exception ex)
            {
                Logging.error("Cannot initialize API server! The error was: " + ex.Message);
                IxianHandler.forceShutdown = true;
                return;
            }

            while (continueRunning)
            {
                HttpListenerContext context = null;
                try
                {
                    context = listener.GetContext();
                }
                catch (Exception ex)
                {
                    if (continueRunning)
                    {
                        Logging.error("Error in API server! " + ex.Message);
                    }
                    return;
                }

                try
                {
                    if (context != null)
                    {
                        if (allowedIPs != null && allowedIPs.Count() > 0 && !allowedIPs.Contains(context.Request.RemoteEndPoint.Address.ToString()))
                        {
                            context.Response.Close();
                            Thread.Yield();
                            continue;
                        }
                        if (isAuthorized(context))
                        {
                            onUpdate(context);
                        }
                        else
                        {
                            context.Response.StatusCode = 401;
                            context.Response.StatusDescription = "401 Unauthorized";
                        }
                        context.Response.Close();
                    }
                }
                catch (Exception e)
                {
                    Logging.error("Error processing api request in GenericAPIServer.apiLoop: " + e);
                }
                TLC.Report();
                Thread.Yield();
            }

        }

        protected void sendError(HttpListenerContext context, string errorString)
        {
            sendResponse(context.Response, errorString);
        }

        protected void sendResponse(HttpListenerResponse responseObject, string responseString)
        {
            byte[] buffer = System.Text.Encoding.UTF8.GetBytes(responseString);

            try
            {
                responseObject.ContentLength64 = buffer.Length;
                System.IO.Stream output = responseObject.OutputStream;
                output.Write(buffer, 0, buffer.Length);
                output.Close();
            }
            catch (Exception e)
            {
                if (continueRunning)
                {
                    Logging.error("APIServer: {0}", e);
                }
            }
        }

        public void sendResponse(HttpListenerResponse responseObject, JsonResponse response)
        {
            string responseString = JsonConvert.SerializeObject(response, new JsonSerializerSettings() { ReferenceLoopHandling = ReferenceLoopHandling.Ignore });

            string responseError = "null";
            if (response.error != null)
            {
                try
                {
                    responseError = JsonConvert.SerializeObject(response.error);
                }
                catch (Exception)
                {
                    responseError = response.error.ToString();
                }
            }

            Logging.trace("Processed request, sending response with error code: {0}", responseError);

            byte[] buffer = Encoding.UTF8.GetBytes(responseString);

            try
            {
                responseObject.ContentLength64 = buffer.Length;
                Stream output = responseObject.OutputStream;
                output.Write(buffer, 0, buffer.Length);
                output.Close();
            }
            catch (Exception e)
            {
                if (continueRunning)
                {
                    Logging.error("APIServer: {0}", e);
                }
            }
        }

        public void sendResponse(HttpListenerResponse responseObject, byte[] buffer)
        {
            try
            {
                responseObject.ContentLength64 = buffer.Length;
                Stream output = responseObject.OutputStream;
                output.Write(buffer, 0, buffer.Length);
                output.Close();
            }
            catch (Exception e)
            {
                if (continueRunning)
                {
                    Logging.error("APIServer: {0}", e);
                }
            }
        }

        protected void onResources(HttpListenerContext context)
        {
            string name = "";
            for (int i = 2; i < context.Request.Url.Segments.Count(); i++)
            {
                name += context.Request.Url.Segments[i];
            }

            if (name != null && name.Length > 1 && !name.EndsWith("/"))
            {
                name = name.Replace('/', Path.DirectorySeparatorChar);
                string file_path = "html" + Path.DirectorySeparatorChar + name;
                if (File.Exists(file_path))
                {
                    if (name.EndsWith(".css", StringComparison.OrdinalIgnoreCase))
                    {
                        context.Response.ContentType = "text/css";
                    }
                    else if (name.EndsWith(".js", StringComparison.OrdinalIgnoreCase))
                    {
                        context.Response.ContentType = "text/javascript";
                    }
                    else if (name.EndsWith(".html", StringComparison.OrdinalIgnoreCase))
                    {
                        context.Response.ContentType = "text/html";
                    }
                    else
                    {
                        context.Response.ContentType = "application/octet-stream";
                    }
                    sendResponse(context.Response, File.ReadAllBytes(file_path));
                    return;
                }
                else
                {
                    Logging.error("File {0} is missing.", file_path);
                }
            }
            // 404
            context.Response.ContentType = "text/plain";
            context.Response.StatusCode = 404;
            context.Response.StatusDescription = "404 File not found";
            sendResponse(context.Response, "404 File not found");
        }

        // Send the embedded wallet html file
        protected void sendWallet(HttpListenerContext context)
        {
            string wallet_path = "html" + Path.DirectorySeparatorChar + "wallet.html";
            if (!File.Exists(wallet_path))
            {
                Logging.error("File {0} is missing.", wallet_path);
                return;
            }

            string wallet_html = File.ReadAllText(wallet_path);

            // Set the content type to html to show the wallet page
            context.Response.ContentType = "text/html";

            sendResponse(context.Response, wallet_html);
        }




        // Generic API Calls

        private JsonResponse onShutdown()
        {
            JsonError error = null;

            IxianHandler.shutdown();

            return new JsonResponse { result = "Node shutdown", error = error };
        }

        private JsonResponse onReconnect(Dictionary<string, object> parameters)
        {
            JsonError error = null;

            bool resetNetworkQueue = false;
            if (parameters.ContainsKey("resetNetworkQueue"))
            {
                resetNetworkQueue = true;
            }

            NetworkUtils.reconnect(resetNetworkQueue);

            return new JsonResponse { result = "Reconnecting node to network now.", error = error };
        }

        private JsonResponse onConnect(Dictionary<string, object> parameters)
        {
            JsonError error = null;

            if (!parameters.ContainsKey("to"))
            {
                error = new JsonError { code = (int)RPCErrorCode.RPC_INVALID_PARAMS, message = "to parameter is missing" };
                return new JsonResponse { result = null, error = error };
            }

            string to = (string)parameters["to"];

            NetworkClientManager.connectTo(to, null);

            return new JsonResponse { result = string.Format("Connecting to node {0}", to), error = error };
        }

        private JsonResponse onIsolate()
        {
            JsonError error = null;

            NetworkUtils.isolate();

            return new JsonResponse { result = "Isolating from network now.", error = error };
        }


        public JsonResponse onAddTransaction(Dictionary<string, object> parameters)
        {
            if (IxianHandler.status != NodeStatus.ready
                && IxianHandler.status != NodeStatus.stalled)
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_IN_WARMUP, message = String.Format("There was an error while creating the transaction: The node isn't ready to process this request yet.") } };
            }

            object r = createTransactionHelper(parameters);
            Transaction transaction = null;
            List<Address> relayNodeAddresses = null;
            if (r is JsonResponse)
            {
                // there was an error
                return (JsonResponse)r;
            }
            else if (r is TransactionWithRelays)
            {
                TransactionWithRelays helperResponse = (TransactionWithRelays)r;
                transaction = helperResponse.transaction;
                relayNodeAddresses = helperResponse.relayNodeAddresses;
            }
            else
            {
                return new JsonResponse
                {
                    result = null,
                    error = new JsonError()
                    {
                        code = (int)RPCErrorCode.RPC_INTERNAL_ERROR,
                        message = String.Format("There was an error while creating the transaction: Unexpected object: {0}", r.GetType().Name)
                    }
                };
            }
            if (IxianHandler.addTransaction(transaction, relayNodeAddresses, true))
            {
                PendingTransactions.addPendingLocalTransaction(transaction, relayNodeAddresses);
                return new JsonResponse { result = transaction.toDictionary(), error = null };
            }

            return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INTERNAL_ERROR, message = "An unknown error occurred while adding the transaction" } };
        }

        private JsonResponse onCreateRawTransaction(Dictionary<string, object> parameters)
        {
            // Create a transaction, but do not add it to the TX pool on the node. Useful for:
            // - offline transactions
            // - manually adjusting fee

            if (IxianHandler.status != NodeStatus.ready
                && IxianHandler.status != NodeStatus.stalled)
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_IN_WARMUP, message = String.Format("There was an error while creating the transaction: The node isn't ready to process this request yet.") } };
            }

            bool sign = false;
            if (parameters.ContainsKey("sign"))
            {
                sign = true;
            }

            object r = createTransactionHelper(parameters, sign);
            Transaction transaction = null;
            List<Address> relayNodeAddresses = null;
            if (r is JsonResponse)
            {
                // there was an error
                return (JsonResponse)r;
            }
            else if (r is TransactionWithRelays)
            {
                TransactionWithRelays helperResponse = (TransactionWithRelays)r;
                transaction = helperResponse.transaction;
                relayNodeAddresses = helperResponse.relayNodeAddresses;
            }
            else
            {
                return new JsonResponse
                {
                    result = null,
                    error = new JsonError()
                    {
                        code = (int)RPCErrorCode.RPC_INTERNAL_ERROR,
                        message = String.Format("There was an error while creating the transaction: Unexpected object: {0}", r.GetType().Name)
                    }
                };
            }
            if (parameters.ContainsKey("json"))
            {
                return new JsonResponse { result = transaction.toDictionary(), error = null };
            }
            else
            {
                return new JsonResponse { result = Crypto.hashToString(transaction.getBytes(true, true)), error = null };
            }
        }

        private JsonResponse onDecodeRawTransaction(Dictionary<string, object> parameters)
        {
            JsonError error = null;

            // transaction which alters a multisig wallet
            if (!parameters.ContainsKey("transaction"))
            {
                error = new JsonError { code = (int)RPCErrorCode.RPC_INVALID_PARAMETER, message = "transaction parameter is missing" };
                return new JsonResponse { result = null, error = error };
            }

            string raw_transaction_hex = (string)parameters["transaction"];

            Transaction raw_transaction = new Transaction(Crypto.stringToHash(raw_transaction_hex), false, true);
            return new JsonResponse { result = raw_transaction.toDictionary(), error = null };
        }

        private JsonResponse onSignRawTransaction(Dictionary<string, object> parameters)
        {
            JsonError error = null;

            // transaction which alters a multisig wallet
            object res = "Incorrect transaction parameters.";

            if (!parameters.ContainsKey("transaction"))
            {
                error = new JsonError { code = (int)RPCErrorCode.RPC_INVALID_PARAMETER, message = "transaction parameter is missing" };
                return new JsonResponse { result = null, error = error };
            }

            string raw_transaction_hex = (string)parameters["transaction"];

            Transaction raw_transaction = new Transaction(Crypto.stringToHash(raw_transaction_hex), false, true);
            raw_transaction.signature = raw_transaction.getSignature(raw_transaction.checksum);
            return new JsonResponse { result = Crypto.hashToString(raw_transaction.getBytes(true, true)), error = null };
        }

        private JsonResponse onSendRawTransaction(Dictionary<string, object> parameters)
        {
            if (IxianHandler.status != NodeStatus.ready
                && IxianHandler.status != NodeStatus.stalled)
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_IN_WARMUP, message = String.Format("There was an error while creating the transaction: The node isn't ready to process this request yet.") } };
            }

            JsonError error = null;

            // transaction which alters a multisig wallet
            object res = "Incorrect transaction parameters.";

            if (!parameters.ContainsKey("transaction"))
            {
                error = new JsonError { code = (int)RPCErrorCode.RPC_INVALID_PARAMETER, message = "transaction parameter is missing" };
                return new JsonResponse { result = null, error = error };
            }

            string raw_transaction_hex = (string)parameters["transaction"];

            Transaction raw_transaction = new Transaction(Crypto.stringToHash(raw_transaction_hex), false, true);

            if (!parameters.ContainsKey("relayNodeAddress"))
            {
                error = new JsonError { code = (int)RPCErrorCode.RPC_INVALID_PARAMETER, message = "relayNodeAddress parameter is missing" };
                return new JsonResponse { result = null, error = error };
            }

            List<Address> relayNodeAddresses = new() { new Address((string)parameters["relayNodeAddress"]) };

            if (IxianHandler.addTransaction(raw_transaction, relayNodeAddresses, true))
            {
                PendingTransactions.addPendingLocalTransaction(raw_transaction, relayNodeAddresses);
                return new JsonResponse { result = raw_transaction.toDictionary(), error = null };
            }

            return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_VERIFY_ERROR, message = "An unknown error occurred while adding the transaction" } };
        }

        private JsonResponse onCalculateTransactionFee(Dictionary<string, object> parameters)
        {
            // Create a dummy transaction, just so that we can calculate the appropriate fee required to process this (minimum fee)
            object r = createTransactionHelper(parameters);
            Transaction transaction = null;
            List<Address> relayNodeAddresses = null;
            if (r is JsonResponse)
            {
                // there was an error
                return (JsonResponse)r;
            }
            else if (r is TransactionWithRelays)
            {
                TransactionWithRelays helperResponse = (TransactionWithRelays)r;
                transaction = helperResponse.transaction;
                relayNodeAddresses = helperResponse.relayNodeAddresses;
            }
            else
            {
                return new JsonResponse
                {
                    result = null,
                    error = new JsonError()
                    {
                        code = (int)RPCErrorCode.RPC_INTERNAL_ERROR,
                        message = String.Format("There was an error while creating the transaction: Unexpected object: {0}", r.GetType().Name)
                    }
                };
            }
            return new JsonResponse { result = transaction.fee.ToString(), error = null };
        }

        /*private JsonResponse onAddMultiSigTxSignature(Dictionary<string, object> parameters)
        {
            if (IxianHandler.status != NodeStatus.ready
                && IxianHandler.status != NodeStatus.stalled)
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_IN_WARMUP, message = String.Format("There was an error while creating the transaction: The node isn't ready to process this request yet.") } };
            }

            JsonError error = null;

            // transaction which alters a multisig wallet
            object res = "Incorrect transaction parameters.";

            if (!parameters.ContainsKey("wallet"))
            {
                error = new JsonError { code = (int)RPCErrorCode.RPC_INVALID_PARAMETER, message = "wallet parameter is missing" };
                return new JsonResponse { result = null, error = error };
            }
            byte[] destWallet = Base58Check.Base58CheckEncoding.DecodePlain((string)parameters["wallet"]);

            if (!parameters.ContainsKey("origtx"))
            {
                error = new JsonError { code = (int)RPCErrorCode.RPC_INVALID_PARAMETER, message = "origtx parameter is missing" };
                return new JsonResponse { result = null, error = error };
            }
            byte[] orig_txid = Transaction.txIdLegacyToV8((string)parameters["origtx"]);
            // no need to check if orig_txid exists as it may not (yet) because we're C/W node, TODO TODO in the future we could query a M/H node

            IxiNumber fee = ConsensusConfig.forceTransactionPrice;

            Transaction transaction = Transaction.multisigAddTxSignature(orig_txid, fee, new Address(destWallet), IxianHandler.getHighestKnownNetworkBlockHeight());
            if (IxianHandler.addTransaction(transaction, true))
            {
                PendingTransactions.addPendingLocalTransaction(transaction);
                res = transaction.toDictionary();
            }
            else
            {
                error = new JsonError { code = (int)RPCErrorCode.RPC_INTERNAL_ERROR, message = "There was an error adding the transaction." };
                res = null;
            }

            return new JsonResponse { result = res, error = error };
        }

        private JsonResponse onAddMultiSigTransaction(Dictionary<string, object> parameters)
        {
            if (IxianHandler.status != NodeStatus.ready
                && IxianHandler.status != NodeStatus.stalled)
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_IN_WARMUP, message = String.Format("There was an error while creating the transaction: The node isn't ready to process this request yet.") } };
            }

            JsonError error = null;

            // Add a new transaction. This test allows sending and receiving from arbitrary addresses
            object res = "Incorrect transaction parameters.";

            if (!parameters.ContainsKey("to"))
            {
                error = new JsonError { code = (int)RPCErrorCode.RPC_INVALID_PARAMETER, message = "to parameter is missing" };
                return new JsonResponse { result = null, error = error };
            }

            IxiNumber amount = 0;
            IxiNumber fee = ConsensusConfig.forceTransactionPrice;
            Dictionary<Address, Transaction.ToEntry> toList = new Dictionary<Address, Transaction.ToEntry>(new AddressComparer());
            string[] to_split = ((string)parameters["to"]).Split('-');
            if (to_split.Length > 0)
            {
                foreach (string single_to in to_split)
                {
                    string[] single_to_split = single_to.Split('_');
                    byte[] single_to_address = Base58Check.Base58CheckEncoding.DecodePlain(single_to_split[0]);
                    if (!Address.validateChecksum(single_to_address))
                    {
                        res = "Incorrect to address.";
                        amount = 0;
                        break;
                    }
                    IxiNumber singleToAmount = new IxiNumber(single_to_split[1]);
                    if (singleToAmount < 0 || singleToAmount == 0)
                    {
                        res = "Incorrect amount.";
                        amount = 0;
                        break;
                    }
                    amount += singleToAmount;
                    Transaction.ToEntry toEntry = new Transaction.ToEntry(Transaction.getExpectedVersion(IxianHandler.getLastBlockVersion()), singleToAmount, null, null);
                    toList.Add(new Address(single_to_address), toEntry);
                }
            }
            if (parameters.ContainsKey("fee") && ((string)parameters["fee"]).Length > 0)
            {
                string fee_string = (string)parameters["fee"];
                fee = new IxiNumber(fee_string);
            }

            if (!parameters.ContainsKey("from"))
            {
                error = new JsonError { code = (int)RPCErrorCode.RPC_INVALID_PARAMETER, message = "from parameter is missing" };
                return new JsonResponse { result = null, error = error };
            }

            Address from = new Address(Base58Check.Base58CheckEncoding.DecodePlain((string)parameters["from"]));
            if (IxianHandler.getWallet(from).type != WalletType.Multisig)
            {
                error = new JsonError { code = (int)RPCErrorCode.RPC_WALLET_ERROR, message = "The specified 'from' wallet is not a multisig wallet." };
                return new JsonResponse { result = null, error = error };
            }
            // Only create a transaction if there is a valid amount
            if (amount > 0)
            {
                Transaction transaction = Transaction.multisigTransaction(fee, toList, from, IxianHandler.getHighestKnownNetworkBlockHeight());
                if (transaction == null)
                {
                    error = new JsonError { code = (int)RPCErrorCode.RPC_INTERNAL_ERROR, message = "An error occurred while creating multisig transaction" };
                    return new JsonResponse { result = null, error = error };
                }
                Wallet wallet = IxianHandler.getWallet(from);
                if (wallet.balance < transaction.amount + transaction.fee)
                {
                    error = new JsonError { code = (int)RPCErrorCode.RPC_WALLET_INSUFFICIENT_FUNDS, message = "Your account's balance is less than the sending amount + fee." };
                    return new JsonResponse { result = null, error = error };
                }
                else
                {
                    if (IxianHandler.addTransaction(transaction, true))
                    {
                        PendingTransactions.addPendingLocalTransaction(transaction);
                        res = transaction.toDictionary();
                    }
                    else
                    {
                        error = new JsonError { code = (int)RPCErrorCode.RPC_INTERNAL_ERROR, message = "An error occurred while creating multisig transaction" };
                        return new JsonResponse { result = null, error = error };
                    }
                }
            }

            return new JsonResponse { result = res, error = error };
        }

        private JsonResponse onAddMultiSigKey(Dictionary<string, object> parameters)
        {
            if (IxianHandler.status != NodeStatus.ready
                && IxianHandler.status != NodeStatus.stalled)
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_IN_WARMUP, message = String.Format("There was an error while creating the transaction: The node isn't ready to process this request yet.") } };
            }

            // transaction which alters a multisig wallet
            if (!parameters.ContainsKey("wallet"))
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMS, message = "Parameter 'wallet' is missing." } };
            }
            Address destWallet = new Address(Base58Check.Base58CheckEncoding.DecodePlain((string)parameters["wallet"]));

            if (!parameters.ContainsKey("signer"))
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMS, message = "Parameter 'signer' is missing." } };
            }
            string signer = (string)parameters["signer"];

            Address signer_address = new Address(Base58Check.Base58CheckEncoding.DecodePlain(signer));
            IxiNumber fee = ConsensusConfig.forceTransactionPrice;

            Transaction transaction = Transaction.multisigAddKeyTransaction(signer_address, fee, destWallet, IxianHandler.getHighestKnownNetworkBlockHeight());
            if (IxianHandler.addTransaction(transaction, true))
            {
                PendingTransactions.addPendingLocalTransaction(transaction);
                return new JsonResponse { result = transaction.toDictionary(), error = null };
            }
            return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INTERNAL_ERROR, message = "Error while creating the transaction." } };
        }

        private JsonResponse onDelMultiSigKey(Dictionary<string, object> parameters)
        {
            if (IxianHandler.status != NodeStatus.ready
                && IxianHandler.status != NodeStatus.stalled)
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_IN_WARMUP, message = String.Format("There was an error while creating the transaction: The node isn't ready to process this request yet.") } };
            }

            // transaction which alters a multisig wallet
            object res = "Incorrect transaction parameters.";

            if (!parameters.ContainsKey("wallet"))
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMS, message = "Parameter 'wallet' is missing." } };
            }
            Address destWallet = new Address(Base58Check.Base58CheckEncoding.DecodePlain((string)parameters["wallet"]));

            if (!parameters.ContainsKey("signer"))
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMS, message = "Parameter 'signer' is missing." } };
            }
            string signer = (string)parameters["signer"];

            Address signer_address = new Address(Base58Check.Base58CheckEncoding.DecodePlain(signer));

            IxiNumber fee = ConsensusConfig.forceTransactionPrice;

            Transaction transaction = Transaction.multisigDelKeyTransaction(signer_address, fee, destWallet, IxianHandler.getHighestKnownNetworkBlockHeight());
            if (IxianHandler.addTransaction(transaction, true))
            {
                PendingTransactions.addPendingLocalTransaction(transaction);
                return new JsonResponse { result = transaction.toDictionary(), error = null };
            }
            return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INTERNAL_ERROR, message = "Error while creating the transaction." } };
        }

        private JsonResponse onChangeMultiSigs(Dictionary<string, object> parameters)
        {
            if (IxianHandler.status != NodeStatus.ready
                && IxianHandler.status != NodeStatus.stalled)
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_IN_WARMUP, message = String.Format("There was an error while creating the transaction: The node isn't ready to process this request yet.") } };
            }

            // transaction which alters a multisig wallet
            object res = "Incorrect transaction parameters.";

            if (!parameters.ContainsKey("wallet"))
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMS, message = "Parameter 'wallet' is missing." } };
            }
            Address destWallet = new Address(Base58Check.Base58CheckEncoding.DecodePlain((string)parameters["wallet"]));

            if (!parameters.ContainsKey("sigs"))
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMS, message = "Parameter 'sigs' is missing." } };
            }
            string sigs = (string)parameters["sigs"];

            IxiNumber fee = ConsensusConfig.forceTransactionPrice;
            if (byte.TryParse(sigs, out byte reqSigs))
            {

                Transaction transaction = Transaction.multisigChangeReqSigs(reqSigs, fee, destWallet, IxianHandler.getHighestKnownNetworkBlockHeight());
                if (IxianHandler.addTransaction(transaction, true))
                {
                    PendingTransactions.addPendingLocalTransaction(transaction);
                    return new JsonResponse { result = transaction.toDictionary(), error = null };
                }
            }
            else
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMETER, message = "Parameter 'sigs' must be a number between 1 and 255." } };
            }

            return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INTERNAL_ERROR, message = "Error while creating the transaction." } };
        }*/

        private JsonResponse onGetTotalBalance(Dictionary<string, object> parameters)
        {
            Address wallet = null;
            if (parameters.ContainsKey("wallet"))
            {
                wallet = new Address(Base58Check.Base58CheckEncoding.DecodePlain((string)parameters["wallet"]));
            }

            IxiNumber balance = IxianHandler.getWalletStorage(wallet).getMyTotalBalance(IxianHandler.getWalletStorage(wallet).getPrimaryAddress());
            // TODO TODO TODO TODO adapt the following line for v3 wallets
            balance -= PendingTransactions.getPendingSendingTransactionsAmount(null);
            return new JsonResponse { result = balance.ToString(), error = null };
        }


        private JsonResponse onMyWallet(Dictionary<string, object> parameters)
        {
            JsonError error = null;

            Address wallet = null;
            if (parameters.ContainsKey("wallet"))
            {
                wallet = new Address(Base58Check.Base58CheckEncoding.DecodePlain((string)parameters["wallet"]));
            }

            // Show own address, balance and blockchain synchronization status
            List<Address> address_list = IxianHandler.getWalletStorage(wallet).getMyAddresses();

            Dictionary<string, string> address_balance_list = new Dictionary<string, string>();

            foreach (Address addr in address_list)
            {
                address_balance_list.Add(addr.ToString(), IxianHandler.getWalletBalance(addr).ToString());
            }

            return new JsonResponse { result = address_balance_list, error = error };
        }

        private JsonResponse onMyPubKey(Dictionary<string, object> parameters)
        {
            JsonError error = null;

            Address wallet = null;
            if (parameters.ContainsKey("wallet"))
            {
                wallet = new Address(Base58Check.Base58CheckEncoding.DecodePlain((string)parameters["wallet"]));
            }

            return new JsonResponse { result = Crypto.hashToString(IxianHandler.getWalletStorage(wallet).getPrimaryPublicKey()), error = error };
        }

        private JsonResponse onClients()
        {
            JsonError error = null;

            String[] res = NetworkServer.getConnectedClients();

            return new JsonResponse { result = res, error = error };
        }

        private JsonResponse onServers()
        {
            JsonError error = null;

            String[] res = NetworkClientManager.getConnectedClients(true);

            return new JsonResponse { result = res, error = error };
        }

        protected Dictionary<string, object> getStatus(bool verbose)
        {
            Dictionary<string, object> status = new Dictionary<string, object>();

            status.Add("Core Version", CoreConfig.version);
            status.Add("Node Version", CoreConfig.productVersion);
            status.Add("Network type", IxianHandler.networkType.ToString());
            status.Add("My time", Clock.getTimestamp());
            status.Add("Network time difference", Clock.networkTimeDifference);
            status.Add("Real network time difference", Clock.realNetworkTimeDifference);
            status.Add("My External IP", IxianHandler.publicIP);
            status.Add("My Listening Port", IxianHandler.publicPort);
            //status.Add("Listening interface", context.Request.RemoteEndPoint.Address.ToString());

            status.Add("Core Status", IxianHandler.status);

            status.Add("Block Height", IxianHandler.getLastBlockHeight());
            status.Add("Block Version", IxianHandler.getLastBlockVersion());
            status.Add("Network Block Height", IxianHandler.getHighestKnownNetworkBlockHeight());
            status.Add("Node Type", PresenceList.myPresenceType);
            status.Add("Connectable", NetworkServer.isConnectable());

            if (verbose)
            {
                Dictionary<string, object> queues = new Dictionary<string, object>();
                queues.Add("RcvLow", NetworkQueue.getLowPriorityMessageCount());
                queues.Add("RcvMedium", NetworkQueue.getMediumPriorityMessageCount());
                queues.Add("RcvHigh", NetworkQueue.getHighPriorityMessageCount());
                queues.Add("SendClients", NetworkServer.getQueuedMessageCount());
                queues.Add("SendServers", NetworkClientManager.getQueuedMessageCount());
                queues.Add("Logging", Logging.getRemainingStatementsCount());
                queues.Add("Pending Transactions", PendingTransactions.pendingTransactionCount());

                status.Add("Queues", queues);

                status.Add("Presences", PresenceList.getTotalPresences());

                status.Add("Masters", PresenceList.countPresences('M'));
                status.Add("Relays", PresenceList.countPresences('R'));
                status.Add("Clients", PresenceList.countPresences('C'));
            }

            status.Add("Network Clients", NetworkServer.getConnectedClients());
            status.Add("Network Servers", NetworkClientManager.getConnectedClients(true));
            status.Add("Stream Servers", StreamClientManager.getConnectedClients(true));

            return status;
        }

        private JsonResponse onStatus(Dictionary<string, object> parameters)
        {
            bool verbose = false;

            if (parameters.ContainsKey("verbose"))
            {
                verbose = true;
            }

            var status = getStatus(verbose);

            return new JsonResponse { result = status, error = null };
        }

        private JsonResponse onBlockHeight()
        {
            JsonError error = null;

            ulong blockheight = IxianHandler.getLastBlockHeight();

            return new JsonResponse { result = blockheight, error = error };
        }

        private JsonResponse onActivity(Dictionary<string, object> parameters)
        {
            return new JsonResponse
            {
                result = null,
                error = new JsonError()
                {
                    code = (int)RPCErrorCode.RPC_INVALID_REQUEST,
                    message = "/activity has been deprecated, please use /activity2?wallet=&type=&count=&fromId=&descending="
                }
            };
        }

        private JsonResponse onActivity2(Dictionary<string, object> parameters)
        {
            if (activityStorage == null)
            {
                return new JsonResponse
                {
                    result = null,
                    error = new JsonError()
                    {
                        code = (int)RPCErrorCode.RPC_INTERNAL_ERROR,
                        message = "/activity2 can't be used, because ActivityStorage was not implemented."
                    }
                };
            }

            JsonError error = null;

            byte[] fromKey = null;
            if (parameters.ContainsKey("fromId"))
            {
                fromKey = Convert.FromBase64String((string)parameters["fromId"]);
            }

            string count = "50";
            if (parameters.ContainsKey("count"))
            {
                count = (string)parameters["count"];
            }

            int type = -1;
            if (parameters.ContainsKey("type"))
            {
                type = Int32.Parse((string)parameters["type"]);
            }

            bool descending = false;
            if (parameters.ContainsKey("descending") && (string)parameters["descending"] == "true")
            {
                descending = true;
            }

            Address wallet = null;
            if (parameters.ContainsKey("wallet"))
            {
                wallet = new Address(Base58Check.Base58CheckEncoding.DecodePlain((string)parameters["wallet"]));
            }

            List<ActivityObject> res;

            if (type == -1 || type == (int)ActivityType.None)
            {
                res = activityStorage.getActivitiesBySeedHashAndType(IxianHandler.getWalletStorage(wallet).getSeedHash(), null, fromKey, Int32.Parse(count), descending);
            }
            else
            {
                res = activityStorage.getActivitiesBySeedHashAndType(IxianHandler.getWalletStorage(wallet).getSeedHash(), (ActivityType)type, fromKey, Int32.Parse(count), descending);
            }
            return new JsonResponse { result = res, error = error };
        }

        private JsonResponse onGenerateNewAddress(Dictionary<string, object> parameters)
        {
            Address wallet_address = null;
            if (parameters.ContainsKey("wallet"))
            {
                wallet_address = new Address(Base58Check.Base58CheckEncoding.DecodePlain((string)parameters["wallet"]));
            }

            string base_address_str = null;
            if (parameters.ContainsKey("address"))
            {
                base_address_str = (string)parameters["address"];
            }

            Address base_address;
            if (base_address_str == null)
            {
                base_address = IxianHandler.getWalletStorage(wallet_address).getPrimaryAddress();
            }
            else
            {
                base_address = new Address(Base58Check.Base58CheckEncoding.DecodePlain(base_address_str));
            }

            Address new_address = IxianHandler.getWalletStorage(wallet_address).generateNewAddress(base_address, null);
            if (new_address != null)
            {
                return new JsonResponse { result = new_address.ToString(), error = null };
            }
            else
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_WALLET_ERROR, message = "Error occurred while generating a new address" } };
            }
        }

        private JsonResponse onGetWalletBackup(Dictionary<string, object> parameters)
        {
            Address wallet = null;
            if (parameters.ContainsKey("wallet"))
            {
                wallet = new Address(Base58Check.Base58CheckEncoding.DecodePlain((string)parameters["wallet"]));
            }
            return new JsonResponse { result = "IXIHEX" + Crypto.hashToString(IxianHandler.getWalletStorage(wallet).getRawWallet()), error = null };
        }

        private JsonResponse onGetViewingWallet(Dictionary<string, object> parameters)
        {
            Address wallet = null;
            if (parameters.ContainsKey("wallet"))
            {
                wallet = new Address(Base58Check.Base58CheckEncoding.DecodePlain((string)parameters["wallet"]));
            }
            return new JsonResponse { result = "IXIHEX" + Crypto.hashToString(IxianHandler.getWalletStorage(wallet).getRawViewingWallet()), error = null };
        }

        private JsonResponse onLoadWallet(Dictionary<string, object> parameters)
        {
            if (!parameters.ContainsKey("file"))
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMS, message = "Missing parameter 'file'." } };
            }
            if (!parameters.ContainsKey("password"))
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMS, message = "Missing parameter 'password'." } };
            }

            string file = (string)parameters["file"];
            string password = (string)parameters["password"];

            WalletStorage ws = IxianHandler.getWalletStorageByFilename(file);
            if (ws == null)
            {
                ws = new WalletStorage(file);
                if (!ws.readWallet(password))
                {
                    return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_WALLET_ERROR, message = "Error occurred while reading wallet file - incorrect password or file doesn't exist." } };
                }

                IxianHandler.addWallet(ws);
                ws.scanForLostAddresses();
            }

            return new JsonResponse { result = ws.getPrimaryAddress().ToString(), error = null };
        }

        private JsonResponse onUnloadWallet(Dictionary<string, object> parameters)
        {
            if (!parameters.ContainsKey("wallet"))
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMS, message = "Missing parameter 'wallet'." } };
            }

            Address wallet = new Address(Base58Check.Base58CheckEncoding.DecodePlain((string)parameters["wallet"]));
            if (IxianHandler.removeWallet(wallet))
            {
                return new JsonResponse { result = "OK", error = null };
            }
            else
            {
                return new JsonResponse { result = "FAIL", error = null };
            }
        }

        // Signs message or hash
        private JsonResponse onSign(Dictionary<string, object> parameters)
        {
            Address wallet = null;
            if (parameters.ContainsKey("wallet"))
            {
                wallet = new Address(Base58Check.Base58CheckEncoding.DecodePlain((string)parameters["wallet"]));
            }


            string signature;

            if (parameters.ContainsKey("message"))
            {
                string message = (string)parameters["message"];
                byte[] hash = CryptoManager.lib.sha3_512sqTrunc(UTF8Encoding.UTF8.GetBytes(message));
                signature = Crypto.hashToString(CryptoManager.lib.getSignature(hash, IxianHandler.getWalletStorage(wallet).getPrimaryPrivateKey()));

            }
            else if (parameters.ContainsKey("hash"))
            {
                byte[] hash = Crypto.stringToHash((string)parameters["hash"]);
                signature = Crypto.hashToString(CryptoManager.lib.getSignature(hash, IxianHandler.getWalletStorage(wallet).getPrimaryPrivateKey()));
            }
            else
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMS, message = "Missing parameter 'message' or 'hash'." } };
            }

            return new JsonResponse { result = signature, error = null };
        }

        // Verifies message or hash
        private JsonResponse onVerify(Dictionary<string, object> parameters)
        {
            if (!parameters.ContainsKey("publicKey"))
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMS, message = "Missing parameter 'publicKey'." } };
            }

            if (!parameters.ContainsKey("signature"))
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMS, message = "Missing parameter 'signature'." } };
            }

            byte[] publicKey = Crypto.stringToHash((string)parameters["publicKey"]);
            byte[] signature = Crypto.stringToHash((string)parameters["signature"]);

            bool sigOk = false;

            if (parameters.ContainsKey("message"))
            {
                string message = (string)parameters["message"];
                byte[] hash = CryptoManager.lib.sha3_512sqTrunc(UTF8Encoding.UTF8.GetBytes(message));
                sigOk = CryptoManager.lib.verifySignature(hash, publicKey, signature);

            }
            else if (parameters.ContainsKey("hash"))
            {
                byte[] hash = Crypto.stringToHash((string)parameters["hash"]);
                sigOk = CryptoManager.lib.verifySignature(hash, publicKey, signature);
            }
            else
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMS, message = "Missing parameter 'message' or 'hash'." } };
            }

            if (sigOk)
            {
                return new JsonResponse { result = "OK", error = null };
            }
            else
            {
                return new JsonResponse { result = "FAIL", error = null };
            }
        }

        private JsonResponse onListWallets()
        {
            return new JsonResponse { result = IxianHandler.getWalletList(), error = null };
        }

        // Returns "OK" if checksum of the address passes and error RPC_INVALID_ADDRESS_OR_KEY if the address is incorrect
        private JsonResponse onValidateAddress(Dictionary<string, object> parameters)
        {
            string address = null;
            if (parameters.ContainsKey("address"))
            {
                address = (string)parameters["address"];
            }

            byte[] address_bytes = null;
            try
            {
                address_bytes = Base58Check.Base58CheckEncoding.DecodePlain(address);
            }
            catch (Exception)
            {
                address_bytes = null;
            }

            if (address_bytes == null || !Address.validateChecksum(address_bytes))
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_ADDRESS_OR_KEY, message = "Invalid address was specified" } };
            }

            return new JsonResponse { result = "OK", error = null };
        }

        private JsonResponse onBlacklistPeer(Dictionary<string, object> parameters)
        {
            if (parameters.ContainsKey("host"))
            {
                string host = (string)parameters["host"];
                PeerStorage.blacklist(host);
            }
            if (parameters.ContainsKey("wallet"))
            {
                Address address = new Address(Base58Check.Base58CheckEncoding.DecodePlain((string)parameters["wallet"]));
                PeerStorage.blacklist(address);
            }
            return new JsonResponse { result = "OK", error = null };
        }

        private JsonResponse onClearPeerBlacklist()
        {
            PeerStorage.clearBlacklist();
            return new JsonResponse { result = "OK", error = null };
        }

        private JsonResponse onGetPresence(Dictionary<string, object> parameters)
        {
            if (!parameters.ContainsKey("wallet"))
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMS, message = "Missing parameter 'wallet'" } };
            }
            Address address = new Address(Base58Check.Base58CheckEncoding.DecodePlain((string)parameters["wallet"]));
            Presence p = PresenceList.getPresenceByAddress(address);
            if (p != null)
            {
                return new JsonResponse { result = p, error = null };
            }
            return new JsonResponse { result = null, error = null };
        }

        private JsonResponse onRegisterName(Dictionary<string, object> parameters)
        {
            if (!parameters.ContainsKey("name"))
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMS, message = "Missing parameter 'name'" } };
            }
            if (!parameters.ContainsKey("registrationTime"))
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMS, message = "Missing parameter 'registrationTime'" } };
            }
            if (!parameters.ContainsKey("capacity"))
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMS, message = "Missing parameter 'capacity'" } };
            }
            byte[] nameBytes = IxiNameUtils.encodeAndHashIxiName((string)parameters["name"]);
            Address recoveryHash = IxianHandler.primaryWalletAddress;
            if (parameters.ContainsKey("recoveryHash"))
            {
                recoveryHash = new Address((string)parameters["recoveryHash"]);
            }
            Address pkHash = IxianHandler.primaryWalletAddress;
            if (parameters.ContainsKey("pkHash"))
            {
                pkHash = new Address((string)parameters["pkHash"]);
            }
            uint regTime = uint.Parse((string)parameters["registrationTime"]);
            uint capacity = uint.Parse((string)parameters["capacity"]);
            ToEntry toEntry = RegisteredNamesTransactions.createRegisterToEntry(nameBytes, regTime, capacity, recoveryHash, pkHash, ConsensusConfig.rnPricePerUnit * (ulong)capacity * (ulong)(regTime / ConsensusConfig.rnMonthInBlocks));

            var txTuple = createRegNameTransaction(toEntry, null, null);
            Transaction fundedTx = txTuple.tx;
            List<Address> relayNodeAddresses = txTuple.relayNodeAddresses;
            if (fundedTx == null)
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INTERNAL_ERROR, message = "An unknown error occurred while funding the transaction" } };
            }

            if (IxianHandler.addTransaction(fundedTx, relayNodeAddresses, true))
            {
                PendingTransactions.addPendingLocalTransaction(fundedTx, relayNodeAddresses);
                return new JsonResponse { result = fundedTx.toDictionary(), error = null };
            }

            return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INTERNAL_ERROR, message = "An unknown error occurred while adding the transaction" } };
        }

        private JsonResponse onExtendName(Dictionary<string, object> parameters)
        {
            if (!parameters.ContainsKey("name"))
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMS, message = "Missing parameter 'name'" } };
            }
            if (!parameters.ContainsKey("extensionTime"))
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMS, message = "Missing parameter 'extensionTime'" } };
            }
            byte[] nameBytes = IxiNameUtils.encodeAndHashIxiName((string)parameters["name"]);
            uint regTime = uint.Parse((string)parameters["extensionTime"]);
            var name = IxianHandler.getRegName(nameBytes);
            var capacity = name.capacity;
            ToEntry toEntry = RegisteredNamesTransactions.createExtendToEntry(nameBytes, regTime, ConsensusConfig.rnPricePerUnit * (ulong)capacity * (ulong)(regTime / ConsensusConfig.rnMonthInBlocks));

            var txTuple = createRegNameTransaction(toEntry, null, null);
            Transaction fundedTx = txTuple.tx;
            List<Address> relayNodeAddresses = txTuple.relayNodeAddresses;
            if (fundedTx == null)
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INTERNAL_ERROR, message = "An unknown error occurred while funding the transaction" } };
            }

            if (IxianHandler.addTransaction(fundedTx, relayNodeAddresses, true))
            {
                PendingTransactions.addPendingLocalTransaction(fundedTx, relayNodeAddresses);
                return new JsonResponse { result = fundedTx.toDictionary(), error = null };
            }

            return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INTERNAL_ERROR, message = "An unknown error occurred while adding the transaction" } };
        }

        private JsonResponse onUpdateNameCapacity(Dictionary<string, object> parameters)
        {
            if (!parameters.ContainsKey("name"))
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMS, message = "Missing parameter 'name'" } };
            }
            if (!parameters.ContainsKey("newCapacity"))
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMS, message = "Missing parameter 'newCapacity'" } };
            }
            byte[] nameBytes = IxiNameUtils.encodeAndHashIxiName((string)parameters["name"]);
            var name = IxianHandler.getRegName(nameBytes);

            uint newCapacity = uint.Parse((string)parameters["newCapacity"]);

            Address nextPkHash = IxianHandler.primaryWalletAddress;
            if (parameters.ContainsKey("nextPkHash"))
            {
                nextPkHash = new Address((string)parameters["nextPkHash"]);
            }

            var curPkHash = name.nextPkHash;
            Address sigPk = new Address(IxianHandler.getWalletStorage(curPkHash).getPrimaryPublicKey());
            if (parameters.ContainsKey("sigPk"))
            {
                sigPk = new Address((string)parameters["sigPk"]);
            }

            ulong months = name.expirationBlockHeight / ConsensusConfig.rnMonthInBlocks;
            ulong sequence = name.sequence + 1;

            byte[] sig;
            if (parameters.ContainsKey("sig"))
            {
                sig = Convert.FromBase64String((string)parameters["sig"]);
            }
            else
            {
                name.setCapacity(newCapacity, sequence, nextPkHash, null, null, 0);
                var newChecksum = name.calculateChecksum();
                sig = CryptoManager.lib.getSignature(newChecksum, IxianHandler.getWalletStorage(curPkHash).getPrimaryPrivateKey());
            }

            ToEntry toEntry = RegisteredNamesTransactions.createChangeCapacityToEntry(nameBytes, newCapacity, sequence, nextPkHash, sigPk, sig, ConsensusConfig.rnPricePerUnit * months * (ulong)newCapacity);

            var txTuple = createRegNameTransaction(toEntry, null, null);
            Transaction fundedTx = txTuple.tx;
            List<Address> relayNodeAddresses = txTuple.relayNodeAddresses;
            if (fundedTx == null)
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INTERNAL_ERROR, message = "An unknown error occurred while funding the transaction" } };
            }

            if (IxianHandler.addTransaction(fundedTx, relayNodeAddresses, true))
            {
                PendingTransactions.addPendingLocalTransaction(fundedTx, relayNodeAddresses);
                return new JsonResponse { result = fundedTx.toDictionary(), error = null };
            }

            return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INTERNAL_ERROR, message = "An unknown error occurred while adding the transaction" } };
        }

        private JsonResponse onRecoverName(Dictionary<string, object> parameters)
        {
            if (!parameters.ContainsKey("name"))
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMS, message = "Missing parameter 'name'" } };
            }
            byte[] nameBytes = IxiNameUtils.encodeAndHashIxiName((string)parameters["name"]);
            Address nextPkHash = IxianHandler.primaryWalletAddress;
            if (parameters.ContainsKey("nextPkHash"))
            {
                nextPkHash = new Address((string)parameters["nextPkHash"]);
            }
            Address nextRecoveryHash = IxianHandler.primaryWalletAddress;
            if (parameters.ContainsKey("nextRecoveryHash"))
            {
                nextRecoveryHash = new Address((string)parameters["nextRecoveryHash"]);
            }
            var name = IxianHandler.getRegName(nameBytes);
            var curPkHash = name.nextPkHash;
            Address sigPk = new Address(IxianHandler.getWalletStorage(curPkHash).getPrimaryPublicKey());
            if (parameters.ContainsKey("sigPk"))
            {
                sigPk = new Address((string)parameters["sigPk"]);
            }
            ulong sequence = name.sequence + 1;

            byte[] sig;

            if (parameters.ContainsKey("sig"))
            {
                sig = Convert.FromBase64String((string)parameters["sig"]);
            }
            else
            {
                var newChecksum = RegisteredNamesTransactions.calculateRegNameChecksumForRecovery(name, nameBytes, nextRecoveryHash, sequence, nextPkHash);
                sig = CryptoManager.lib.getSignature(newChecksum, IxianHandler.getWalletStorage(curPkHash).getPrimaryPrivateKey());
            }

            ToEntry toEntry = RegisteredNamesTransactions.createRecoverToEntry(nameBytes, sequence, nextPkHash, nextRecoveryHash, sigPk, sig);

            var txTuple = createRegNameTransaction(toEntry, null, null);
            Transaction fundedTx = txTuple.tx;
            List<Address> relayNodeAddresses = txTuple.relayNodeAddresses;
            if (fundedTx == null)
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INTERNAL_ERROR, message = "An unknown error occurred while funding the transaction" } };
            }

            if (IxianHandler.addTransaction(fundedTx, relayNodeAddresses, true))
            {
                PendingTransactions.addPendingLocalTransaction(fundedTx, relayNodeAddresses);
                return new JsonResponse { result = fundedTx.toDictionary(), error = null };
            }

            return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INTERNAL_ERROR, message = "An unknown error occurred while adding the transaction" } };
        }

        private JsonResponse onUpdateNameRecord(Dictionary<string, object> parameters)
        {
            if (!parameters.ContainsKey("name"))
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMS, message = "Missing parameter 'name'" } };
            }

            if (!parameters.ContainsKey("records[]"))
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMS, message = "Missing parameter/s 'records[]'" } };
            }
            string namePlainText = (string)parameters["name"];
            byte[] nameBytes = IxiNameUtils.encodeAndHashIxiName(namePlainText);
            Address nextPkHash = IxianHandler.primaryWalletAddress;
            if (parameters.ContainsKey("nextPkHash"))
            {
                nextPkHash = new Address((string)parameters["nextPkHash"]);
            }
            var name = IxianHandler.getRegName(nameBytes);
            var curPkHash = name.nextPkHash;
            Address sigPk = new Address(IxianHandler.getWalletStorage(curPkHash).getPrimaryPublicKey());
            if (parameters.ContainsKey("sigPk"))
            {
                sigPk = new Address((string)parameters["sigPk"]);
            }
            ulong sequence = name.sequence + 1;

            List<RegisteredNameDataRecord> records = new List<RegisteredNameDataRecord>();
            foreach (var record in (string[])parameters["records[]"])
            {
                var splitRecord = record.Split(',');
                var recordKeyPlainText = splitRecord[0];
                RegisteredNameDataRecord rndr = new RegisteredNameDataRecord(IxiNameUtils.encodeAndHashIxiNameRecordKey(nameBytes, recordKeyPlainText), int.Parse(splitRecord[1]), IxiNameUtils.encryptRecord(UTF8Encoding.UTF8.GetBytes(namePlainText), UTF8Encoding.UTF8.GetBytes(recordKeyPlainText), UTF8Encoding.UTF8.GetBytes(splitRecord[2])));
                records.Add(rndr);
            }

            byte[] sig;

            if (parameters.ContainsKey("sig"))
            {
                sig = Convert.FromBase64String((string)parameters["sig"]);
            }
            else
            {
                var newChecksum = RegisteredNamesTransactions.calculateRegNameChecksumFromUpdatedDataRecords(name, nameBytes, records, sequence, nextPkHash);
                sig = CryptoManager.lib.getSignature(newChecksum, IxianHandler.getWalletStorage(curPkHash).getPrimaryPrivateKey());
            }
            ToEntry toEntry = RegisteredNamesTransactions.createUpdateRecordToEntry(nameBytes, records, sequence, nextPkHash, sigPk, sig);

            var txTuple = createRegNameTransaction(toEntry, null, null);
            Transaction fundedTx = txTuple.tx;
            List<Address> relayNodeAddresses = txTuple.relayNodeAddresses;
            if (fundedTx == null)
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INTERNAL_ERROR, message = "An unknown error occurred while funding the transaction" } };
            }

            if (IxianHandler.addTransaction(fundedTx, relayNodeAddresses, true))
            {
                PendingTransactions.addPendingLocalTransaction(fundedTx, relayNodeAddresses);
                return new JsonResponse { result = fundedTx.toDictionary(), error = null };
            }

            return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INTERNAL_ERROR, message = "An unknown error occurred while adding the transaction" } };
        }

        private JsonResponse onDecodeNameData(Dictionary<string, object> parameters)
        {
            JsonError error = null;
            if (!parameters.ContainsKey("data"))
            {
                error = new JsonError { code = (int)RPCErrorCode.RPC_INVALID_PARAMETER, message = "data parameter is missing" };
                return new JsonResponse { result = null, error = error };
            }

            string rawNameDataHex = (string)parameters["data"];

            RegNameTxEntryBase decodedNameData = IxiNameUtils.decodeNameData(Crypto.stringToHash(rawNameDataHex));
            return new JsonResponse { result = decodedNameData, error = null };
        }

        private JsonResponse onDecodeTransaction(Dictionary<string, object> parameters)
        {
            JsonError error = null;
            if (!parameters.ContainsKey("transaction"))
            {
                error = new JsonError { code = (int)RPCErrorCode.RPC_INVALID_PARAMETER, message = "transaction parameter is missing" };
                return new JsonResponse { result = null, error = error };
            }

            string rawTxHex = (string)parameters["transaction"];

            Transaction decodedTransaction = new Transaction(Crypto.stringToHash(rawTxHex));
            return new JsonResponse { result = decodedTransaction, error = null };
        }

        private (Transaction tx, List<Address> relayNodeAddresses) createRegNameTransaction(ToEntry toEntry, Address walletAddress, Address primaryAddress)
        {
            Transaction t = new Transaction((int)Transaction.Type.RegName);
            t.toList = new Dictionary<Address, ToEntry>(new AddressComparer())
            {
                { ConsensusConfig.rnRewardPoolAddress, toEntry }
            };
            return createTransaction(t, walletAddress, primaryAddress, 0);
        }

        private (Transaction tx, List<Address> relayNodeAddresses) createTransaction(Transaction t, Address walletAddress, Address primaryAddress, IxiNumber additionalFees)
        {
            IxiNumber fromAmount = 0;
            IxiNumber fee = ConsensusConfig.forceTransactionPrice;

            WalletStorage ws = IxianHandler.getWalletStorage(walletAddress);

            if (primaryAddress == null)
            {
                primaryAddress = ws.getPrimaryAddress();
            }
            IxiNumber toAmount = additionalFees;
            if (t.toList.Count > 0)
            {
                foreach (var toEntry in t.toList)
                {
                    IxiNumber singleToAmount = toEntry.Value.amount;
                    if (singleToAmount < 0)
                    {
                        return (null, null);
                    }
                    toAmount += singleToAmount;
                }
            }

            // Only create a transaction if there is a valid amount
            if (toAmount < 0)
            {
                return (null, null);
            }

            List<Address> relayNodeAddresses = null;
            IxiNumber relayFee = 0;
            if (PresenceList.myPresenceType == 'C')
            {
                // Add relay node fee
                relayNodeAddresses = NetworkClientManager.getRandomConnectedClientAddresses(2);
                foreach (var relayNodeAddress in relayNodeAddresses)
                {
                    ToEntry relayNodeToEntry = new ToEntry(getExpectedVersion(IxianHandler.getLastBlockVersion()),
                                                  fee,
                                                  null,
                                                  null);
                    t.toList.Add(relayNodeAddress, relayNodeToEntry);
                    relayFee += fee;
                }
            }

            byte[] pubKey = ws.getKeyPair(primaryAddress).publicKeyBytes;

            t.blockHeight = IxianHandler.getHighestKnownNetworkBlockHeight();
            t.pubKey = new Address(ws.getPrimaryPublicKey());

            SortedDictionary<byte[], IxiNumber> fromList = null;
            lock (PendingTransactions.pendingTransactions)
            {
                fromList = ws.generateFromList(primaryAddress, toAmount + relayFee + fee, t.toList.Keys.ToList(), PendingTransactions.pendingTransactions.Select(x => x.transaction).ToList());
                t.fromList = fromList;
                t.amount = t.calculateTotalAmount();
                t.fee = t.calculateMinimumFee(ConsensusConfig.forceTransactionPrice);
                if (relayNodeAddresses != null)
                {
                    relayFee = 0;
                    foreach (var relayNodeAddress in relayNodeAddresses)
                    {
                        t.toList[relayNodeAddress].amount = t.fee;
                        relayFee += t.fee;
                    }
                }
            }

            IxiNumber totalTxFee = fee;
            for (int i = 0; i < 2 && t.fee != totalTxFee; i++)
            {
                totalTxFee = t.fee;
                lock (PendingTransactions.pendingTransactions)
                {
                    fromList = ws.generateFromList(primaryAddress, toAmount + relayFee + totalTxFee, t.toList.Keys.ToList(), PendingTransactions.pendingTransactions.Select(x => x.transaction).ToList());
                }
                if (fromList == null || fromList.Count == 0)
                {
                    return (null, null);
                }
                t.fromList = fromList;
                t.fee = t.calculateMinimumFee(ConsensusConfig.forceTransactionPrice);
                if (relayNodeAddresses != null)
                {
                    relayFee = 0;
                    foreach (var relayNodeAddress in relayNodeAddresses)
                    {
                        t.toList[relayNodeAddress].amount = t.fee;
                        relayFee += t.fee;
                    }
                }
                t.amount = t.calculateTotalAmount();
            }

            // verify that all "from amounts" match all "to_amounts" and that the fee is included in "from_amounts"
            // we need to recalculate "from_amount"
            fromAmount = fromList.Aggregate(new IxiNumber(), (sum, next) => sum + next.Value, sum => sum);
            if (fromAmount != (toAmount + relayFee + t.fee))
            {
                return (null, null);
            }
            if (toAmount + relayFee + t.fee > ws.getMyTotalBalance(primaryAddress))
            {
                return (null, null);
            }

            t.generateChecksums();
            t.signature = t.getSignature(t.checksum, ws.getPrimaryPrivateKey());
            // the transaction appears valid
            return (t, relayNodeAddresses);
        }

        // This is a bit hacky way to return useful error values
        // returns either Transaction or JsonResponse
        private object createTransactionHelper(Dictionary<string, object> parameters, bool sign_transaction = true)
        {
            IxiNumber from_amount = 0;
            IxiNumber fee = ConsensusConfig.forceTransactionPrice;

            bool auto_fee = false;
            if (parameters.ContainsKey("autofee"))
            {
                string r_auto_fee = (string)parameters["autofee"];
                if (r_auto_fee.ToLower() == "true" || r_auto_fee == "1")
                {
                    auto_fee = true;
                }
            }

            Address walletAddress = null;
            if (parameters.ContainsKey("wallet"))
            {
                walletAddress = new Address(Base58Check.Base58CheckEncoding.DecodePlain((string)parameters["wallet"]));
            }

            WalletStorage ws = IxianHandler.getWalletStorage(walletAddress);

            Address primary_address = null;
            if (!parameters.ContainsKey("primaryAddress"))
            {
                primary_address = ws.getPrimaryAddress();
            }
            else
            {
                primary_address = new Address(Base58Check.Base58CheckEncoding.DecodePlain((string)parameters["primaryAddress"]));
            }

            SortedDictionary<byte[], IxiNumber> fromList = new SortedDictionary<byte[], IxiNumber>(new ByteArrayComparer());
            if (parameters.ContainsKey("from"))
            {
                string[] from_split = ((string)parameters["from"]).Split('-');
                if (from_split.Length > 0)
                {
                    foreach (string single_from in from_split)
                    {
                        string[] single_from_split = single_from.Split('_');
                        Address single_from_address = new Address(Base58Check.Base58CheckEncoding.DecodePlain(single_from_split[0]));
                        if (!ws.isMyAddress(single_from_address))
                        {
                            return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_ADDRESS_OR_KEY, message = "Invalid from address was specified" } };
                        }
                        byte[] single_from_nonce = ws.getAddress(single_from_address).nonce;
                        IxiNumber singleFromAmount = new IxiNumber(single_from_split[1]);
                        if (singleFromAmount < 0 || singleFromAmount == 0)
                        {
                            from_amount = 0;
                            break;
                        }
                        from_amount += singleFromAmount;
                        fromList.Add(single_from_nonce, singleFromAmount);
                    }
                }
                // Only create a transaction if there is a valid amount
                if (from_amount < 0 || from_amount == 0)
                {
                    return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMS, message = "Invalid from amount was specified" } };
                }
            }

            if (!parameters.ContainsKey("to"))
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMS, message = "Parameter 'to' is missing." } };
            }

            IxiNumber to_amount = 0;
            Dictionary<Address, ToEntry> toList = new Dictionary<Address, ToEntry>(new AddressComparer());
            string[] to_split = ((string)parameters["to"]).Split('-');
            if (to_split.Length > 0)
            {
                foreach (string single_to in to_split)
                {
                    string[] single_to_split = single_to.Split('_');
                    byte[] single_to_address = Base58Check.Base58CheckEncoding.DecodePlain(single_to_split[0]);
                    if (!Address.validateChecksum(single_to_address))
                    {
                        return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_ADDRESS_OR_KEY, message = "Invalid to address was specified" } };
                    }
                    IxiNumber singleToAmount = new IxiNumber(single_to_split[1]);
                    if (singleToAmount < 0 || singleToAmount == 0)
                    {
                        return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMS, message = "Invalid to amount was specified" } };
                    }
                    to_amount += singleToAmount;
                    ToEntry toEntry = new ToEntry(getExpectedVersion(IxianHandler.getLastBlockVersion()), singleToAmount, null, null);
                    toList.Add(new Address(single_to_address), toEntry);
                }
            }

            if (parameters.ContainsKey("fee") && ((string)parameters["fee"]).Length > 0)
            {
                fee = new IxiNumber((string)parameters["fee"]);
            }

            List<Address> relayNodeAddresses = null;
            IxiNumber relayFee = 0;
            if (PresenceList.myPresenceType == 'C')
            {
                if (parameters.ContainsKey("relayNodeAddress"))
                {
                    relayNodeAddresses = new() { new Address((string)parameters["relayNodeAddress"]) };
                }
                else
                {
                    relayNodeAddresses = NetworkClientManager.getRandomConnectedClientAddresses(2);
                }


                foreach (Address relayNodeAddress in relayNodeAddresses)
                {
                    ToEntry toEntry = new ToEntry(getExpectedVersion(IxianHandler.getLastBlockVersion()),
                                                  fee,
                                                  null,
                                                  null);
                    toList.Add(relayNodeAddress, toEntry);
                    relayFee += fee;
                }
            }

            // Only create a transaction if there is a valid amount
            if (to_amount < 0 || to_amount == 0)
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMS, message = "Invalid to amount was specified" } };
            }

            byte[] pubKey = ws.getKeyPair(primary_address).publicKeyBytes;

            bool adjust_amount = false;
            if (fromList.Count == 0)
            {
                lock (PendingTransactions.pendingTransactions)
                {
                    fromList = ws.generateFromList(primary_address, to_amount + relayFee + fee, toList.Keys.ToList(), PendingTransactions.pendingTransactions.Select(x => x.transaction).ToList());
                }
                adjust_amount = true;
            }

            if (fromList == null || fromList.Count == 0)
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_VERIFY_ERROR, message = "From list is empty" } };
            }

            Transaction transaction = new Transaction((int)Transaction.Type.Normal, fee, toList, fromList, new Address(pubKey), IxianHandler.getHighestKnownNetworkBlockHeight(), -1, sign_transaction);
            //Logging.info("Initial transaction size: {0}.", transaction.getBytes().Length);
            //Logging.info("Initial transaction set fee: {0}.", transaction.fee);
            if (adjust_amount) //true only if automatically generating from address
            {
                IxiNumber total_tx_fee = fee;
                for (int i = 0; i < 3 && transaction.fee != total_tx_fee; i++)
                {
                    if (relayNodeAddresses != null)
                    {
                        relayFee = 0;
                        foreach (Address relayNodeAddress in relayNodeAddresses)
                        {
                            transaction.toList[relayNodeAddress].amount = transaction.fee;
                            relayFee += transaction.fee;
                        }
                    }

                    total_tx_fee = transaction.fee;
                    lock (PendingTransactions.pendingTransactions)
                    {
                        fromList = ws.generateFromList(primary_address, to_amount + relayFee + total_tx_fee, toList.Keys.ToList(), PendingTransactions.pendingTransactions.Select(x => x.transaction).ToList());
                    }
                    if (fromList == null || fromList.Count == 0)
                    {
                        return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_VERIFY_ERROR, message = "From list is empty" } };
                    }
                    transaction = new Transaction((int)Transaction.Type.Normal, fee, toList, fromList, new Address(pubKey), IxianHandler.getHighestKnownNetworkBlockHeight(), -1, sign_transaction);
                }
            }
            else if (auto_fee) // true if user specified both a valid from address and the parameter autofee=true
            {
                // fee is taken from the first specified address
                byte[] first_address = fromList.Keys.First();
                fromList[first_address] = fromList[first_address] + transaction.fee;
                if (fromList[first_address] > IxianHandler.getWalletBalance(new Address(transaction.pubKey.addressNoChecksum, first_address)))
                {
                    return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_WALLET_INSUFFICIENT_FUNDS, message = "Balance is too low" } };
                }
                transaction = new Transaction((int)Transaction.Type.Normal, fee, toList, fromList, new Address(pubKey), IxianHandler.getHighestKnownNetworkBlockHeight(), -1, sign_transaction);
            }
            //Logging.info("Transaction size after automatic adjustments: {0}.", transaction.getBytes().Length);
            //Logging.info("Transaction fee after automatic adjustments: {0}.", transaction.fee);
            // verify that all "from amounts" match all "to_amounts" and that the fee is included in "from_amounts"
            // we need to recalculate "from_amount"
            from_amount = fromList.Aggregate(new IxiNumber(), (sum, next) => sum + next.Value, sum => sum);
            if (from_amount != (to_amount + relayFee + transaction.fee))
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_VERIFY_ERROR, message = "From amounts (incl. fee) do not match to amounts. If you haven't accounted for the transaction fee in the from amounts, use the parameter 'autofee' to have the node do it automatically." } };
            }
            if (to_amount + relayFee + transaction.fee > ws.getMyTotalBalance(primary_address))
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_WALLET_INSUFFICIENT_FUNDS, message = "Balance is too low" } };
            }

            // the transaction appears valid
            return new TransactionWithRelays(transaction, relayNodeAddresses);
        }

        public JsonResponse onPl()
        {
            JsonError error = null;

            List<Presence> presences = PresenceList.getPresences();

            // Show a list of presences
            return new JsonResponse { result = presences, error = error };
        }

        public JsonResponse onRelaySectors()
        {
            JsonError error = null;

            var sectors = RelaySectors.Instance.debugDump();

            return new JsonResponse { result = sectors, error = error };
        }

        public JsonResponse onGetSectorNodes(Dictionary<string, object> parameters)
        {
            JsonError error = null;

            if (!parameters.ContainsKey("maxRelayCount"))
            {
                error = new JsonError { code = (int)RPCErrorCode.RPC_INVALID_PARAMETER, message = "maxRelayCount parameter is missing" };
                return new JsonResponse { result = null, error = error };
            }

            int maxRelayCount = int.Parse((string)parameters["maxRelayCount"]);

            byte[] prefixBytes;

            if (parameters.ContainsKey("prefixHex"))
            {
                prefixBytes = Crypto.stringToHash((string)parameters["prefixHex"]);
            }
            else if (parameters.ContainsKey("address"))
            {
                prefixBytes = CryptoManager.lib.sha3_512Trunc(new Address((string)parameters["address"]).addressNoChecksum);
            } else
            {
                error = new JsonError { code = (int)RPCErrorCode.RPC_INVALID_PARAMETER, message = "prefixHex or address parameter is missing" };
                return new JsonResponse { result = null, error = error };
            }

            var relayList = RelaySectors.Instance.getSectorNodes(prefixBytes, maxRelayCount);

            return new JsonResponse { result = relayList, error = error };
        }
    }

    internal class TransactionWithRelays
    {
        public Transaction transaction { get; private set; }
        public List<Address> relayNodeAddresses { get; private set; }

        public TransactionWithRelays(Transaction transaction, List<Address> relayNodeAddresses)
        {
            this.transaction = transaction;
            this.relayNodeAddresses = relayNodeAddresses;
        }
    }
}

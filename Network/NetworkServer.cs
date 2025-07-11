// Copyright (C) 2017-2025 Ixian
// This file is part of Ixian Core - www.github.com/ixian-platform/Ixian-Core
//
// Ixian Core is free software: you can redistribute it and/or modify
// it under the terms of the MIT License as published
// by the Open Source Initiative.
//
// Ixian Core is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// MIT License for more details.

using IXICore.Inventory;
using IXICore.Meta;
using IXICore.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace IXICore.Network
{
    /// <summary>
    ///  Helper structure which holds a single IP addresses on which the server component is listening. Used only to communicate the configuration
    ///  to the server listening thread.
    /// </summary>
    public struct NetOpsData
    {
        public IPEndPoint listenAddress;
    }

    /// <summary>
    ///  Ixian network server object. This is used to accept connections from Ixian clients or other nodes
    ///  and recieve Ixian protocol messages.
    ///  Basic protocol validation is performed before a specialized protocol parser is called.
    /// </summary>
    public class NetworkServer
    {
        private static bool continueRunning = false;
        private static Thread netControllerThread = null;
        private static TcpListener listener;
        /// <summary>
        ///  List of connected clients.
        /// </summary>
        public static List<RemoteEndpoint> connectedClients = new List<RemoteEndpoint>();

        private static Dictionary<string, DateTime> nodeBlacklist = new Dictionary<string, DateTime>();
        private static ThreadLiveCheck TLC;

        private static DateTime lastIncomingConnectionTime = DateTime.MinValue;
        /// <summary>
        ///  Flag, indicating whether the listening socket is open and accepting connections.
        /// </summary>
        public static bool connectable = true;

        public static bool paused = false;

        /// <summary>
        ///  Starts listening for and accepting network connections.
        /// </summary>
        public static void beginNetworkOperations()
        {
            if (netControllerThread != null)
            {
                // already running
                Logging.info("Network server thread is already running.");
                return;
            }

            if(IxianHandler.publicPort <= 0 || IxianHandler.publicPort > 65535)
            {
                Logging.error("Cannot start network server, public port is invalid");
                return;
            }

            if (CoreConfig.preventNetworkOperations)
            {
                Logging.warn("Not starting NetworkClientManager thread due to preventNetworkOperations flag being set.");
                return;
            }

            TLC = new ThreadLiveCheck();
            netControllerThread = new Thread(networkOpsLoop);
            netControllerThread.Name = "Network_Server_Controller_Thread";
            connectedClients = new List<RemoteEndpoint>();
            continueRunning = true;

            // Read the server port from the configuration
            NetOpsData nod = new NetOpsData();
            nod.listenAddress = new IPEndPoint(IPAddress.Any, IxianHandler.publicPort);
            netControllerThread.Start(nod);

            Logging.info("Public network node address: {0} port {1}", IxianHandler.publicIP, IxianHandler.publicPort);

            paused = false;
        }

        /// <summary>
        ///  Stops listening for new connections and disconnects all connected clients.
        /// </summary>
        public static void stopNetworkOperations()
        {
            if (netControllerThread == null)
            {
                // not running
                Logging.info("Network server thread was already halted.");
                return;
            }
            continueRunning = false;

            // Close blocking socket
            listener.Stop();

            netControllerThread.Interrupt();
            netControllerThread.Join();
            netControllerThread = null;

            Logging.info("Closing network server connected clients");
            // Clear all clients
            lock (connectedClients)
            {
                // Immediately close all connected client sockets
                foreach (RemoteEndpoint client in connectedClients)
                {
                    client.stop();
                }

                connectedClients.Clear();
            }
        }

        public static void pause()
        {
            restartNetworkOperations();
            paused = true;
        }

        public static void resume()
        {
            paused = false;
        }

        /// <summary>
        ///  Checks the list of clients and removes the ones who have disconnected since the last check.
        /// </summary>
        public static void handleDisconnectedClients()
        {
            List<RemoteEndpoint> netClients = null;
            lock (connectedClients)
            {
                netClients = new List<RemoteEndpoint>(connectedClients);
            }

            // Prepare a list of failed clients
            List<RemoteEndpoint> failed_clients = new List<RemoteEndpoint>();

            foreach (RemoteEndpoint client in netClients)
            {
                if (client.isConnected())
                {
                    continue;
                }
                failed_clients.Add(client);
            }

            // Go through the list of failed clients and remove them
            foreach (RemoteEndpoint client in failed_clients)
            {
                client.stop();
                lock (connectedClients)
                {
                    // Remove this endpoint from the network server
                    connectedClients.Remove(client);
                }
            }
        }

        /// <summary>
        ///  Restarts the network server.
        /// </summary>
        public static void restartNetworkOperations()
        {
            Logging.info("Stopping network server...");
            stopNetworkOperations();
            Thread.Sleep(1000);
            Logging.info("Restarting network server...");
            beginNetworkOperations();
        }

        private static void networkOpsLoop(object data)
        {
            try
            {
                if (data is NetOpsData)
                {
                    try
                    {
                        NetOpsData netOpsData = (NetOpsData)data;
                        listener = new TcpListener(netOpsData.listenAddress);
                        listener.Start();
                    }
                    catch (Exception e)
                    {
                        Logging.error("Exception starting server: {0}", e.ToString());
                        return;
                    }
                }
                else
                {
                    Logging.error("NetworkServer.networkOpsLoop called with incorrect data object. Expected 'NetOpsData', got '{0}'", data.GetType().ToString());
                    return;
                }
                // housekeeping tasks
                while (continueRunning)
                {
                    TLC.Report();
                    try
                    {
                        handleDisconnectedClients();
                    }
                    catch (Exception e)
                    {
                        Logging.error("Fatal exception occurred in NetworkServer.networkOpsLoop: " + e);
                    }
                    // Use a blocking mechanism
                    try
                    {
                        Socket handlerSocket = listener.AcceptSocket();
                        acceptConnection(handlerSocket);
                    }
                    catch (SocketException)
                    {
                        // Could be an interupt request
                    }
                    catch (ThreadInterruptedException)
                    {
                        throw;
                    }
                    catch (Exception)
                    {
                        if (continueRunning)
                        {
                            Logging.error("Exception occurred in NetworkServer while trying to accept socket connection.");
                            restartNetworkOperations();
                        }
                        return;
                    }

                    // Sleep to prevent cpu usage
                    Thread.Sleep(100);

                }
                Logging.info("Server listener thread ended.");
            }
            catch (ThreadInterruptedException)
            {

            }
            catch (Exception e)
            {
                Logging.error("NetworkOpsLoop exception: {0}", e);
            }
        }

        /// <summary>
        ///  Sends the given data to all appropriate connected clients.
        /// </summary>
        /// <param name="types">Types of clients to which the data should be sent.</param>
        /// <param name="code">Type of the protocol message being sent.</param>
        /// <param name="data">Byte-field of the data, appropriate for the specific `code` used.</param>
        /// <param name="helper_data">Optional, additional data to transmit after `data`.</param>
        /// <param name="skipEndpoint">If given, the message will not be sent to this remote endpoint. This prevents echoing the message to the originating node.</param>
        /// <returns>True, if at least one message was sent to at least one client.</returns>
        public static bool broadcastData(char[] types, ProtocolMessageCode code, byte[] data, byte[] helper_data, RemoteEndpoint skipEndpoint = null)
        {
            bool result = false;
            QueueMessage queue_message = RemoteEndpoint.getQueueMessage(code, data, helper_data);
            lock (connectedClients)
            {
                foreach (RemoteEndpoint endpoint in connectedClients)
                {
                    if (skipEndpoint != null)
                    {
                        if (endpoint == skipEndpoint)
                            continue;
                    }

                    if (!endpoint.isConnected())
                    {
                        continue;
                    }

                    if (endpoint.helloReceived == false)
                    {
                        continue;
                    }

                    if (types != null)
                    {
                        if (endpoint.presenceAddress == null || !types.Contains(endpoint.presenceAddress.type))
                        {
                            continue;
                        }
                    }

                    endpoint.sendData(queue_message);
                    result = true;
                }
            }
            return result;
        }

        /// <summary>
        ///  Sends the specified event to all connected clients.
        ///  The information is only sent to those clients who have previously subscribed to this event type
        /// </summary>
        /// <param name="type">Types of the event that has occurred.</param>
        /// <param name="code">Type of the protocol message being sent.</param>
        /// <param name="data">Byte-field of the data, appropriate for the specific `code` used.</param>
        /// <param name="address">Ixian Wallet Address which triggered the event</param>
        /// <param name="helper_data">Optional, additional data to transmit after `data`.</param>
        /// <param name="skipEndpoint">If given, the message will not be sent to this remote endpoint. This prevents echoing the message to the originating node.</param>
        /// <returns>True, if at least one message was sent to at least one client.</returns>
        public static bool broadcastEventData(NetworkEvents.Type type, ProtocolMessageCode code, byte[] data, byte[] address, byte[] helper_data, RemoteEndpoint skipEndpoint = null)
        {
            bool result = false;
            try
            {
                QueueMessage queue_message = RemoteEndpoint.getQueueMessage(code, data, helper_data);
                lock (connectedClients)
                {
                    foreach (RemoteEndpoint endpoint in connectedClients)
                    {
                        if (skipEndpoint != null)
                        {
                            if (endpoint == skipEndpoint)
                                continue;
                        }

                        if (!endpoint.isConnected())
                        {
                            continue;
                        }

                        if (endpoint.helloReceived == false)
                        {
                            continue;
                        }

                        if (endpoint.presenceAddress == null || (endpoint.presenceAddress.type != 'C' && endpoint.presenceAddress.type != 'R'))
                        {
                            continue;
                        }

                        // Finally, check if the endpoint is subscribed to this event and address
                        if (endpoint.isSubscribedToAddress(type, address))
                        {
                            endpoint.sendData(queue_message);
                            result = true;
                        }
                    }
                }
            }catch(Exception e)
            {
                Logging.error("Exception occurred in NetworkServer.broadcastEventData: " + e);
            }

            return result;
        }


        /// <summary>
        ///  Sends the specified network message to the given address, if it is known and connected among clients.
        /// </summary>
        /// <param name="address">Ixian Wallet Address - the recipient of the message</param>
        /// <param name="code">Type of the network message to send</param>
        /// <param name="message">Byte-field with the required data, as specified by `code`.</param>
        /// <returns>True, if the message was delivered.</returns>
        public static bool forwardMessage(Address address, ProtocolMessageCode code, byte[] message)
        {
            if (address == null)
            {
                Logging.warn("Cannot forward message to null address.");
                return false;
            }

            Logging.info(">>>> Preparing to forward to {0}", address.ToString());

            QueueMessage queue_message = RemoteEndpoint.getQueueMessage(code, message, null);
            lock (connectedClients)
            {
                foreach (RemoteEndpoint endpoint in connectedClients)
                {
                    // Skip connections without presence information
                    if (endpoint.presence == null)
                        continue;

                    // SKip disconnected endpoints
                    if(!endpoint.isConnected())
                        continue;

                    Address client_wallet = endpoint.presence.wallet;

                    if (client_wallet != null && address.SequenceEqual(client_wallet))
                    {
                        Logging.info(">>>> Forwarding message");
                        endpoint.sendData(queue_message);
                        return true;
                    }

                }
            }


            return false;
        }

        /// <summary>
        ///  Sends the specified network message to all connected clients
        /// </summary>
        /// <param name="address">Ixian Wallet Address - the recipient of the message</param>
        /// <param name="code">Type of the network message to send</param>
        /// <param name="message">Byte-field with the required data, as specified by `code`.</param>
        /// <returns>True, if the message was delivered.</returns>
        public static bool forwardMessage(ProtocolMessageCode code, byte[] message, byte[] exclude_address = null)
        {
            Logging.info(">>>> Preparing to forward to everyone");

            QueueMessage queue_message = RemoteEndpoint.getQueueMessage(code, message, null);
            lock (connectedClients)
            {
                foreach (RemoteEndpoint endpoint in connectedClients)
                {
                    // Skip connections without presence information
                    if (endpoint.presence == null)
                        continue;

                    byte[] client_wallet = endpoint.presence.wallet.addressNoChecksum;

                    if (client_wallet != null)
                    {
                        if(exclude_address != null && client_wallet.SequenceEqual(exclude_address))
                        {
                            continue;
                        }
                        Logging.info(">>>> Forwarding message");
                        endpoint.sendData(queue_message);

                    }

                }
            }

            return false;
        }

        /// <summary>
        ///  Sends the protocol message to the specified neighbor node, given as a Hostname or IP address and port.
        /// </summary>
        /// <param name="neighbor">IP address or hostname and port for the neighbor.</param>
        /// <param name="code">Type of the protocol message</param>
        /// <param name="data">Data required by the protocol message `code`.</param>
        /// <param name="helper_data">Optional, additional data to transmit after `data`.</param>
        /// <returns>True if the data was sent to the specified neighbor.</returns>
        public static bool sendToClient(string neighbor, ProtocolMessageCode code, byte[] data, byte[] helper_data)
        {
            RemoteEndpoint client = null;
            lock (connectedClients)
            {
                foreach (RemoteEndpoint ep in connectedClients)
                {
                    if (ep.getFullAddress() == neighbor)
                    {
                        client = ep;
                        break;
                    }
                }
            }
            if (client != null)
            {
                client.sendData(code, data, helper_data);
                return true;
            }
            return false;
        }

        /// <summary>
        ///  Retrieves all connected remote endpoints as hostnames or IP addresses and optionally ports.
        /// </summary>
        /// <param name="useIncomingPort">Whether the TCP port information should be included.</param>
        /// <returns>List of connected clients with optional port information.</returns>
        public static string[] getConnectedClients(bool useIncomingPort = false)
        {
            List<String> result = new List<String>();

            lock (connectedClients)
            {
                foreach (RemoteEndpoint client in connectedClients)
                {
                    if (client.isConnected())
                    {
                        try
                        {
                            string client_name = client.getFullAddress(useIncomingPort);
                            result.Add(client_name);
                        }
                        catch (Exception e)
                        {
                            Logging.warn("Exception in NetworkServer->getConnectedClients: {0}", e.ToString());
                        }
                    }
                }
            }

            return result.ToArray();
        }

        private static void acceptConnection(Socket clientSocket)
        {
            IPEndPoint clientEndpoint = (IPEndPoint)clientSocket.RemoteEndPoint;
            // Add timeouts and set socket options
            //clientSocket.ReceiveTimeout = 5000;
            //clientSocket.SendTimeout = 5000;
            clientSocket.LingerState = new LingerOption(true, 3);
            clientSocket.NoDelay = true;
            clientSocket.Blocking = true;

            if (!IxianHandler.isAcceptingConnections() || paused)
            {
                CoreProtocolMessage.sendBye(clientSocket, ProtocolByeCode.notReady, string.Format("The node isn't ready yet, please try again later."), "");
                clientSocket.Shutdown(SocketShutdown.Both);
                clientSocket.Disconnect(false);
                clientSocket.Close();
                return;
            }

            lastIncomingConnectionTime = DateTime.UtcNow;
            connectable = true;

            // Setup the remote endpoint
            RemoteEndpoint remoteEndpoint = new RemoteEndpoint();

            lock (connectedClients)
            {
                if (CoreConfig.maximumServerMasterNodes + CoreConfig.maximumServerClients > 0
                    && connectedClients.Count + 1 > CoreConfig.maximumServerMasterNodes + CoreConfig.maximumServerClients)
                {
                    Logging.warn("Maximum number of connected master nodes reached. Disconnecting client: {0}:{1}",
                        clientEndpoint.Address.ToString(), clientEndpoint.Port);
                    CoreProtocolMessage.sendBye(clientSocket, ProtocolByeCode.rejected, "Too many clients already connected.", "");
                    clientSocket.Shutdown(SocketShutdown.Both);
                    clientSocket.Disconnect(false);
                    clientSocket.Close();
                    return;
                }

                var existing_clients = connectedClients.Where(re => re.remoteIP.Address == clientEndpoint.Address);
                if (existing_clients.Count() > 0)
                {
                    Logging.warn("Client {0}:{1} already connected as {2}.",
                        clientEndpoint.Address.ToString(), clientEndpoint.Port, existing_clients.First().ToString());
                    CoreProtocolMessage.sendBye(clientSocket, ProtocolByeCode.rejected, "You are already connected.", "");
                    clientSocket.Shutdown(SocketShutdown.Both);
                    clientSocket.Disconnect(false);
                    clientSocket.Close();
                    return;
                }

                connectedClients.Add(remoteEndpoint);

                Logging.info("Client connection accepted: {0} | #{1}/{2}", clientEndpoint.ToString(), connectedClients.Count + 1, CoreConfig.maximumServerMasterNodes + CoreConfig.maximumServerClients);

                remoteEndpoint.start(clientSocket);
            }
        }

        /// <summary>
        ///  Removes the given endpoint from the connected client list, but does not immediately issue a disconnect message.
        /// </summary>
        /// <param name="endpoint">Endpoint to remove</param>
        /// <returns>True if the endpoint was removed or false if the endpoint was not known.</returns>
        public static bool removeEndpoint(RemoteEndpoint endpoint)
        {
            bool result = false;
            lock (connectedClients)
            {
                result = connectedClients.Remove(endpoint);
            }
            return result;
        }

        /// <summary>
        ///  Retrieves the number of queued outgoing messages for all clients.
        /// </summary>
        /// <returns>Number of messages in all outgoing queues</returns>
        public static int getQueuedMessageCount()
        {
            int messageCount = 0;
            lock (connectedClients)
            {
                foreach (RemoteEndpoint client in connectedClients)
                {
                    messageCount += client.getQueuedMessageCount();
                }
            }
            return messageCount;
        }

        /// <summary>
        ///  Gets the client by sequential index.
        /// </summary>
        /// <param name="idx">Sequential index of the client.</param>
        /// <returns>Client at the given index, or null if out of bounds.</returns>
        public static RemoteEndpoint getClient(int idx)
        {
            lock (connectedClients)
            {
                int i = 0;
                RemoteEndpoint lastClient = null;
                foreach (RemoteEndpoint client in connectedClients)
                {
                    if (client.isConnected())
                    {
                        lastClient = client;
                    }
                    if (i == idx && lastClient != null)
                    {
                        break;
                    }
                    i++;
                }
                return lastClient;
            }
        }

        public static RemoteEndpoint getClient(Address clientAddress, bool fullyConnected = true)
        {
            lock (connectedClients)
            {
                foreach (RemoteEndpoint c in connectedClients)
                {
                    if (fullyConnected)
                    {
                        if (!c.isConnected() || !c.helloReceived)
                        {
                            continue;
                        }
                        if (c.presenceAddress == null)
                        {
                            continue;
                        }
                    }

                    if (c.serverWalletAddress != null
                        && c.serverWalletAddress.SequenceEqual(clientAddress))
                    {
                        return c;
                    }
                }
            }

            return null;
        }


        /// <summary>
        ///  Adds the speficied node to the blacklist by public IP.
        /// </summary>
        /// <param name="ip">Node to blacklist.</param>
        public static void blacklistNode(string ip)
        {
            lock (nodeBlacklist)
            {
                nodeBlacklist.AddOrReplace(ip, DateTime.UtcNow);
            }
        }

        /// <summary>
        ///  Checks if the specified IP is blacklisted.
        /// </summary>
        /// <param name="ip">IP address to check</param>
        /// <returns>True, if the node is blacklisted.</returns>
        public static bool isNodeBlacklisted(string ip)
        {
            lock (nodeBlacklist)
            {
                if (nodeBlacklist.ContainsKey(ip))
                {
                    DateTime dt = nodeBlacklist[ip];
                    if ((DateTime.UtcNow - dt).TotalSeconds > 600)
                    {
                        nodeBlacklist.Remove(ip);
                    }
                    return true;
                }
            }
            return false;
        }

        /// <summary>
        ///  Checks if the server is running.
        /// </summary>
        /// <returns>True, if the network server is running and accepting connections.</returns>
        public static bool isRunning()
        {
            return continueRunning;
        }

        /// <summary>
        ///  Returns if the server is proven to be connectable.
        ///  (Someone has connected to the server successfully within the past 5 minutes.)
        /// </summary>
        /// <returns>True, if the server is connectable from the Internet.</returns>
        static public bool isConnectable()
        {
            if (getConnectedClients().Count() > 0)
            {
                return true;
            }

            if ((DateTime.UtcNow - lastIncomingConnectionTime).TotalSeconds < 300) // if somebody connected within 5 minutes the node is probably connectable
            {
                return true;
            }

            return connectable;
        }

        public static bool addToInventory(char[] types, InventoryItem item, RemoteEndpoint skip_endpoint)
        {
            lock (connectedClients)
            {
                foreach (var client in connectedClients)
                {
                    try
                    {
                        if(!client.isConnected() || !client.helloReceived)
                        {
                            continue;
                        }
                        if (client == skip_endpoint)
                        {
                            continue;
                        }
                        if (client.presenceAddress == null)
                        {
                            continue;
                        }
                        if (!types.Contains(client.presenceAddress.type))
                        {
                            continue;
                        }
                        client.addInventoryItem(item);
                    }catch (Exception e)
                    {
                        Logging.error("Exception occurred in NetworkServer.addToInventory: " + e);
                    }
                }
            }
            return true;
        }

        public static bool addToInventorySubscribed(InventoryItemKeepAlive item, RemoteEndpoint skip_endpoint)
        {
            lock (connectedClients)
            {
                foreach (var client in connectedClients)
                {
                    try
                    {
                        if (!client.isConnected() || !client.helloReceived)
                        {
                            continue;
                        }
                        if (client == skip_endpoint)
                        {
                            continue;
                        }
                        if (client.presenceAddress == null)
                        {
                            continue;
                        }
                        if (client.presenceAddress.type != 'C')
                        {
                            continue;
                        }
                        if (!client.isSubscribedToAddress(NetworkEvents.Type.keepAlive, item.address.addressNoChecksum))
                        {
                            continue;
                        }
                        client.addInventoryItem(item);
                    }
                    catch (Exception e)
                    {
                        Logging.error("Exception occurred in NetworkServer.addToInventory: " + e);
                    }
                }
            }
            return true;
        }

        public static List<ulong> getBlockHeights()
        {
            List<ulong> blockHeights = new List<ulong>();
            lock (connectedClients)
            {
                foreach (var client in connectedClients)
                {
                    if(client.blockHeight != 0)
                    {
                        blockHeights.Add(client.blockHeight);
                    }
                }
            }
            return blockHeights;
        }
    }
}

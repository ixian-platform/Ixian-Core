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

using Force.Crc32;
using IXICore.Inventory;
using IXICore.Meta;
using IXICore.Network;
using IXICore.Network.Messages;
using IXICore.RegNames;
using IXICore.Streaming;
using IXICore.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;

namespace IXICore
{
    /// <summary>
    ///  Common functions for manipulating Ixian protocol message.
    /// </summary>
    public class CoreProtocolMessage
    {
        /// <summary>
        /// Prepares and sends the disconnect message to the specified remote endpoint.
        /// </summary>
        /// <param name="endpoint">Remote client.</param>
        /// <param name="code">Disconnection reason.</param>
        /// <param name="message">Optional text message for the user of the remote client.</param>
        /// <param name="data">Optional payload to further explain the disconnection reason.</param>
        /// <param name="removeAddressEntry">If true, the remote address will be removed from the `PresenceList`.</param>
        public static void sendBye(RemoteEndpoint endpoint, ProtocolByeCode code, string message, string data, bool removeAddressEntry = true)
        {
            using (MemoryStream m2 = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(m2))
                {
                    writer.Write((int)code);
                    writer.Write(message);
                    writer.Write(data);
#if TRACE_MEMSTREAM_SIZES
                    Logging.info(String.Format("CoreProtocolMessage::sendBye: {0}", m2.Length));
#endif
                    if (code == ProtocolByeCode.bye)
                    {
                        endpoint.reconnectOnFailure = false;
                    }
                    endpoint.sendData(ProtocolMessageCode.bye, m2.ToArray());
                    Logging.info("Sending bye to {0} with message '{1}' and data '{2}'", endpoint.getFullAddress(), message, data);
                }
            }
            if (removeAddressEntry)
            {
                if (endpoint.presence != null && endpoint.presence.wallet != null && endpoint.presenceAddress != null)
                {
                    PresenceList.removeAddressEntry(endpoint.presence.wallet, endpoint.presenceAddress);
                }
                //PeerStorage.removePeer(endpoint.getFullAddress(true));
            }
        }

        /// <summary>
        /// Prepares and sends the disconnect message to the specified remote endpoint.
        /// </summary>
        /// <param name="endpoint">Remote client.</param>
        /// <param name="code">Disconnection reason.</param>
        /// <param name="message">Optional text message for the user of the remote client.</param>
        /// <param name="data">Optional payload to further explain the disconnection reason.</param>
        /// <param name="removeAddressEntry">If true, the remote address will be removed from the `PresenceList`.</param>
        public static void sendBye(Socket socket, ProtocolByeCode code, string message, string data)
        {
            using (MemoryStream m2 = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(m2))
                {
                    writer.Write((int)code);
                    writer.Write(message);
                    writer.Write(data);
#if TRACE_MEMSTREAM_SIZES
                    Logging.info(String.Format("CoreProtocolMessage::sendBye: {0}", m2.Length));
#endif

                    socket.Send(RemoteEndpoint.prepareProtocolMessage(ProtocolMessageCode.bye, m2.ToArray(), CoreConfig.protocolVersion, 0));

                    IPEndPoint remoteIP = (IPEndPoint)socket.RemoteEndPoint;
                    string address = remoteIP.Address.ToString() + ":" + remoteIP.Port;
                    Logging.info("Sending bye to {0} with message '{1}' and data '{2}'", address, message, data);
                }
            }
        }

        /// <summary>
        ///  Reads a protocol message from the specified byte-field and calls appropriate methods to process this message.
        /// </summary>
        /// <remarks>
        ///  This function checks all applicable checksums and validates that the message is complete before calling one of the specialized
        ///  methods to handle actual decoding and processing.
        /// </remarks>
        /// <param name="recv_buffer">Byte-field with an Ixian protocol message.</param>
        /// <param name="endpoint">Remote endpoint from where the message was received.</param>
        public static void readProtocolMessage(QueueMessageRaw raw_message, MessagePriority priority, RemoteEndpoint endpoint)
        {
            if (endpoint == null)
            {
                Logging.error("Endpoint was null. readProtocolMessage");
                return;
            }

            ProtocolMessageCode code = raw_message.code;

            // Filter messages
            if (endpoint.presence == null)
            {
                // Check for presence and only accept hello and bye messages if there is no presence.
                if (code != ProtocolMessageCode.hello 
                    && code != ProtocolMessageCode.helloData
                    && code != ProtocolMessageCode.bye)
                {
                    return;
                }
            }
            if(raw_message.legacyChecksum != null)
            {
                // Compute checksum of received data
                byte[] local_checksum = Crypto.sha512sqTrunc(raw_message.data, 0, 0, 32);

                // Verify the checksum before proceeding
                if (local_checksum.SequenceEqual(raw_message.legacyChecksum) == false)
                {
                    Logging.error("Dropped message (invalid legacy checksum)");
                    return;
                }
            }else
            {
                // Compute checksum of received data
                uint local_checksum = Crc32CAlgorithm.Compute(raw_message.data);

                // Verify the checksum before proceeding
                if (local_checksum != raw_message.checksum)
                {
                    Logging.error("Dropped message (invalid checksum)");
                    return;
                }
            }


            // Can proceed to parse the data parameter based on the protocol message code.
            // Data can contain multiple elements.
            //parseProtocolMessage(code, data, socket, endpoint);
            NetworkQueue.receiveProtocolMessage(code, raw_message.data, Crc32CAlgorithm.Compute(raw_message.data), priority, endpoint);
        }

        /// <summary>
        ///  Processes a Hello Ixian protocol message and updates the `PresenceList` as appropriate.
        /// </summary>
        /// <remarks>
        ///  This function should normally be called from `NetworkProtocol.parseProtocolMessage()`
        /// </remarks>
        /// <param name="endpoint">Remote endpoint from which the message was received.</param>
        /// <param name="reader">Reader object placed at the beginning of the hello message data.</param>
        /// <returns>True if the message was formatted properly and accepted.</returns>
        public static bool processHelloMessageV6(RemoteEndpoint endpoint, BinaryReader reader, bool set_hello_received = true)
        {
            // Node already has a presence
            if (endpoint.presence != null)
            {
                // Ignore the hello message in this case
                return false;
            }

            // Another layer to catch any incompatible node exceptions for the hello message
            try
            {
                int protocol_version = (int)reader.ReadIxiVarUInt();
                endpoint.version = protocol_version;

                Logging.info("Received Hello: Node version {0}", protocol_version);
                // Check for incompatible nodes
                if (protocol_version < 6)
                {
                    Logging.warn("Hello: Connected node version ({0}) is too old! Upgrade the node.", protocol_version);
                    sendBye(endpoint, ProtocolByeCode.deprecated, string.Format("Your node version is too old. Should be at least {0} is {1}", CoreConfig.protocolVersion, protocol_version), CoreConfig.protocolVersion.ToString(), true);
                    return false;
                }

                int addrLen = (int)reader.ReadIxiVarUInt();
                if (addrLen > 70)
                {
                    Logging.error("Hello: Invalid address from {0}.", endpoint.getFullAddress(true));
                    sendBye(endpoint, ProtocolByeCode.rejected, "Invalid address", "", true);
                    return false;
                }
                Address addr = new Address(reader.ReadBytes(addrLen));

                bool test_net = reader.ReadBoolean();
                char node_type = reader.ReadChar();
                string node_version = reader.ReadString();
                if (node_version.Length > 20)
                {
                    Logging.error("Hello: Invalid node version from {0} - {1}.", endpoint.getFullAddress(true), node_version);
                    sendBye(endpoint, ProtocolByeCode.rejected, "Invalid Node Version", "", true);
                    return false;
                }

                int device_id_len = (int)reader.ReadIxiVarUInt();
                byte[] device_id = reader.ReadBytes(device_id_len);
                if (device_id_len > 32)
                {
                    Logging.error("Hello: Invalid device id from {0} - {1}.", endpoint.getFullAddress(true), Crypto.hashToString(device_id));
                    sendBye(endpoint, ProtocolByeCode.rejected, "Invalid Device ID", "", true);
                    return false;
                }

                int pkLen = (int)reader.ReadIxiVarUInt();
                byte[] pubkey = null;
                if (pkLen > 0)
                {
                    pubkey = reader.ReadBytes(pkLen);
                }

                endpoint.serverPubKey = pubkey;

                int port = (int)reader.ReadIxiVarInt();

                long timestamp = reader.ReadIxiVarInt();

                int sigLen = (int)reader.ReadIxiVarUInt();
                byte[] signature = reader.ReadBytes(sigLen);

                int challenge = 0;
                bool in_hello = false;
                if (endpoint.GetType() != typeof(NetworkClient))
                {
                    challenge = (int)reader.ReadIxiVarUInt();
                    in_hello = true;
                }

                // Check the testnet designator and disconnect on mismatch
                if (test_net != IxianHandler.isTestNet)
                {
                    Logging.warn("Hello: Rejected node {0} due to incorrect testnet designator: {1}", endpoint.fullAddress, test_net);
                    sendBye(endpoint, ProtocolByeCode.incorrectNetworkType, string.Format("Incorrect testnet designator: {0}. Should be {1}", test_net, IxianHandler.isTestNet), test_net.ToString(), true);
                    return false;
                }

                // Check the address and pubkey and disconnect on mismatch
                if (!addr.addressNoChecksum.SequenceEqual(new Address(pubkey).addressNoChecksum))
                {
                    Logging.warn("Hello: Pubkey and address do not match.");
                    sendBye(endpoint, ProtocolByeCode.authFailed, "Pubkey and address do not match.", "", true);
                    return false;
                }

                endpoint.incomingPort = port;

                if (PeerStorage.isBlacklisted(addr) || PeerStorage.isBlacklisted(endpoint.getFullAddress(true)))
                {
                    Logging.warn("Hello: Connected node is blacklisted ({0} - {1}).", endpoint.getFullAddress(true), addr.ToString());
                    sendBye(endpoint, ProtocolByeCode.rejected, "Blacklisted", "", true);
                    return false;
                }

                // Verify the signature
                if (node_type == 'C')
                {
                    // TODO: verify if the client is connectable, then if connectable, check if signature verifies

                    /*if (CryptoManager.lib.verifySignature(Encoding.UTF8.GetBytes(ConsensusConfig.ixianChecksumLockString + "-" + device_id + "-" + timestamp + "-" + endpoint.getFullAddress(true)), pubkey, signature) == false)
                    {
                        CoreProtocolMessage.sendBye(endpoint, ProtocolByeCode.incorrectIp, "Verify signature failed in hello message, likely an incorrect IP was specified. Detected IP:", endpoint.address);
                        Logging.warn(string.Format("Connected node used an incorrect signature in hello message, likely an incorrect IP was specified. Detected IP: {0}", endpoint.address));
                        return false;
                    }*/
                    // TODO store the full address if connectable
                    // Store the presence address for this remote endpoint
                    endpoint.presenceAddress = new PresenceAddress(device_id, "", node_type, node_version, Clock.getNetworkTimestamp() - CoreConfig.clientKeepAliveInterval, null);
                }
                else
                {
                    using (MemoryStream mSig = new MemoryStream(1024))
                    {
                        using (BinaryWriter sigWriter = new BinaryWriter(mSig))
                        {
                            sigWriter.Write(ConsensusConfig.ixianChecksumLock);
                            sigWriter.Write(device_id);
                            sigWriter.Write(timestamp);
                            sigWriter.Write(endpoint.getFullAddress(true));
                            if(in_hello)
                            {
                                sigWriter.Write(challenge);
                            }else
                            {
                                sigWriter.Write(endpoint.challenge);
                            }
                        }
                        if (!CryptoManager.lib.verifySignature(mSig.ToArray(), pubkey, signature))
                        {
                            sendBye(endpoint, ProtocolByeCode.incorrectIp, "Verify signature failed in hello message, likely an incorrect IP was specified. Detected IP:", endpoint.address);
                            Logging.warn("Hello: Connected node used an incorrect signature in hello message, likely an incorrect IP was specified. Detected IP: {0}", endpoint.address);
                            return false;
                        }
                    }

                    // Store the presence address for this remote endpoint
                    endpoint.presenceAddress = new PresenceAddress(device_id, endpoint.getFullAddress(true), node_type, node_version, Clock.getNetworkTimestamp() - CoreConfig.serverKeepAliveInterval, null);
                }

                // if we're a client update the network time difference
                if (endpoint.GetType() == typeof(NetworkClient))
                {
                    long timeDiff = endpoint.calculateTimeDifference();

                    // amortize +- 2 seconds
                    if (timeDiff >= -2 && timeDiff <= 2)
                    {
                        timeDiff = 0;
                    }

                    ((NetworkClient)endpoint).timeDifference = timeDiff;


                    // Check the address and local address and disconnect on mismatch
                    if (endpoint.serverWalletAddress != null && !addr.addressNoChecksum.SequenceEqual(endpoint.serverWalletAddress.addressNoChecksum))
                    {
                        Logging.warn("Hello: Local address mismatch, possible Man-in-the-middle attack.");
                        sendBye(endpoint, ProtocolByeCode.addressMismatch, "Local address mismatch.", "", true);
                        return false;
                    }

                    PeerStorage.updateLastConnected(endpoint.getFullAddress(true));
                }

                endpoint.serverWalletAddress = addr;

                if (endpoint.GetType() != typeof(NetworkClient))
                {
                    // we're the server

                    int masterNodeCount = 0;
                    if (node_type == 'M' || node_type == 'H')
                    {
                        lock (NetworkServer.connectedClients)
                        {
                            masterNodeCount = NetworkServer.connectedClients.Where(x => x.presenceAddress != null && (x.presenceAddress.type == 'M' || x.presenceAddress.type == 'H')).Count();
                            if (masterNodeCount > CoreConfig.maximumServerMasterNodes)
                            {
                                sendBye(endpoint, ProtocolByeCode.rejected, "Too many master nodes already connected.", "", false);
                                return false;
                            }
                        }
                    }
                    else if (node_type == 'C')
                    {
                        lock (NetworkServer.connectedClients)
                        {
                            if (NetworkServer.connectedClients.Count() - masterNodeCount > CoreConfig.maximumServerClients)
                            {
                                sendBye(endpoint, ProtocolByeCode.rejected, "Too many clients already connected.", "", false);
                                return false;
                            }
                        }
                    }

                    if (node_type == 'M' || node_type == 'H' || node_type == 'R')
                    {
                        if (node_type != 'R')
                        {
                            if (ConsensusConfig.minimumMasterNodeFunds > 0)
                            {
                                // Check the wallet balance for the minimum amount of coins
                                IxiNumber balance = IxianHandler.getWalletBalance(addr);
                                if (balance < ConsensusConfig.minimumMasterNodeFunds)
                                {
                                    Logging.warn("Hello: Rejected master node {0} due to insufficient funds: {1}", endpoint.getFullAddress(), balance.ToString());
                                    sendBye(endpoint, ProtocolByeCode.insufficientFunds, string.Format("Insufficient funds. Minimum is {0}", ConsensusConfig.minimumMasterNodeFunds), balance.ToString(), true);
                                    return false;
                                }
                            }
                        }
                        // Limit to one IP per masternode
                        // TODO TODO TODO - think about this and do it properly
                        /*string[] hostname_split = hostname.Split(':');
                        if (PresenceList.containsIP(hostname_split[0], 'M'))
                        {
                            using (MemoryStream m2 = new MemoryStream())
                            {
                                using (BinaryWriter writer = new BinaryWriter(m2))
                                {
                                    writer.Write(string.Format("This IP address ( {0} ) already has a masternode connected.", hostname_split[0]));
                                    Logging.info(string.Format("Rejected master node {0} due to duplicate IP address", hostname));
                                    socket.Send(prepareProtocolMessage(ProtocolMessageCode.bye, m2.ToArray()), SocketFlags.None);
                                    socket.Disconnect(true);
                                    return;
                                }
                            }
                        }*/
                        if (!checkNodeConnectivity(endpoint))
                        {
                            return false;
                        }
                    }

                    sendHelloMessageV6(endpoint, true, challenge);
                    if (set_hello_received)
                    {
                        endpoint.helloReceived = true;
                    }
                }


                // Create a temporary presence with the client's address and device id
                endpoint.presence = new Presence(addr, pubkey, null, endpoint.presenceAddress);

            }
            catch (Exception e)
            {
                // Disconnect the node in case of any reading errors
                Logging.warn("Hello: Exception occurred in Hello Message {0}", e.ToString());
                sendBye(endpoint, ProtocolByeCode.deprecated, "Something went wrong during hello, make sure you're running the latest version of Ixian DLT.", "", true);
                return false;
            }

            if (NetworkClientManager.getConnectedClients().Count() == 1)
            {
                PresenceList.forceSendKeepAlive = true;
            }

            return true;
        }

        /// <summary>
        ///  Prepares and sends an Ixian protocol 'Hello' message to the specified remote endpoint.
        /// </summary>
        /// <remarks>
        ///  A valid Ixian 'Hello' message includes certain Node data, verified by a public-key signature, which this function prepares using
        ///  the primary wallet's keypair. If this message is a reply to the other endpoint's hello message, then
        /// </remarks>
        /// <param name="endpoint">Remote endpoint to send the message to.</param>
        /// <param name="sendHelloData">True if the message is the first hello sent to the remote node, false if it is a reply to the challenge.</param>
        /// <param name="challenge_response">Response byte-field to the other node's hello challenge</param>
        public static void sendHelloMessageV6(RemoteEndpoint endpoint, bool sendHelloData, int challenge)
        {
            using (MemoryStream m = new MemoryStream(1856))
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    string publicHostname = IxianHandler.getFullPublicAddress();

                    // Send the node version
                    writer.WriteIxiVarInt(6);

                    // Send the public node address
                    byte[] address = IxianHandler.getWalletStorage().getPrimaryAddress().addressWithChecksum;
                    writer.WriteIxiVarInt(address.Length);
                    writer.Write(address);

                    // Send the testnet designator
                    writer.Write(IxianHandler.isTestNet);

                    char node_type = PresenceList.myPresenceType;
                    writer.Write(node_type);

                    // Send the version
                    writer.Write(CoreConfig.productVersion);

                    // Send the node device id
                    writer.WriteIxiVarInt(CoreConfig.device_id.Length);
                    writer.Write(CoreConfig.device_id);

                    // Send the wallet public key
                    writer.WriteIxiVarInt(IxianHandler.getWalletStorage().getPrimaryPublicKey().Length);
                    writer.Write(IxianHandler.getWalletStorage().getPrimaryPublicKey());

                    // Send listening port
                    writer.WriteIxiVarInt(IxianHandler.publicPort);

                    // Send timestamp
                    long timestamp = Clock.getTimestamp() + endpoint.calculateTimeDifference();
                    writer.WriteIxiVarInt(timestamp);

                    // generate signature
                    using (MemoryStream mSig = new MemoryStream(1024))
                    {
                        using (BinaryWriter sigWriter = new BinaryWriter(mSig))
                        {
                            sigWriter.Write(ConsensusConfig.ixianChecksumLock);
                            sigWriter.Write(CoreConfig.device_id);
                            sigWriter.Write(timestamp);
                            sigWriter.Write(publicHostname);
                            sigWriter.Write(challenge);
                        }
                        byte[] signature = CryptoManager.lib.getSignature(mSig.ToArray(), IxianHandler.getWalletStorage().getPrimaryPrivateKey());
                        writer.WriteIxiVarInt(signature.Length);
                        writer.Write(signature);
                    }

                    if (sendHelloData)
                    {
                        Block block = IxianHandler.getLastBlock();
                        if (block == null)
                        {
                            Logging.warn("Clients are connecting, but we have no blocks yet to send them!");
                            sendBye(endpoint, ProtocolByeCode.notReady, string.Format("The node isn't ready yet, please try again later."), "", false);
                            return;
                        }


                        writer.WriteIxiVarInt(block.blockNum);

                        if (block.blockChecksum != null)
                        {
                            writer.WriteIxiVarInt(block.blockChecksum.Length);
                            writer.Write(block.blockChecksum);
                        }
                        else
                        {
                            writer.WriteIxiVarInt(0);
                        }

                        writer.WriteIxiVarInt(block.version);

                        writer.Write(endpoint.getFullAddress(true));

#if TRACE_MEMSTREAM_SIZES
                        Logging.info(String.Format("CoreProtocolMessage::sendHelloMessage: {0}", m.Length));
#endif

                        endpoint.sendData(ProtocolMessageCode.helloData, m.ToArray());

                    }
                    else
                    {
                        byte[] challenge_bytes = IxiVarInt.GetIxiVarIntBytes(challenge);
                        endpoint.challenge = BitConverter.GetBytes(challenge);
                        writer.Write(challenge_bytes);

#if TRACE_MEMSTREAM_SIZES
                        Logging.info(String.Format("CoreProtocolMessage::sendHelloMessage: {0}", m.Length));
#endif

                        endpoint.sendData(ProtocolMessageCode.hello, m.ToArray());
                    }
                }
            }
        }


        /// <summary>
        ///  Prepares and broadcasts an Ixian protocol message to all connected nodes, filtered by `types`.
        /// </summary>
        /// <remarks>
        ///  The payload `data` should be properly formatted for the given `code` - this function will not ensure that this is so and
        ///  the caller must provide a valid message to this function.
        ///  The `skipEndpoint` parameter is useful when re-broadcasting a message received from a specific endpoint and do not wish to echo the same
        ///  data back to the sender.
        /// </remarks>
        /// <param name="types">Types of nodes to send this message to.</param>
        /// <param name="code">Protocol code.</param>
        /// <param name="data">Message payload</param>
        /// <param name="helper_data">Additional information, as required by the protocol message</param>
        /// <param name="skipEndpoint">Remote endpoint which should be skipped (data should not be sent to it).</param>
        /// <returns>True, if at least one message was sent to at least one other node. False if no messages were sent.</returns>
        public static bool broadcastProtocolMessage(char[] types, ProtocolMessageCode code, byte[] data, byte[] helper_data, RemoteEndpoint skipEndpoint = null)
        {
            if (data == null)
            {
                Logging.warn(string.Format("Invalid protocol message data for {0}", code));
                return false;
            }

            bool c_result = NetworkClientManager.broadcastData(types, code, data, helper_data, skipEndpoint);
            bool s_result = NetworkServer.broadcastData(types, code, data, helper_data, skipEndpoint);
            
            if (!c_result
                && !s_result)
                return false;

            return true;
        }

        // Broadcast an event-specific protocol message across subscribed clients
        // Returns true if it sent the message to at least one endpoint. Returns false if the message couldn't be sent to any endpoints
        /// <summary>
        ///  Broadcasts an event message to all clients who are subscribed to receive the specific event type and wallet address.
        /// </summary>
        /// <remarks>
        ///  Events are filtered by type and address. A client must subscribe to the specifif type for specific addresses in order to receive this data.
        ///  The payload `data` should be properly formatted for the given `code` - this function will not ensure that this is so and
        ///  the caller must provide a valid message to this function.
        ///  The `skipEndpoint` parameter is useful when re-broadcasting a message received from a specific endpoint and do not wish to echo the same
        ///  data back to the sender.
        /// </remarks>
        /// <param name="type">Type of the event message - used to filter subscribers</param>
        /// <param name="address">Address, which triggered the event.</param>
        /// <param name="code">Ixian protocol code.</param>
        /// <param name="data">Payload data.</param>
        /// <param name="helper_data">Optional additional data, as required by `code`.</param>
        /// <param name="skipEndpoint">Endpoint to skip when broadcasting.</param>
        /// <returns>True, if at least one message was sent to at least one remote endpoint. False if no messages were sent.</returns>
        public static bool broadcastEventDataMessage(NetworkEvents.Type type, byte[] address, ProtocolMessageCode code, byte[] data, byte[] helper_data, RemoteEndpoint skipEndpoint = null)
        {
            // Send it to subscribed C nodes
            bool f_result = NetworkServer.broadcastEventData(type, code, data, address, helper_data, skipEndpoint);
            return f_result;
        }


        // Broadcasts protocol message to a single random node with block height higher than the one specified with parameter block_num
        /// <summary>
        ///  Sends the specified protocol message to one of the connected remote endpoints, chosen randomly.
        /// </summary>
        /// <remarks>
        ///  The payload `data` should be properly formatted for the given `code` - this function will not ensure that this is so and
        ///  the caller must provide a valid message to this function.
        ///  The `skipEndpoint` parameter is useful when re-broadcasting a message received from a specific endpoint and do not wish to echo the same
        ///  data back to the sender.
        ///  The `block_num` parameter is used to filter the remote endpoints based on their latest known block height.
        /// </remarks>
        /// <param name="types">Types of the nodes where the message should be sent.</param>
        /// <param name="code">Ixian protocol code.</param>
        /// <param name="data">Payload data.</param>
        /// <param name="block_num">Minimum block height for endpoints which should receive this message.</param>
        /// <param name="skipEndpoint">Skip sending message to this endpoint.</param>
        /// <param name="helper_data">Additional information, to prevent sending duplicate messages. In case of duplicate message will be replaced with latest message.</param>
        /// <param name="msg_id">Message id, usually related to block height, which prioritizes relevant incoming messages.</param>
        /// <returns>True, if at least one message was sent to at least one remote endpoint. False if no messages were sent.</returns>
        public static bool broadcastProtocolMessageToSingleRandomNode(char[] types, ProtocolMessageCode code, byte[] data, ulong block_num, RemoteEndpoint skipEndpoint = null, byte[] helper_data = null, long msg_id = 0)
        {
            if (data == null)
            {
                Logging.warn("Invalid protocol message data for {0}", code);
                return false;
            }

            lock (NetworkClientManager.networkClients)
            {
                lock (NetworkServer.connectedClients)
                {
                    int serverCount = 0;
                    int clientCount = 0;
                    List<NetworkClient> servers = null;
                    List<RemoteEndpoint> clients = null;

                    if (types == null)
                    {
                        servers = NetworkClientManager.networkClients.FindAll(x => x.blockHeight > block_num && x.isConnected() && x.helloReceived);
                        clients = NetworkServer.connectedClients.FindAll(x => x.blockHeight > block_num && x.isConnected() && x.helloReceived);

                        serverCount = servers.Count();
                        clientCount = clients.Count();

                        if (serverCount == 0 && clientCount == 0)
                        {
                            servers = NetworkClientManager.networkClients.FindAll(x => x.blockHeight == block_num && x.isConnected() && x.helloReceived);
                            clients = NetworkServer.connectedClients.FindAll(x => x.blockHeight == block_num && x.isConnected() && x.helloReceived);
                        }
                    }
                    else
                    {
                        servers = NetworkClientManager.networkClients.FindAll(x => x.blockHeight > block_num && x.presenceAddress != null && types.Contains(x.presenceAddress.type) && x.isConnected() && x.helloReceived);
                        clients = NetworkServer.connectedClients.FindAll(x => x.blockHeight > block_num && x.presenceAddress != null && types.Contains(x.presenceAddress.type) && x.isConnected() && x.helloReceived);

                        serverCount = servers.Count();
                        clientCount = clients.Count();

                        if (serverCount == 0 && clientCount == 0)
                        {
                            servers = NetworkClientManager.networkClients.FindAll(x => x.blockHeight == block_num && x.presenceAddress != null && types.Contains(x.presenceAddress.type) && x.isConnected() && x.helloReceived);
                            clients = NetworkServer.connectedClients.FindAll(x => x.blockHeight == block_num && x.presenceAddress != null && types.Contains(x.presenceAddress.type) && x.isConnected() && x.helloReceived);
                        }
                    }

                    serverCount = servers.Count();
                    clientCount = clients.Count();

                    if (serverCount == 0 && clientCount == 0)
                    {
                        return false;
                    }

                    int rIdx = Random.Shared.Next(serverCount + clientCount);

                    RemoteEndpoint re = null;

                    if (rIdx < serverCount)
                    {
                        re = servers[rIdx];
                    }
                    else
                    {
                        re = clients[rIdx - serverCount];
                    }

                    if (re == skipEndpoint && serverCount + clientCount > 1)
                    {
                        if (rIdx + 1 < serverCount)
                        {
                            re = servers[rIdx + 1];
                        }
                        else if (rIdx + 1 < serverCount + clientCount)
                        {
                            re = clients[rIdx + 1 - serverCount];
                        }
                        else if (serverCount > 0)
                        {
                            re = servers[0];
                        }
                        else if (clientCount > 0)
                        {
                            re = clients[0];
                        }
                    }

                    if (re != null && re.isConnected())
                    {
                        re.sendData(code, data, helper_data, msg_id);
                        return true;
                    }
                    return false;
                }
            }
        }

        /// <summary>
        ///  Verifies that the given remote endpoint is reachable by connecting to it and sending a short message.
        /// </summary>
        /// <remarks>
        ///  This function is used to ensure that the remote endpoing has listed the correct IP and port information for their `PresenceList` entry.
        /// </remarks>
        /// <param name="endpoint">Target endpoint to verify for connectivity.</param>
        /// <returns>True, if the endpoing is connectable.</returns>
        public static bool checkNodeConnectivity(RemoteEndpoint endpoint)
        {
            // TODO TODO TODO TODO we should put this in a separate thread
            string hostname = endpoint.getFullAddress(true);
            if (NetworkUtils.PingAddressReachable(hostname) == false)
            {
                Logging.warn("Node {0} was not reachable on the advertised address.", hostname);
                sendBye(endpoint, ProtocolByeCode.notConnectable, "External " + hostname + " not reachable!", "", true);
                return false;
            }
            return true;
        }

        /// <summary>
        /// Returns cuckoo filter based on client's addresses
        /// </summary>
        public static Cuckoo getMyAddressesCuckooFilter()
        {
            var my_addresses = IxianHandler.getWalletStorage().getMyAddresses();
            Cuckoo filter = new Cuckoo(my_addresses.Count());
            foreach (var addr in my_addresses)
            {
                filter.Add(addr.addressNoChecksum);
            }
            return filter;
        }

        /// <summary>
        /// Subscribes client to transactionFrom, transactionTo and balance
        /// </summary>
        /// <param name="endpoint">Target endpoint to verify for connectivity.</param>
        public static void subscribeToEvents(RemoteEndpoint endpoint)
        {
            // TODO TODO TODO events can be optimized as there is no real need to subscribe them to every connected node

            // Subscribe to transaction events, for own addresses
            var my_addresses = IxianHandler.getWalletStorage().getMyAddresses();
            Cuckoo filter = getMyAddressesCuckooFilter();
            byte[] filter_data = filter.getFilterBytes();
            byte[] event_data = NetworkEvents.prepareEventMessageData(NetworkEvents.Type.transactionFrom, filter_data);
            endpoint.sendData(ProtocolMessageCode.attachEvent, event_data);

            event_data = NetworkEvents.prepareEventMessageData(NetworkEvents.Type.transactionTo, filter_data);
            endpoint.sendData(ProtocolMessageCode.attachEvent, event_data);

            event_data = NetworkEvents.prepareEventMessageData(NetworkEvents.Type.balance, filter_data);
            endpoint.sendData(ProtocolMessageCode.attachEvent, event_data);
        }

        public static bool broadcastGetTransaction(byte[] txid, ulong block_num, RemoteEndpoint endpoint = null, bool broadcast_to_single_node = true)
        {
            using (MemoryStream mw = new MemoryStream())
            {
                using (BinaryWriter writerw = new BinaryWriter(mw))
                {
                    writerw.WriteIxiVarInt(txid.Length);
                    writerw.Write(txid);
                    writerw.WriteIxiVarInt(block_num);
#if TRACE_MEMSTREAM_SIZES
                        Logging.info(String.Format("NetworkProtocol::broadcastGetTransaction: {0}", mw.Length));
#endif

                    if (endpoint != null)
                    {
                        if (endpoint.isConnected())
                        {
                            endpoint.sendData(ProtocolMessageCode.getTransaction3, mw.ToArray());
                            return true;
                        }
                    }
                    // TODO TODO TODO TODO TODO determine if historic transaction and send to 'H' instead of 'M'
                    char[] node_types = new char[] { 'M', 'H' };
                    if (PresenceList.myPresenceType == 'C')
                    {
                        node_types = new char[] { 'M', 'H', 'R' };
                    }
                    if (broadcast_to_single_node)
                    {
                        return broadcastProtocolMessageToSingleRandomNode(node_types, ProtocolMessageCode.getTransaction3, mw.ToArray(), block_num);
                    }
                    else
                    {
                        return broadcastProtocolMessage(node_types, ProtocolMessageCode.getTransaction3, mw.ToArray(), null);
                    }
                }
            }
        }

        public static void broadcastGetPresence(byte[] address, RemoteEndpoint endpoint)
        {
            using (MemoryStream mw = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(mw))
                {
                    writer.WriteIxiVarInt(address.Length);
                    writer.Write(address);

                    if (endpoint != null && endpoint.isConnected())
                    {
                        endpoint.sendData(ProtocolMessageCode.getPresence2, mw.ToArray(), address);
                    }
                    else
                    {
                        char[] node_types = new char[] { 'M', 'H' };
                        if (PresenceList.myPresenceType == 'C')
                        {
                            node_types = new char[] { 'M', 'H', 'R' };
                        }
                        broadcastProtocolMessageToSingleRandomNode(node_types, ProtocolMessageCode.getPresence2, mw.ToArray(), 0, null, address);
                    }
                }
            }
        }

        public static bool addToInventory(char[] types, InventoryItem item, RemoteEndpoint skip_endpoint)
        {
            bool c_result = NetworkClientManager.addToInventory(types, item, skip_endpoint);
            bool s_result = NetworkServer.addToInventory(types, item, skip_endpoint);
            return c_result || s_result;
        }

        public static void processBye(byte[] data, RemoteEndpoint endpoint)
        {
            using (MemoryStream m = new MemoryStream(data))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    endpoint.stop();

                    try
                    {
                        ProtocolByeCode byeCode = (ProtocolByeCode)reader.ReadInt32();
                        string byeMessage = reader.ReadString();
                        string byeData = reader.ReadString();

                        switch (byeCode)
                        {
                            case ProtocolByeCode.bye: // all good
                                endpoint.reconnectOnFailure = false;
                                break;

                            case ProtocolByeCode.incorrectIp: // incorrect IP
                                if (PresenceList.myPresenceType == 'M'
                                    || PresenceList.myPresenceType == 'H'
                                    || PresenceList.myPresenceType == 'R')
                                {
                                    if (IxiUtils.validateIPv4(byeData))
                                    {
                                        if (NetworkClientManager.getConnectedClients(true).Length < 2
                                            && NetworkServer.getConnectedClients(true).Length < 2)
                                        {
                                            if (!IxianHandler.forceIP)
                                            {
                                                IxianHandler.publicIP = byeData;
                                                Logging.warn("Changed internal IP Address to " + byeData + ", reconnecting");
                                                return;
                                            }
                                        }
                                    }
                                }
                                Logging.warn("Disconnected by '{0}', with message: {1} {2} {3}", endpoint.address.ToString(), byeCode.ToString(), byeMessage, byeData);
                                break;

                            case ProtocolByeCode.notConnectable: // not connectable from the internet
                                NetworkServer.connectable = false;
                                if (PresenceList.myPresenceType == 'M'
                                    || PresenceList.myPresenceType == 'H'
                                    || PresenceList.myPresenceType == 'R')
                                {
                                    if (!NetworkServer.isConnectable())
                                    {
                                        Logging.error("This node must be connectable from the internet, to connect to the network.");
                                        Logging.error("Please setup uPNP and/or port forwarding on your router for port " + IxianHandler.publicPort + ".");
                                    }
                                }
                                break;

                            default:
                                Logging.warn("Disconnected by '{0}', with message: {1} {2} {3}", endpoint.address.ToString(), byeCode.ToString(), byeMessage, byeData);
                                break;
                        }
                    }
                    catch (Exception e)
                    {
                        Logging.error("Exception in processBye: " + e);
                    }
                }
            }
        }

        public static void broadcastGetRegisteredNameRecord(byte[] name, byte[] record, RemoteEndpoint endpoint)
        {
            using (MemoryStream mw = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(mw))
                {
                    writer.Write(name.GetIxiBytes());
                    writer.Write(record.GetIxiBytes());
                }

                if (endpoint != null && endpoint.isConnected())
                {
                    endpoint.sendData(ProtocolMessageCode.getNameRecord, mw.ToArray(), name);
                }
                else
                {
                    char[] node_types = new char[] { 'M', 'H' };
                    if (PresenceList.myPresenceType == 'C')
                    {
                        node_types = new char[] { 'M', 'H', 'R' };
                    }
                    broadcastProtocolMessageToSingleRandomNode(node_types, ProtocolMessageCode.getNameRecord, mw.ToArray(), 0, null, name);
                }
            }
        }

        public static void sendRegisteredNameRecord(RemoteEndpoint endpoint, byte[] name, List<RegisteredNameDataRecord> dataRecords)
        {
            // TODO TODO TODO extend this with proof paths, sigs and relevant data
            using (MemoryStream mw = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(mw))
                {
                    writer.WriteIxiVarInt(name.Length);
                    writer.Write(name);

                    writer.WriteIxiVarInt(dataRecords.Count);
                    foreach (var dataRecord in dataRecords)
                    {
                        byte[] data = dataRecord.toBytes(false);
                        writer.WriteIxiVarInt(data.Length);
                        writer.Write(data);
                    }
                }
                endpoint.sendData(ProtocolMessageCode.nameRecord, mw.ToArray());
            }
        }

        public static void sendSectorNodes(byte[] prefix, List<Address> relayList, RemoteEndpoint endpoint)
        {
            using (MemoryStream m = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.WriteIxiVarInt(prefix.Length);
                    writer.Write(prefix);

                    var relayPresences = relayList.Select(PresenceList.getPresenceByAddress)
                     .Where(p => p != null)
                     .ToList();

                    writer.WriteIxiVarInt(relayPresences.Count);

                    foreach (var p in relayPresences)
                    {
                        var pBytes = p.getBytes();
                        writer.WriteIxiVarInt(pBytes.Length);
                        writer.Write(pBytes);
                    }
                }

                endpoint.sendData(ProtocolMessageCode.sectorNodes, m.ToArray(), null, 0, MessagePriority.high);
            }
        }

        public static void broadcastGetKeepAlives(List<InventoryItemKeepAlive> ka_list, RemoteEndpoint endpoint)
        {
            int ka_count = ka_list.Count;
            int max_ka_per_chunk = CoreConfig.maximumKeepAlivesPerChunk;
            for (int i = 0; i < ka_count;)
            {
                using (MemoryStream mOut = new MemoryStream(max_ka_per_chunk * 570))
                {
                    using (BinaryWriter writer = new BinaryWriter(mOut))
                    {
                        int next_ka_count;
                        if (ka_count - i > max_ka_per_chunk)
                        {
                            next_ka_count = max_ka_per_chunk;
                        }
                        else
                        {
                            next_ka_count = ka_count - i;
                        }
                        writer.WriteIxiVarInt(next_ka_count);

                        for (int j = 0; j < next_ka_count && i < ka_count; j++)
                        {
                            InventoryItemKeepAlive ka = ka_list[i];
                            i++;

                            if (ka == null)
                            {
                                break;
                            }

                            long rollback_len = mOut.Length;

                            writer.WriteIxiVarInt(ka.address.addressNoChecksum.Length);
                            writer.Write(ka.address.addressNoChecksum);

                            writer.WriteIxiVarInt(ka.deviceId.Length);
                            writer.Write(ka.deviceId);

                            if (mOut.Length > CoreConfig.maxMessageSize)
                            {
                                mOut.SetLength(rollback_len);
                                i--;
                                break;
                            }
                        }
                    }
                    endpoint.sendData(ProtocolMessageCode.getKeepAlives, mOut.ToArray(), null);
                }
            }
        }

        /// <summary>
        ///  Determines highest network block height depending on 2/3rd of connected servers block heights.
        /// </summary>
        public static ulong determineHighestNetworkBlockNum()
        {
            List<ulong> blockHeights = NetworkClientManager.getBlockHeights();
            blockHeights.AddRange(NetworkServer.getBlockHeights());

            if (blockHeights.Count() < 1)
            {
                return 0;
            }

            blockHeights.Sort();

            int thirdCount = (int)Math.Floor((decimal)blockHeights.Count / 3);

            var blockHeightsMajority = blockHeights;

            if (thirdCount >= 1 && blockHeights.Count > thirdCount)
            {
                blockHeightsMajority = blockHeights.Skip(thirdCount).Take(thirdCount).ToList();
            }

            ulong netBh = blockHeightsMajority.Max();

            Block lastBlock = IxianHandler.getLastBlock();
            if (lastBlock == null)
            {
                return netBh;
            }

            ulong maxBlocksGenerated = (ulong)(Clock.getNetworkTimestamp() - lastBlock.timestamp) / (ulong)ConsensusConfig.blockGenerationInterval;
            ulong maxBlockHeight = lastBlock.blockNum + maxBlocksGenerated;
            if (maxBlockHeight < netBh)
            {
                return maxBlockHeight;
            }
            return netBh;
        }

        public static void broadcastGetTransactions(List<byte[]> tx_list, long block_num, RemoteEndpoint endpoint)
        {
            int tx_count = tx_list.Count;
            int max_tx_per_chunk = CoreConfig.maximumTransactionsPerChunk;
            for (int i = 0; i < tx_count;)
            {
                using (MemoryStream mOut = new MemoryStream(max_tx_per_chunk * 570))
                {
                    using (BinaryWriter writer = new BinaryWriter(mOut))
                    {
                        int next_tx_count = tx_count - i;
                        if (next_tx_count > max_tx_per_chunk)
                        {
                            next_tx_count = max_tx_per_chunk;
                        }
                        writer.WriteIxiVarInt(block_num);
                        writer.WriteIxiVarInt(next_tx_count);

                        for (int j = 0; j < next_tx_count && i < tx_count; j++)
                        {
                            long rollback_len = mOut.Length;

                            writer.WriteIxiVarInt(tx_list[i].Length);
                            writer.Write(tx_list[i]);

                            i++;

                            if (mOut.Length > CoreConfig.maxMessageSize)
                            {
                                mOut.SetLength(rollback_len);
                                i--;
                                break;
                            }
                        }
                    }
                    MessagePriority priority = block_num > 0 ? MessagePriority.high : MessagePriority.auto;
                    if (endpoint == null)
                    {
                        char[] node_types = new char[] { 'M', 'H' };
                        if (PresenceList.myPresenceType == 'C')
                        {
                            node_types = new char[] { 'M', 'H', 'R' };
                        }
                        CoreProtocolMessage.broadcastProtocolMessageToSingleRandomNode(node_types, ProtocolMessageCode.getTransactions2, mOut.ToArray(), 0, null);
                    }
                    else
                    {
                        endpoint.sendData(ProtocolMessageCode.getTransactions2, mOut.ToArray(), null, 0, priority);
                    }
                }
            }
        }

        public static void processGetKeepAlives(byte[] data, RemoteEndpoint endpoint)
        {
            using (MemoryStream m = new MemoryStream(data))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    int ka_count = (int)reader.ReadIxiVarUInt();

                    int max_ka_per_chunk = CoreConfig.maximumKeepAlivesPerChunk;

                    for (int i = 0; i < ka_count;)
                    {
                        using (MemoryStream mOut = new MemoryStream(max_ka_per_chunk * 570))
                        {
                            using (BinaryWriter writer = new BinaryWriter(mOut))
                            {
                                int next_ka_count;
                                if (ka_count - i > max_ka_per_chunk)
                                {
                                    next_ka_count = max_ka_per_chunk;
                                }
                                else
                                {
                                    next_ka_count = ka_count - i;
                                }
                                writer.WriteIxiVarInt(next_ka_count);

                                for (int j = 0; j < next_ka_count && i < ka_count; j++)
                                {
                                    i++;

                                    long in_rollback_pos = reader.BaseStream.Position;
                                    long out_rollback_len = mOut.Length;

                                    if (m.Position == m.Length)
                                    {
                                        break;
                                    }

                                    int address_len = (int)reader.ReadIxiVarUInt();
                                    Address address = new Address(reader.ReadBytes(address_len));

                                    int device_len = (int)reader.ReadIxiVarUInt();
                                    byte[] device = reader.ReadBytes(device_len);

                                    Presence p = PresenceList.getPresenceByAddress(address);
                                    if (p == null)
                                    {
                                        Logging.info("I don't have presence: " + address.ToString());
                                        continue;
                                    }

                                    PresenceAddress pa = p.addresses.Find(x => x.device.SequenceEqual(device));
                                    if (pa == null)
                                    {
                                        Logging.info("I don't have presence address: " + address.ToString());
                                        continue;
                                    }

                                    KeepAlive ka = pa.getKeepAlive(address);
                                    byte[] ka_bytes = ka.getBytes();
                                    byte[] ka_len = IxiVarInt.GetIxiVarIntBytes(ka_bytes.Length);
                                    writer.Write(ka_len);
                                    writer.Write(ka_bytes);

                                    if (mOut.Length > CoreConfig.maxMessageSize)
                                    {
                                        reader.BaseStream.Position = in_rollback_pos;
                                        mOut.SetLength(out_rollback_len);
                                        i--;
                                        break;
                                    }
                                }
                            }
                            endpoint.sendData(ProtocolMessageCode.keepAlivesChunk, mOut.ToArray(), null);
                        }
                    }
                }
            }
        }

        public static void sendRejected(RejectedCode code, byte[] data, RemoteEndpoint endpoint)
        {
            endpoint?.sendData(ProtocolMessageCode.rejected, new Rejected(code, data).getBytes());
        }

        public static void fetchSectorNodes(Address address, int maxSectorNodesToRequest, RemoteEndpoint endpoint = null)
        {
            Logging.trace("Fetching sector nodes for " + address.ToString());
            using (MemoryStream mw = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(mw))
                {
                    writer.WriteIxiVarInt(address.sectorPrefix.Length);
                    writer.Write(address.sectorPrefix);
                    writer.WriteIxiVarInt(maxSectorNodesToRequest);
                }
                if (endpoint != null)
                {
                    endpoint.sendData(ProtocolMessageCode.getSectorNodes, mw.ToArray(), null);
                }
                else
                {
                    char[] nodeTypes = ['M', 'H', 'R'];
                    if (PresenceList.myPresenceType == 'M'
                        || PresenceList.myPresenceType == 'H'
                        || PresenceList.myPresenceType == 'R')
                    {
                        nodeTypes = ['M', 'H'];
                    }
                    NetworkClientManager.broadcastData(nodeTypes, ProtocolMessageCode.getSectorNodes, mw.ToArray(), null);
                }
            }
        }
    }
}

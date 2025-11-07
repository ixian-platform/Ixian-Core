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

using IXICore.Meta;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace IXICore.Network
{
    static class StreamClientManager
    {
        private static List<NetworkClient> streamClients = new List<NetworkClient>();
        private static List<string> connectingClients = new List<string>(); // A list of clients that we're currently connecting

        private static CancellationTokenSource ctsLoop;
        private static Task reconnectTask;
        private static TaskCompletionSource wakeSignal = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private static readonly TimeSpan reconnectInterval = TimeSpan.FromMilliseconds(CoreConfig.networkClientReconnectInterval);
        private static bool autoReconnect = true;

        public static string primaryS2Address = "";

        private static int simultaneousConnectedNeighbors;
        private static bool automaticallySetPublicIP;

        private static HashSet<string> pinnedNodes = new();

        private static string bindAddress = null;

        public static void start(int simultaneousConnectedNeighbors, bool automaticallySetPublicIP, string bindAddress = null)
        {
            if (ctsLoop != null)
            {
                return;
            }

            StreamClientManager.simultaneousConnectedNeighbors = simultaneousConnectedNeighbors;
            StreamClientManager.automaticallySetPublicIP = automaticallySetPublicIP;
            StreamClientManager.bindAddress = bindAddress;

            streamClients.Clear();
            connectingClients.Clear();

            ctsLoop = new CancellationTokenSource();

            // Start the reconnect thread
            autoReconnect = true;
            reconnectTask = Task.Run(() => reconnectLoop(ctsLoop.Token));
        }

        public static void stop()
        {
            if (ctsLoop == null)
            {
                return;
            }

            autoReconnect = false;
            isolate();

            ctsLoop.Cancel();
            wakeSignal.TrySetResult();
            try
            {
                // Wait for reconnect loop to finish
                reconnectTask.GetAwaiter().GetResult();
            }
            catch (OperationCanceledException) { }
            finally
            {
                ctsLoop.Dispose();
                ctsLoop = null;
                reconnectTask = null;
            }
        }

        public static void setPinnedNodes(List<string> pinnedNodes)
        {
            lock (streamClients)
            {
                if (pinnedNodes == null)
                {
                    StreamClientManager.pinnedNodes = new();
                    return;
                }

                StreamClientManager.pinnedNodes = pinnedNodes.ToHashSet();
            }
        }

        // Immediately disconnects all clients
        public static void isolate()
        {
            Logging.info("Isolating stream clients...");

            lock (streamClients)
            {
                // Disconnect each client
                foreach (NetworkClient client in streamClients)
                {
                    client.stop();
                }

                // Empty the client list
                streamClients.Clear();
            }
        }

        public static void restartClients()
        {
            Logging.info("Stopping stream clients...");
            stop();
            Thread.Sleep(100);
            Logging.info("Starting stream clients...");
            start(simultaneousConnectedNeighbors, automaticallySetPublicIP);
        }

        // Send data to all connected nodes
        // Returns true if the data was sent to at least one client
        public static bool broadcastData(ProtocolMessageCode code, byte[] data, byte[] helperData, RemoteEndpoint skipEndpoint = null)
        {
            bool result = false;
            lock (streamClients)
            {
                foreach (NetworkClient client in streamClients)
                {
                    if (client.isConnected())
                    {
                        if (skipEndpoint != null)
                        {
                            if (client == skipEndpoint)
                                continue;
                        }

                        if (client.helloReceived == false)
                        {
                            continue;
                        }

                        client.sendData(code, data, helperData);
                        result = true;
                    }
                }
            }
            return result;
        }

        // Scan for and connect to a new stream node
        private static void connectToRandomStreamNode()
        {
            // TODO TODO TODO TODO improve this
            string neighbor = null;
            Address neighbor_address = null;

            try
            {
                List<Presence> presences = PresenceList.getPresencesByType('R', CoreConfig.maxRelaySectorNodesToRequest);
                if(presences.Count > 0)
                {
                    List<Presence> tmp_presences = presences.FindAll(x => x.addresses.Find(y => y.type == 'R') != null); // TODO tmp_presences can be removed after protocol is finalized

                    Presence p = tmp_presences[Random.Shared.Next(tmp_presences.Count)];
                    lock(p)
                    {
                        neighbor = p.addresses.Find(x => x.type == 'R').address;
                        neighbor_address = p.wallet;
                    }
                }
            }
            catch(Exception e)
            {
                Logging.error("Exception looking up random stream node: " + e);
                return;
            }

            if (neighbor != null)
            {
                Logging.info("Attempting to add new stream node: {0}", neighbor);
                connectTo(neighbor, neighbor_address);
            }
            else
            {
                Logging.error("Failed to add random stream node.");
            }
        }

        private static async Task reconnectLoop(CancellationToken token)
        {
            try
            {
                while (autoReconnect)
                {
                    try
                    {
                        handleDisconnectedClients();

                        if (getConnectedClients(true).Count() > simultaneousConnectedNeighbors)
                        {
                            NetworkClient? client = null;
                            lock (streamClients)
                            {
                                foreach (var tmpClient in streamClients)
                                {
                                    if (tmpClient.getFullAddress(true) == primaryS2Address)
                                    {
                                        continue;
                                    }
                                    if (pinnedNodes.Contains(tmpClient.getFullAddress(true)))
                                    {
                                        continue;
                                    }
                                    client = tmpClient;
                                    break;
                                }
                                if (client != null)
                                {
                                    streamClients.Remove(client);
                                }
                            }
                            if (client != null)
                            {
                                CoreProtocolMessage.sendBye(client, ProtocolByeCode.bye, "Disconnected for shuffling purposes.", "", false);
                                client.stop();
                            }
                        }

                        string[] netClients = getConnectedClients();

                        // Check if we need to connect to more neighbors
                        if (netClients.Length < 1)
                        {
                            // Scan for and connect to a new neighbor
                            connectToRandomStreamNode();
                        }

                        if (!netClients.Contains(primaryS2Address))
                        {
                            if (automaticallySetPublicIP)
                            {
                                var connectedClients = getConnectedClients(true);
                                if (connectedClients.Length > 0)
                                {
                                    primaryS2Address = connectedClients.First();

                                    var endpoint = streamClients.Find(x => x.getFullAddress(true) == primaryS2Address);
                                    if (endpoint != null)
                                    {
                                        IxianHandler.publicPort = endpoint.incomingPort;
                                        IxianHandler.publicIP = endpoint.address;
                                        PresenceList.forceSendKeepAlive = true;
                                        Logging.info("Forcing KA from StreamClientManager");
                                    }
                                }
                                else
                                {
                                    primaryS2Address = "";
                                    IxianHandler.publicIP = "";
                                }
                            }
                        }
                    }
                    catch (Exception e) when (e is not OperationCanceledException)
                    {
                        Logging.error("Fatal exception in reconnectClients: {0}", e);
                    }

                    // setup fresh wake signal
                    var currentWake = wakeSignal;
                    wakeSignal = new(TaskCreationOptions.RunContinuationsAsynchronously);

                    // wait either interval or wake signal
                    await Task.WhenAny(Task.Delay(reconnectInterval, token), currentWake.Task);
                }
            }
            catch (OperationCanceledException)
            {
                // normal shutdown
            }
            catch (Exception e)
            {
                Logging.error("ReconnectLoop exception: {0}", e);
            }
        }

        private static void handleDisconnectedClients()
        {
            List<NetworkClient> netClients = null;
            lock (streamClients)
            {
                netClients = new List<NetworkClient>(streamClients);
            }

            // Prepare a list of failed clients
            List<NetworkClient> failed_clients = new List<NetworkClient>();

            List<NetworkClient> dup_clients = new List<NetworkClient>();

            foreach (NetworkClient client in netClients)
            {
                if (dup_clients.Find(x => x.getFullAddress(true) == client.getFullAddress(true)) != null)
                {
                    failed_clients.Add(client);
                    continue;
                }
                dup_clients.Add(client);
                if (client.isConnected())
                {
                    continue;
                }
                // Check if we exceeded the maximum reconnect count
                if (!client.reconnectOnFailure)
                {
                    failed_clients.Add(client);
                }
                else if (client.getTotalReconnectsCount() >= CoreConfig.maximumNeighborReconnectCount
                         || client.fullyStopped)
                {
                    // Remove this client so we can search for a new neighbor
                    failed_clients.Add(client);
                    PeerStorage.decreaseRating(client.getFullAddress(true), 1);
                }
                else
                {
                    // Reconnect
                    client.reconnect();
                }
            }

            // Go through the list of failed clients and remove them
            foreach (NetworkClient client in failed_clients)
            {
                client.stop();
                lock (streamClients)
                {
                    streamClients.Remove(client);
                }
                // Remove this node from the connecting clients list
                lock (connectingClients)
                {
                    connectingClients.Remove(client.getFullAddress(true));
                }
            }
        }

        // Connects to a specified node, with the syntax host:port
        // Returns the connected stream client
        // Returns null if connection failed
        public static NetworkClient connectTo(string host, Address wallet_address)
        {
            if (host == null || host.Length < 3)
            {
                Logging.error("Invalid host address {0}", host);
                return null;
            }

            string[] server = host.Split(':');
            if (server.Count() < 2)
            {
                Logging.warn("Cannot connect to invalid hostname: {0}", host);
                return null;
            }

            // Resolve the hostname first
            string resolved_server_name = NetworkUtils.resolveHostname(server[0]);

            // Skip hostnames we can't resolve
            if (resolved_server_name.Length < 1)
            {
                Logging.warn("Cannot resolve IP for {0}, skipping connection.", server[0]);
                return null;
            }

            string resolved_host = string.Format("{0}:{1}", resolved_server_name, server[1]);

            if (NetworkServer.isRunning()
                && !automaticallySetPublicIP)
            {
                // Verify against the publicly disclosed ip
                // Don't connect to self
                if (resolved_server_name.Equals(IxianHandler.publicIP, StringComparison.Ordinal))
                {
                    if (server[1].Equals(string.Format("{0}", IxianHandler.publicPort), StringComparison.Ordinal))
                    {
                        Logging.info("Skipping connection to public self seed node {0}", host);
                        return null;
                    }
                }

                // Get all self addresses and run through them
                List<string> self_addresses = NetworkUtils.GetAllLocalIPAddresses();
                foreach (string self_address in self_addresses)
                {
                    // Don't connect to self
                    if (resolved_server_name.Equals(self_address, StringComparison.Ordinal))
                    {
                        if (server[1].Equals(string.Format("{0}", IxianHandler.publicPort), StringComparison.Ordinal))
                        {
                            Logging.info("Skipping connection to self seed node {0}", host);
                            return null;
                        }
                    }
                }
            }

            lock (connectingClients)
            {
                foreach (string client in connectingClients)
                {
                    if (resolved_host.Equals(client, StringComparison.Ordinal))
                    {
                        // We're already connecting to this client
                        return null;
                    }
                }

                // The the client to the connecting clients list
                connectingClients.Add(resolved_host);
            }

            // Check if node is already in the client list
            lock (streamClients)
            {
                foreach (NetworkClient client in streamClients)
                {
                    if (client.getFullAddress(true).Equals(resolved_host, StringComparison.Ordinal))
                    {
                        // Address is already in the client list
                        return null;
                    }
                }
            }


            // Connect to the specified node
            NetworkClient new_client = new NetworkClient(bindAddress);
            // Recompose the connection address from the resolved IP and the original port
            bool result = new_client.connectToServer(resolved_server_name, Convert.ToInt32(server[1]), wallet_address);

            // Add this node to the client list if connection was successfull
            if (result == true)
            {
                // Add this node to the client list
                lock (streamClients)
                {
                    streamClients.Add(new_client);
                }
            }

            // Remove this node from the connecting clients list
            lock (connectingClients)
            {
                connectingClients.Remove(resolved_host);
            }

            return new_client;
        }

        // Check if we're connected to a certain host address
        // Returns StreamClient or null if not found
        public static NetworkClient isConnectedTo(string address, bool only_fully_connected = true)
        {
            lock (streamClients)
            {
                foreach (NetworkClient client in streamClients)
                {
                    if (client.remoteIP.Address.ToString().Equals(address, StringComparison.Ordinal))
                    {
                        if (only_fully_connected && (!client.isConnected() || !client.helloReceived))
                        {
                            break;
                        }
                        return client;
                    }
                }
            }

            return null;
        }

        // Returns all the connected clients
        public static string[] getConnectedClients(bool only_fully_connected = false)
        {
            List<string> result = new List<string>();

            lock (streamClients)
            {
                foreach (NetworkClient client in streamClients)
                {
                    if (client.isConnected())
                    {
                        if (only_fully_connected && !client.helloReceived)
                        {
                            continue;
                        }

                        try
                        {
                            string client_name = client.getFullAddress(true);
                            result.Add(client_name);
                        }
                        catch (Exception e)
                        {
                            Logging.error("StreamClientManager->getConnectedClients: {0}", e);
                        }
                    }
                }
            }

            return result.ToArray();
        }

        public static NetworkClient getClient(Address clientAddress, bool fullyConnected = true)
        {
            lock (streamClients)
            {
                foreach (NetworkClient c in streamClients)
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

        public static bool sendToClient(List<Peer> relayNodes, ProtocolMessageCode code, byte[] data, byte[] helper_data, int client_count = 1)
        {
            List<NetworkClient> clients = new();
            lock (streamClients)
            {
                foreach (NetworkClient c in streamClients)
                {
                    if (c.isConnected()
                        && c.helloReceived
                        && relayNodes.Find(x => (x.hostname != null && x.hostname == c.getFullAddress()) || (x.walletAddress != null && x.walletAddress.SequenceEqual(c.serverWalletAddress))) != null)
                    {
                        clients.Add(c);
                        if (clients.Count == client_count)
                        {
                            break;
                        }
                    }
                }
            }

            if (clients.Count > 0)
            {
                foreach (var c in clients)
                {
                    c.sendData(code, data, helper_data);
                }
                return true;
            }

            return false;
        }

        public static bool sendToClient(Address neighbor, ProtocolMessageCode code, byte[] data, byte[] helper_data)
        {
            NetworkClient client = getClient(neighbor, true);

            if (client != null)
            {
                client.sendData(code, data, helper_data);
                return true;
            }

            return false;
        }

        public static void wakeReconnectLoop()
        {
            wakeSignal.TrySetResult();
        }
    }
}

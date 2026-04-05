// Copyright (C) 2017-2026 Ixian
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

namespace IXICore.Network
{
    public abstract class NetworkClientManagerBase
    {
        public List<NetworkClient> networkClients { get; private set; } = new List<NetworkClient>();
        protected List<string> connectingClients = new List<string>(); // A list of clients that we're currently connecting

        private CancellationTokenSource? ctsLoop = null;
        private Task? reconnectTask = null;
        private TaskCompletionSource wakeSignal = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TimeSpan reconnectInterval = TimeSpan.FromMilliseconds(CoreConfig.networkClientReconnectInterval);
        protected bool autoReconnect = true;

        protected ThreadLiveCheck TLC;

        protected bool paused = false;

        /// <summary>
        ///  Target number of simultaneously connected neighbors.
        /// </summary>
        /// <remarks>
        ///  If more neighbors are connected, they will slowly be disconnected. 
        ///  If fewer neighbors are connected, more will be added over time.
        /// </remarks>
        public int simultaneousConnectedNeighbors;

        private string? bindAddress = null;

        private HashSet<string> pinnedNodes = new();

        public NetworkClientManagerBase(int simultaneousConnectedNeighbors, string? bindAddress = null)
        {
            if (simultaneousConnectedNeighbors < 3)
            {
                throw new Exception("Setting simultanousConnectedNeighbors should be at least 3.");
            }
            this.simultaneousConnectedNeighbors = simultaneousConnectedNeighbors;
            this.bindAddress = bindAddress;

            TLC = new ThreadLiveCheck();
        }

        // Starts the Network Client Manager.
        // If connections_to_wait_for parameter is bigger than 0, it waits until it connects to the specified number of nodes.
        // Afterwards, it starts the reconnect and keepalive threads
        public void start(int connections_to_wait_for = 0)
        {
            lock (networkClients)
            {
                if (ctsLoop != null)
                {
                    return;
                }

                if (CoreConfig.preventNetworkOperations)
                {
                    Logging.warn("Not starting NetworkClientManager thread due to preventNetworkOperations flag being set.");
                    return;
                }

                networkClients.Clear();
                connectingClients.Clear();

                ctsLoop = new CancellationTokenSource();

            }
            if (connections_to_wait_for > 0)
            {
                // Connect to a random node first
                int i = 0;
                while (getConnectedClients(true).Count() < connections_to_wait_for && IxianHandler.forceShutdown == false)
                {
                    Task.Run(() =>
                    {
                        handleDisconnectedClients();
                        reconnectClients();
                    });
                    i++;
                    if (i > 10)
                    {
                        i = 0;
                        Thread.Sleep(1000);
                    }
                    else
                    {
                        Thread.Sleep(200);
                    }
                    if (ctsLoop == null)
                    {
                        return;
                    }
                }
            }

            // Start the reconnect thread
            autoReconnect = true;
            reconnectTask = Task.Run(() => reconnectLoop(ctsLoop.Token));
        }

        private async Task reconnectLoop(CancellationToken token)
        {
            try
            {
                while (autoReconnect && !token.IsCancellationRequested)
                {
                    if (!paused)
                    {
                        TLC.Report();

                        try
                        {
                            handleDisconnectedClients();
                            reconnectClients();
                        }
                        catch (Exception e) when (e is not OperationCanceledException)
                        {
                            Logging.error("Fatal exception in reconnectClients: {0}", e);
                        }
                    }

                    // wait either interval or wake signal
                    await Task.WhenAny(Task.Delay(reconnectInterval, token), wakeSignal.Task).ConfigureAwait(false);

                    // setup fresh wake signal
                    wakeSignal = new(TaskCreationOptions.RunContinuationsAsynchronously);
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

        // Checks for missing clients
        protected void reconnectClients()
        {
            // Check if we need to connect to more neighbors
            if (getConnectedClients().Count() < simultaneousConnectedNeighbors)
            {
                // Scan for and connect to a new neighbor
                connectToRandomNeighbor();
                return;
            }
            else if (getConnectedClients(true).Count() > simultaneousConnectedNeighbors)
            {
                NetworkClient? client = null;
                lock (networkClients)
                {
                    foreach (var tmpClient in networkClients)
                    {
                        if (pinnedNodes.Contains(tmpClient.getFullAddress(true)))
                        {
                            continue;
                        }
                        client = tmpClient;
                        break;
                    }
                }
                if (client != null)
                {
                    CoreProtocolMessage.sendBye(client, ProtocolByeCode.bye, "Disconnected for shuffling purposes.", "", false);
                }
            }

            // Connect randomly to a new node. Currently a 1% chance to reconnect during this iteration
            if (Random.Shared.Next(100) == 1)
            {
                connectToRandomNeighbor();
            }
        }

        protected abstract void connectToRandomNeighbor();


        // Starts the Network Client Manager in debug mode with a single connection and no reconnect. Used for development only.
        public bool startWithSingleConnection(string address)
        {
            lock (networkClients)
            {
                if (ctsLoop != null)
                {
                    return false;
                }

                ctsLoop = new CancellationTokenSource();

                networkClients.Clear();
                connectingClients.Clear();

                return connectTo(address, null).Result != null;
            }
        }

        public void stop()
        {
            lock (networkClients)
            {
                if (ctsLoop == null)
                {
                    return;
                }

                autoReconnect = false;
                ctsLoop.Cancel();
                wakeSignal.TrySetResult();
            }
            isolate();

            try
            {
                // Wait for reconnect loop to finish
                reconnectTask?.GetAwaiter().GetResult();
            }
            catch (OperationCanceledException) { }
            finally
            {
                ctsLoop.Dispose();
                ctsLoop = null;
                reconnectTask = null;
            }
        }

        public void pause()
        {
            paused = true;
            isolate();
        }

        public void resume()
        {
            paused = false;
        }

        // Immediately disconnects all clients
        public void isolate()
        {
            Logging.info("Isolating network clients...");

            lock (networkClients)
            {
                // Disconnect each client
                foreach (NetworkClient client in networkClients)
                {
                    client.stopAsync();
                }

                // Empty the client list
                networkClients.Clear();
                connectingClients.Clear();
            }
            lock (connectingClients)
            {
                connectingClients.Clear();
            }
        }

        // Reconnects to network clients
        public void restartClients()
        {
            Logging.info("Stopping network clients...");
            stop();
            Thread.Sleep(2000);
            Logging.info("Starting network clients...");
            start();
        }

        // Connects to a specified node, with the syntax host:port
        public async Task<NetworkClient?> connectTo(string host, Address wallet_address)
        {
            if (host.Length < 3)
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

            if (NetworkServer.isRunning())
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

                // Add the client to the connecting clients list
                connectingClients.Add(resolved_host);
            }

            // Check if node is already in the client list
            lock (networkClients)
            {
                foreach (NetworkClient client in networkClients)
                {
                    if (client.getFullAddress(true).Equals(resolved_host, StringComparison.Ordinal))
                    {
                        // Address is already in the client list
                        return null;
                    }
                }
            }

            // Check if node is already in the server list
            string[] connectedClients = NetworkServer.getConnectedClients(true);
            for (int i = 0; i < connectedClients.Length; i++)
            {
                if (connectedClients[i].Equals(resolved_host, StringComparison.Ordinal))
                {
                    // Address is already in the client list
                    return null;
                }
            }

            // Connect to the specified node
            NetworkClient? new_client = new NetworkClient(bindAddress);
            // Recompose the connection address from the resolved IP and the original port
            bool result = await new_client.connectToServer(resolved_server_name, Convert.ToInt32(server[1]), wallet_address).ConfigureAwait(false);

            // Add this node to the client list if connection was successfull
            if (result == true)
            {
                // Add this node to the client list
                lock (networkClients)
                {
                    networkClients.Add(new_client);
                }
            }
            else
            {
                new_client = null;
            }

            // Remove this node from the connecting clients list
            lock (connectingClients)
            {
                connectingClients.Remove(resolved_host);
            }

            return new_client;
        }

        // Send data to all connected nodes
        // Returns true if the data was sent to at least one client
        public bool broadcastData(char[] types, ProtocolMessageCode code, byte[] data, RemoteEndpoint? skipEndpoint = null)
        {
            bool result = false;
            QueueMessage queue_message = RemoteEndpoint.getQueueMessage(code, data);
            lock (networkClients)
            {
                foreach (NetworkClient client in networkClients)
                {
                    if (skipEndpoint != null)
                    {
                        if (client == skipEndpoint)
                            continue;
                    }

                    if (!client.isConnected())
                    {
                        continue;
                    }

                    if (client.helloReceived == false)
                    {
                        continue;
                    }

                    if (types != null)
                    {
                        if (client.presenceAddress == null || !types.Contains(client.presenceAddress.type))
                        {
                            continue;
                        }
                    }


                    client.sendData(queue_message);
                    result = true;
                }
            }
            return result;
        }

        public NetworkClient? getClient(Address clientAddress, bool fullyConnected = true)
        {
            lock (networkClients)
            {
                foreach (NetworkClient c in networkClients)
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

        public bool sendToClient(Address neighbor, ProtocolMessageCode code, byte[] data)
        {
            NetworkClient? client = getClient(neighbor, true);

            if (client != null)
            {
                client.sendData(code, data);
                return true;
            }

            return false;
        }

        public bool sendToClient(string neighbor, ProtocolMessageCode code, byte[] data)
        {
            NetworkClient? client = null;
            lock (networkClients)
            {
                foreach (NetworkClient c in networkClients)
                {
                    if (c.getFullAddress() == neighbor)
                    {
                        client = c;
                        break;
                    }
                }
            }

            if (client != null)
            {
                client.sendData(code, data);
                return true;
            }

            return false;
        }

        // Returns all the connected clients
        public string[] getConnectedClients(bool only_fully_connected = false)
        {
            List<string> result = new List<string>();

            lock (networkClients)
            {
                foreach (NetworkClient client in networkClients)
                {
                    if (client.isConnected())
                    {
                        if (only_fully_connected && !client.helloReceived)
                        {
                            continue;
                        }

                        try
                        {
                            string client_name = client.getFullAddress();
                            result.Add(client_name);
                        }
                        catch (Exception e)
                        {
                            Logging.error("NetworkClientManager->getConnectedClients: {0}", e);
                        }
                    }
                }
            }

            return result.ToArray();
        }


        // Returns all the connected clients
        public List<Address> getRandomConnectedClientAddresses(int addressCount)
        {
            List<Address> addresses = new List<Address>();
            lock (networkClients)
            {
                foreach (NetworkClient client in networkClients)
                {
                    if (client.isConnected())
                    {
                        if (!client.helloReceived)
                        {
                            continue;
                        }

                        try
                        {
                            string client_name = client.getFullAddress();
                            addresses.Add(client.serverWalletAddress);
                            if (addresses.Count >= addressCount)
                            {
                                break;
                            }
                        }
                        catch (Exception e)
                        {
                            Logging.error("NetworkClientManager->getRandomConnectedClientAddress: {0}", e);
                        }
                    }
                }
            }

            return addresses;
        }

        /// <summary>
        ///  Recalculates local time difference depending on 2/3rd of connected servers time differences.
        ///  Maximum time difference is enforced with CoreConfig.maxTimeDifferenceAdjustment.
        ///  If CoreConfig.forceTimeOffset is used, both Clock.networkTimeDifference and
        ///  Clock.realNetworkTimeDifference will be forced to the value of CoreConfig.forceTimeOffset.
        /// </summary>
        public void recalculateLocalTimeDifference()
        {
            lock (networkClients)
            {
                if (PresenceList.myPresenceType == 'M' || PresenceList.myPresenceType == 'H')
                {
                    if (networkClients.Count < 3)
                        return;
                }
                else
                {
                    if (networkClients.Count < 1)
                        return;
                }

                long total_time_diff = 0;

                List<long> time_diffs = new List<long>();

                foreach (NetworkClient client in networkClients)
                {
                    if (client.helloReceived && client.timeSyncComplete)
                    {
                        time_diffs.Add(client.timeDifference);
                    }
                }

                time_diffs.Sort();

                int third_time_diff = time_diffs.Count / 3;

                var time_diffs_majority = time_diffs.Skip(third_time_diff).Take(third_time_diff);

                if (time_diffs_majority.Count() < 1)
                {
                    return;
                }

                foreach (long time in time_diffs_majority)
                {
                    total_time_diff += time;
                }

                long timeDiff = total_time_diff / time_diffs_majority.Count();

                Clock.realNetworkTimeDifference = timeDiff;

                if (PresenceList.myPresenceType == 'M' || PresenceList.myPresenceType == 'H')
                {
                    // if Master/full History node, do time adjustment within max time difference
                    if (timeDiff > CoreConfig.maxTimeDifferenceAdjustment)
                    {
                        Clock.networkTimeDifference = CoreConfig.maxTimeDifferenceAdjustment;
                    }
                    else if (timeDiff < -CoreConfig.maxTimeDifferenceAdjustment)
                    {
                        Clock.networkTimeDifference = -CoreConfig.maxTimeDifferenceAdjustment;
                    }
                    else
                    {
                        Clock.networkTimeDifference = timeDiff;
                    }
                }
                else
                {
                    // If non-Master/full History node adjust time to network time
                    Clock.networkTimeDifference = timeDiff;
                }
            }
        }

        protected void handleDisconnectedClients()
        {
            List<NetworkClient> netClients;
            lock (networkClients)
            {
                netClients = new List<NetworkClient>(networkClients);
            }

            // Prepare a list of failed clients
            List<NetworkClient> failed_clients = new List<NetworkClient>();

            List<NetworkClient> dup_clients = new List<NetworkClient>();
            List<Task> client_tasks = new();
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
                else if (client.getTotalReconnectsCount() >= CoreConfig.maximumNeighborReconnectCount)
                {
                    // Remove this client so we can search for a new neighbor
                    failed_clients.Add(client);
                    PeerStorage.decreaseRating(client.getFullAddress(true), 1);
                }
                else
                {
                    // Reconnect
                    client_tasks.Add(client.reconnect());
                }
            }

            Task.WhenAll(client_tasks).Wait();

            // Go through the list of failed clients and remove them
            foreach (NetworkClient client in failed_clients)
            {
                client.stopAsync().Wait();
                lock (networkClients)
                {
                    networkClients.Remove(client);
                }
                // Remove this node from the connecting clients list
                lock (connectingClients)
                {
                    connectingClients.Remove(client.getFullAddress(true));
                }
            }
        }


        public int getQueuedMessageCount()
        {
            int messageCount = 0;
            lock (networkClients)
            {
                foreach (NetworkClient client in networkClients)
                {
                    messageCount += client.getQueuedMessageCount();
                }
            }
            return messageCount;
        }

        public string? getMyAddress()
        {
            lock (networkClients)
            {
                Dictionary<string, int> addresses = new Dictionary<string, int>();
                foreach (NetworkClient client in networkClients)
                {
                    if (client.myAddress == "" || client.myAddress == null)
                    {
                        continue;
                    }
                    if (!client.myAddress.Contains(":"))
                    {
                        continue;
                    }

                    string ip_address = client.myAddress.Substring(0, client.myAddress.IndexOf(":"));

                    if (!NetworkUtils.validateIP(ip_address))
                    {
                        continue;
                    }
                    if (addresses.ContainsKey(ip_address))
                    {
                        addresses[ip_address]++;
                    }
                    else
                    {
                        addresses.Add(ip_address, 1);
                    }
                }
                if (addresses.Count > 0)
                {
                    var address = addresses.OrderByDescending(x => x.Value).First();
                    if (address.Value > 1)
                    {
                        return address.Key;
                    }
                }
                return null;
            }
        }

        public bool addToInventory(char[] types, InventoryItem item, RemoteEndpoint? skip_endpoint)
        {
            lock (networkClients)
            {
                foreach (var client in networkClients)
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
                        if (!types.Contains(client.presenceAddress.type))
                        {
                            continue;
                        }
                        client.addInventoryItem(item);
                    }
                    catch (Exception e)
                    {
                        Logging.error("Exception occurred in NetworkClientManager.addToInventory: {0}", e);
                    }
                }
            }
            return true;
        }

        public List<ulong> getBlockHeights()
        {
            List<ulong> blockHeights = new List<ulong>();
            lock (networkClients)
            {
                foreach (var client in networkClients)
                {
                    if (client.blockHeight != 0)
                    {
                        blockHeights.Add(client.blockHeight);
                    }
                }
            }
            return blockHeights;
        }

        protected bool shouldConnectToPeer(Peer p)
        {
            string[] server = p.hostname.Split(':');

            if (server.Length < 2)
            {
                return false;
            }

            // Resolve the hostname first
            string resolved_server_name = NetworkUtils.resolveHostname(server[0]);
            string resolved_server_name_with_port = resolved_server_name + ":" + server[1];

            // Check if we are already connected to this address
            lock (networkClients)
            {
                foreach (NetworkClient client in networkClients)
                {
                    if (client.getFullAddress(true).Equals(resolved_server_name_with_port, StringComparison.Ordinal))
                    {
                        // Address is already in the client list
                        return false;
                    }
                }
            }

            // Check if node is already in the server list
            string[] connectedClients = NetworkServer.getConnectedClients(true);
            for (int i = 0; i < connectedClients.Length; i++)
            {
                if (connectedClients[i].Equals(resolved_server_name_with_port, StringComparison.Ordinal))
                {
                    // Address is already in the client list
                    return false;
                }
            }

            // Check against connecting clients list as well
            lock (connectingClients)
            {
                foreach (string client in connectingClients)
                {
                    if (resolved_server_name_with_port.Equals(client, StringComparison.Ordinal))
                    {
                        // Address is already in the connecting client list
                        return false;
                    }
                }

            }

            if (NetworkServer.isRunning())
            {
                // Get all self addresses and run through them
                List<string> self_addresses = NetworkUtils.GetAllLocalIPAddresses();
                foreach (string self_address in self_addresses)
                {
                    // Don't connect to self
                    if (resolved_server_name.Equals(self_address, StringComparison.Ordinal))
                    {
                        if (server[1].Equals(string.Format("{0}", IxianHandler.publicPort), StringComparison.Ordinal))
                        {
                            return false;
                        }
                    }
                }
            }

            return true;
        }

        public void wakeReconnectLoop()
        {
            wakeSignal.TrySetResult();
        }


        public void setPinnedNodes(List<string> pinnedNodes)
        {
            lock (networkClients)
            {
                if (this.pinnedNodes == null)
                {
                    this.pinnedNodes = new();
                    return;
                }

                this.pinnedNodes = pinnedNodes.ToHashSet();
            }
        }

        public bool isConnectedTo(string address, bool only_fully_connected = true)
        {
            lock (networkClients)
            {
                foreach (NetworkClient client in networkClients)
                {
                    if (client.getFullAddress(true).Equals(address, StringComparison.Ordinal))
                    {
                        if (only_fully_connected && (!client.isConnected() || !client.helloReceived))
                        {
                            break;
                        }
                        return true;
                    }
                }
            }

            return false;
        }


        public bool isConnectedTo(RemoteEndpoint endpoint)
        {
            lock (networkClients)
            {
                foreach (NetworkClient client in networkClients)
                {
                    if (client == endpoint)
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        public bool sendToClient(List<Peer> relayNodes, ProtocolMessageCode code, byte[] data, int client_count = 1)
        {
            List<NetworkClient> clients = new();
            lock (networkClients)
            {
                foreach (NetworkClient c in networkClients)
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
                    c.sendData(code, data);
                }
                return true;
            }

            return false;
        }
    }
}

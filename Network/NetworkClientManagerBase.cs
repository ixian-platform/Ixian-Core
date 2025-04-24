// Copyright (C) 2017-2025 Ixian OU
// This file is part of Ixian Core - www.github.com/ProjectIxian/Ixian-Core
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
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace IXICore.Network
{
    public abstract class NetworkClientManagerBase
    {
        public List<NetworkClient> networkClients { get; private set; } = new List<NetworkClient>();
        protected List<string> connectingClients = new List<string>(); // A list of clients that we're currently connecting

        protected Thread reconnectThread;
        protected bool autoReconnect = true;

        protected bool running = false;
        protected ThreadLiveCheck TLC;

        protected bool paused = false;

        private Random rnd = new Random();

        private int simultaneousConnectedNeighbors;

        public NetworkClientManagerBase(int simultaneousConnectedNeighbors)
        {
            this.simultaneousConnectedNeighbors = simultaneousConnectedNeighbors;
        }

        // Starts the Network Client Manager.
        // If connections_to_wait_for parameter is bigger than 0, it waits until it connects to the specified number of nodes.
        // Afterwards, it starts the reconnect and keepalive threads
        public void start(int connections_to_wait_for = 0)
        {
            if (running)
            {
                return;
            }

            if (CoreConfig.preventNetworkOperations)
            {
                Logging.warn("Not starting NetworkClientManager thread due to preventNetworkOperations flag being set.");
                return;
            }

            running = true;
            networkClients = new List<NetworkClient>();
            connectingClients = new List<string>();

            if (connections_to_wait_for > 0)
            {
                Random rnd = new Random();
                // Connect to a random node first
                int i = 0;
                while (getConnectedClients(true).Count() < connections_to_wait_for && IxianHandler.forceShutdown == false)
                {
                    new Thread(() =>
                    {
                        reconnectClients();
                    }).Start();
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
                    if (!running)
                    {
                        return;
                    }
                }
            }

            // Start the reconnect thread
            TLC = new ThreadLiveCheck();

            autoReconnect = true;
            reconnectThread = new Thread(reconnectLoop);
            reconnectThread.Name = "Network_Client_Manager_Reconnect";
            reconnectThread.Start();
        }

        private void reconnectLoop()
        {
            try
            {
                while (autoReconnect)
                {
                    if (!paused)
                    {
                        TLC.Report();

                        try
                        {
                            handleDisconnectedClients();
                            reconnectClients();
                        }
                        catch (ThreadAbortException)
                        {
                            break;
                        }
                        catch (Exception e)
                        {
                            Logging.error("Fatal exception occurred in NetworkClientManager.reconnectClients: {0}", e);
                        }
                    }

                    // Wait 5 seconds before rechecking
                    Thread.Sleep(CoreConfig.networkClientReconnectInterval);
                }
            }
            catch (ThreadInterruptedException)
            {

            }
            catch (Exception e)
            {
                Logging.error("ReconnectLoop exception: {0}", e);
            }
        }

        // Checks for missing clients
        protected void reconnectClients()
        {
            if (simultaneousConnectedNeighbors < 4)
            {
                Logging.error("Setting simultanousConnectedNeighbors should be at least 4.");
                IxianHandler.shutdown();
                throw new Exception("Setting simultanousConnectedNeighbors should be at least 4.");
            }

            // Check if we need to connect to more neighbors
            if (getConnectedClients().Count() < simultaneousConnectedNeighbors)
            {
                // Scan for and connect to a new neighbor
                connectToRandomNeighbor();
                return;
            }
            else if (getConnectedClients(true).Count() > simultaneousConnectedNeighbors)
            {
                NetworkClient client;
                lock (networkClients)
                {
                    client = networkClients[0];
                    networkClients.RemoveAt(0);
                }
                CoreProtocolMessage.sendBye(client, ProtocolByeCode.bye, "Disconnected for shuffling purposes.", "", false);
                client.stop();
            }

            // Connect randomly to a new node. Currently a 1% chance to reconnect during this iteration
            if (rnd.Next(100) == 1)
            {
                connectToRandomNeighbor();
            }
        }

        protected abstract void connectToRandomNeighbor();


        // Starts the Network Client Manager in debug mode with a single connection and no reconnect. Used for development only.
        public bool startWithSingleConnection(string address)
        {
            if (running)
            {
                return false;
            }
            running = true;
            networkClients = new List<NetworkClient>();
            connectingClients = new List<string>();

            bool result = connectTo(address, null);
            if (!result)
            {
                running = false;
            }

            return result;
        }

        public void stop()
        {
            if (!running)
            {
                return;
            }
            running = false;
            autoReconnect = false;
            isolate();

            // Force stopping of reconnect thread
            if (reconnectThread == null)
                return;
            reconnectThread.Interrupt();
            reconnectThread.Join();
            reconnectThread = null;
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
                    client.stop();
                }

                // Empty the client list
                networkClients.Clear();
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
        public bool connectTo(string host, Address wallet_address)
        {
            if (host == null || host.Length < 3)
            {
                Logging.error("Invalid host address {0}", host);
                return false;
            }

            string[] server = host.Split(':');
            if (server.Count() < 2)
            {
                Logging.warn("Cannot connect to invalid hostname: {0}", host);
                return false;
            }

            // Resolve the hostname first
            string resolved_server_name = NetworkUtils.resolveHostname(server[0]);

            // Skip hostnames we can't resolve
            if (resolved_server_name.Length < 1)
            {
                Logging.warn("Cannot resolve IP for {0}, skipping connection.", server[0]);
                return false;
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
                        return false;
                    }
                }

                // Get all self addresses and run through them
                List<string> self_addresses = CoreNetworkUtils.GetAllLocalIPAddresses();
                foreach (string self_address in self_addresses)
                {
                    // Don't connect to self
                    if (resolved_server_name.Equals(self_address, StringComparison.Ordinal))
                    {
                        if (server[1].Equals(string.Format("{0}", IxianHandler.publicPort), StringComparison.Ordinal))
                        {
                            Logging.info("Skipping connection to self seed node {0}", host);
                            return false;
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
                        return false;
                    }
                }

                // The the client to the connecting clients list
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
                        return false;
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
                    return false;
                }
            }

            // Connect to the specified node
            NetworkClient new_client = new NetworkClient();
            // Recompose the connection address from the resolved IP and the original port
            bool result = new_client.connectToServer(resolved_server_name, Convert.ToInt32(server[1]), wallet_address);

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
                new_client.stop();
            }

            // Remove this node from the connecting clients list
            lock (connectingClients)
            {
                connectingClients.Remove(resolved_host);
            }

            return result;
        }

        // Send data to all connected nodes
        // Returns true if the data was sent to at least one client
        public bool broadcastData(char[] types, ProtocolMessageCode code, byte[] data, byte[] helper_data, RemoteEndpoint skipEndpoint = null)
        {
            bool result = false;
            QueueMessage queue_message = RemoteEndpoint.getQueueMessage(code, data, helper_data);
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

        public bool sendToClient(Address neighbor, ProtocolMessageCode code, byte[] data, byte[] helper_data)
        {
            NetworkClient client = null;
            lock (networkClients)
            {
                foreach (NetworkClient c in networkClients)
                {
                    if (c.serverWalletAddress.SequenceEqual(neighbor))
                    {
                        client = c;
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

        public bool sendToClient(string neighbor, ProtocolMessageCode code, byte[] data, byte[] helper_data)
        {
            NetworkClient client = null;
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
                client.sendData(code, data, helper_data);
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
            List<NetworkClient> netClients = null;
            lock (networkClients)
            {
                netClients = new List<NetworkClient>(networkClients);
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
                if (client.getTotalReconnectsCount() >= CoreConfig.maximumNeighborReconnectCount || client.fullyStopped)
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

        public NetworkClient getClient(int idx)
        {
            lock (networkClients)
            {
                int i = 0;
                NetworkClient lastClient = null;
                foreach (NetworkClient client in networkClients)
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

        public string getMyAddress()
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

        public bool addToInventory(char[] types, InventoryItem item, RemoteEndpoint skip_endpoint)
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
                List<string> self_addresses = CoreNetworkUtils.GetAllLocalIPAddresses();
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
    }
}

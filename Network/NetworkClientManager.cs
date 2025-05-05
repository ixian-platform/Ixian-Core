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
using System;
using System.Collections.Generic;

namespace IXICore.Network
{
    public class NetworkClientManager
    {
        public static List<NetworkClient> networkClients { get; private set; } = null;
        public static NetworkClientManagerBase clientManagerBase;

        public static void init(NetworkClientManagerBase clientManagerBase)
        {
            if (NetworkClientManager.clientManagerBase != null)
            {
                throw new Exception("NetworkClientManager already initialized.");
            }

            PeerStorage.readPeersFile();

            // Now add the seed nodes to the list
            foreach (string[] addr in CoreNetworkUtils.getSeedNodes(IxianHandler.networkType))
            {
                Address wallet_addr = null;
                if (addr[1] != null)
                {
                    wallet_addr = new Address(Base58Check.Base58CheckEncoding.DecodePlain(addr[1]));
                }
                PeerStorage.addPeerToPeerList(addr[0], wallet_addr, Clock.getTimestamp(), 0, 1, 0, false);
            }

            NetworkClientManager.clientManagerBase = clientManagerBase;
            networkClients = clientManagerBase.networkClients;
        }

        // Starts the Network Client Manager.
        // If connections_to_wait_for parameter is bigger than 0, it waits until it connects to the specified number of nodes.
        // Afterwards, it starts the reconnect and keepalive threads
        public static void start(int connections_to_wait_for = 0)
        {
            clientManagerBase.start(connections_to_wait_for);
        }

        // Starts the Network Client Manager in debug mode with a single connection and no reconnect. Used for development only.
        public static bool startWithSingleConnection(string address)
        {
            return clientManagerBase.startWithSingleConnection(address);
        }

        public static void stop()
        {
            clientManagerBase.stop();
        }

        public static void pause()
        {
            clientManagerBase.pause();
        }

        public static void resume()
        {
            clientManagerBase.resume();
        }

        // Immediately disconnects all clients
        public static void isolate()
        {
            clientManagerBase.isolate();
        }

        // Reconnects to network clients
        public static void restartClients()
        {
            clientManagerBase.restartClients();
        }

        // Connects to a specified node, with the syntax host:port
        public static bool connectTo(string host, Address wallet_address)
        {
            return clientManagerBase.connectTo(host, wallet_address);
        }

        // Send data to all connected nodes
        // Returns true if the data was sent to at least one client
        public static bool broadcastData(char[] types, ProtocolMessageCode code, byte[] data, byte[] helper_data, RemoteEndpoint skipEndpoint = null)
        {
            return clientManagerBase.broadcastData(types, code, data, helper_data, skipEndpoint);
        }

        public static bool sendToClient(Address neighbor, ProtocolMessageCode code, byte[] data, byte[] helper_data)
        {
            return clientManagerBase.sendToClient(neighbor, code, data, helper_data);
        }

        public static bool sendToClient(string neighbor, ProtocolMessageCode code, byte[] data, byte[] helper_data)
        {
            return clientManagerBase.sendToClient(neighbor, code, data, helper_data);
        }

        // Returns all the connected clients
        public static string[] getConnectedClients(bool only_fully_connected = false)
        {
            return clientManagerBase.getConnectedClients(only_fully_connected);
        }

        public static List<Address> getRandomConnectedClientAddresses(int addressCount)
        {
            return clientManagerBase.getRandomConnectedClientAddresses(addressCount);
        }


        /// <summary>
        ///  Recalculates local time difference depending on 2/3rd of connected servers time differences.
        ///  Maximum time difference is enforced with CoreConfig.maxTimeDifferenceAdjustment.
        ///  If CoreConfig.forceTimeOffset is used, both Clock.networkTimeDifference and
        ///  Clock.realNetworkTimeDifference will be forced to the value of CoreConfig.forceTimeOffset.
        /// </summary>
        public static void recalculateLocalTimeDifference()
        {
            clientManagerBase.recalculateLocalTimeDifference();
        }

        public static int getQueuedMessageCount()
        {
            return clientManagerBase.getQueuedMessageCount();
        }


        public static bool addToInventory(char[] types, InventoryItem item, RemoteEndpoint skip_endpoint)
        {
            return clientManagerBase.addToInventory(types, item, skip_endpoint);
        }

        public static List<ulong> getBlockHeights()
        {
            return clientManagerBase.getBlockHeights();
        }

        public static RemoteEndpoint getClient(Address clientAddress)
        {
            return clientManagerBase.getClient(clientAddress);
        }
    }
}

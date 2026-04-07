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

using System.Collections.Generic;
using System.Threading.Tasks;

namespace IXICore.Network
{
    static class StreamClientManager
    {
        public static string primaryS2Address
        {
            get
            {
                return streamClientManager != null ? streamClientManager.primaryS2Address : "";
            }
            set
            {
                streamClientManager?.primaryS2Address = value;
            }
        }

        private static NetworkClientManagerStream? streamClientManager = null;

        public static void init(int simultaneousConnectedNeighbors, bool connectToRandomStreamNodes, string? bindAddress = null)
        {
            if (streamClientManager != null)
            {
                return;
            }
            streamClientManager = new NetworkClientManagerStream(simultaneousConnectedNeighbors, connectToRandomStreamNodes, bindAddress);
        }


        public static void start()
        {
            streamClientManager.start();
        }

        public static void stop()
        {
            if (streamClientManager == null)
            {
                return;
            }

            streamClientManager.stop();
        }

        public static void setPinnedNodes(List<string> pinnedNodes)
        {
            streamClientManager.setPinnedNodes(pinnedNodes);
        }

        public static void pause()
        {
            streamClientManager.pause();
        }

        public static void resume()
        {
            streamClientManager.resume();
        }

        // Immediately disconnects all clients
        public static void isolate()
        {
            streamClientManager.isolate();
        }

        public static void restartClients()
        {
            streamClientManager.restartClients();
        }

        // Send data to all connected nodes
        // Returns true if the data was sent to at least one client
        public static bool broadcastData(ProtocolMessageCode code, byte[] data, RemoteEndpoint? skipEndpoint = null)
        {
            return streamClientManager.broadcastData(new[] { 'R' }, code, data, skipEndpoint);
        }

        // Connects to a specified node, with the syntax host:port
        // Returns the connected stream client
        // Returns null if connection failed
        public static async Task<NetworkClient?> connectTo(string host, Address wallet_address)
        {
            return await streamClientManager.connectTo(host, wallet_address).ConfigureAwait(false);
        }

        // Check if we're connected to a certain host address
        // Returns StreamClient or null if not found
        public static bool isConnectedTo(string address, bool only_fully_connected = true)
        {
            return streamClientManager.isConnectedTo(address, only_fully_connected);
        }

        public static bool isConnectedTo(RemoteEndpoint endpoint)
        {
            return streamClientManager.isConnectedTo(endpoint);
        }

        // Returns all the connected clients
        public static string[] getConnectedClients(bool only_fully_connected = false)
        {
            return streamClientManager.getConnectedClients(only_fully_connected);
        }

        public static NetworkClient? getClient(Address clientAddress, bool fullyConnected = true)
        {
            return getClient(clientAddress, fullyConnected);
        }

        public static bool sendToClient(List<Peer> relayNodes, ProtocolMessageCode code, byte[] data, int client_count = 1)
        {
            return streamClientManager.sendToClient(relayNodes, code, data, client_count);
        }

        public static bool sendToClient(Address neighbor, ProtocolMessageCode code, byte[] data)
        {
            return streamClientManager.sendToClient(neighbor, code, data);
        }

        public static void wakeReconnectLoop()
        {
            streamClientManager.wakeReconnectLoop();
        }
    }
}

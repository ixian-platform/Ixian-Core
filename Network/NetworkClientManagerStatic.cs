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

using IXICore.Meta;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace IXICore.Network
{
    public class NetworkClientManagerStatic : NetworkClientManagerBase
    {
        List<Peer> clientsToConnectTo = new();

        public NetworkClientManagerStatic(int simultaneousConnectedNeighbors) : base(simultaneousConnectedNeighbors)
        {
        }

        public void setClientsToConnectTo(List<Peer> newClientsToConnectTo)
        {
            clientsToConnectTo = newClientsToConnectTo;
            disconnectFromOldClients();
        }

        private void disconnectFromOldClients()
        {
            lock (networkClients)
            {
                List<NetworkClient> safeNetworkClients = new(networkClients);
                foreach (var nc in safeNetworkClients)
                {
                    if (!nc.isConnected()
                        || nc.helloReceived == false)
                    {
                        continue;
                    
                    }

                    if (nc.serverWalletAddress == null)
                    {
                        continue;
                    }

                    if (clientsToConnectTo.FindIndex(x => x.walletAddress != null && x.walletAddress.SequenceEqual(nc.serverWalletAddress)) == -1)
                    {
                        networkClients.Remove(nc);
                        CoreProtocolMessage.sendBye(nc, ProtocolByeCode.bye, "Disconnected for shuffling purposes.", "", false);
                        nc.stop();
                    }
                }
            }
        }

        // Returns a random new potential neighbor. Returns null if no new neighbor is found.
        private Peer scanForNeighbor()
        {
            if (getConnectedClients(true).Count() == 0)
            {
                PeerStorage.resetInitialConnectionCount();
            }

            // Find only masternodes
            foreach (var p in clientsToConnectTo)
            {
                // If the address is valid, add it to the candidates
                if (shouldConnectToPeer(p))
                {
                    return p;
                }

                Thread.Sleep(10);
            }

            return null;
        }

        // Scan for and connect to a new neighbor
        protected override void connectToRandomNeighbor()
        {
            disconnectFromOldClients();
            Peer neighbor = scanForNeighbor();
            if (neighbor != null)
            {
                Logging.info("Attempting to add new neighbor: {0}", neighbor.hostname);
                connectTo(neighbor.hostname, neighbor.walletAddress);
            }
        }
    }
}

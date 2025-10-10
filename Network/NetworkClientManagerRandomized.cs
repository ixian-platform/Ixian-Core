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
using System.Linq;
using System.Threading;

namespace IXICore.Network
{
    public class NetworkClientManagerRandomized : NetworkClientManagerBase
    {
        public NetworkClientManagerRandomized(int simultaneousConnectedNeighbors, string bindAddress = null) : base(simultaneousConnectedNeighbors, bindAddress)
        {
        }

        // Returns a random new potential neighbor. Returns null if no new neighbor is found.
        private Peer scanForNeighbor()
        {
            Peer connectToPeer = null;
            // Find only masternodes
            while (connectToPeer == null)
            {
                Thread.Sleep(10);

                if (getConnectedClients(true).Count() == 0)
                {
                    PeerStorage.resetInitialConnectionCount();
                }
                Peer p = PeerStorage.getRandomMasterNodeAddress();

                if (p == null)
                {
                    break;
                }

                // If the address is valid, add it to the candidates
                if (shouldConnectToPeer(p))
                {
                    connectToPeer = p;
                }
            }

            return connectToPeer;
        }

        // Scan for and connect to a new neighbor
        protected override void connectToRandomNeighbor()
        {
            Peer neighbor = scanForNeighbor();
            if (neighbor != null)
            {
                Logging.info("Attempting to add new neighbor: {0}", neighbor.hostname);
                connectTo(neighbor.hostname, neighbor.walletAddress);
            }
        }
    }
}

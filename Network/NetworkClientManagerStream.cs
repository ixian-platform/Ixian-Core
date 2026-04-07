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

using IXICore.Meta;
using System;
using System.Collections.Generic;

namespace IXICore.Network
{
    public class NetworkClientManagerStream : NetworkClientManagerBase
    {
        public string primaryS2Address = "";
        private bool connectToRandomStreamNodes;
        public NetworkClientManagerStream(int simultaneousConnectedNeighbors, bool connectToRandomStreamNodes, string? bindAddress = null) : base(simultaneousConnectedNeighbors, bindAddress)
        {
            this.connectToRandomStreamNodes = connectToRandomStreamNodes;
        }

        // Returns a random new potential neighbor. Returns null if no new neighbor is found.
        private void connectToRandomStreamNode()
        {
            string? neighbor = null;
            Address? neighborAddress = null;

            try
            {
                List<Presence> presences = PresenceList.getPresencesByType('R', CoreConfig.maxRelaySectorNodesToRequest);
                if (presences.Count > 0)
                {
                    List<Presence> tmp_presences = presences.FindAll(x => x.addresses.Find(y => y.type == 'R') != null); // TODO tmp_presences can be removed after protocol is finalized

                    Presence p = tmp_presences[Random.Shared.Next(tmp_presences.Count)];
                    lock (p)
                    {
                        neighbor = p.addresses.Find(x => x.type == 'R')?.address;
                        neighborAddress = p.wallet;
                    }
                }
            }
            catch (Exception e)
            {
                Logging.error("Exception looking up random stream node: " + e);
                return;
            }

            if (neighbor != null)
            {
                Logging.info("Attempting to add new stream node: {0}", neighbor);
                connectTo(neighbor, neighborAddress).Wait();
            }
            else
            {
                Logging.error("Failed to add random stream node.");
            }
        }

        // Scan for and connect to a new neighbor
        protected override void connectToRandomNeighbor()
        {
            string[] netClients = getConnectedClients();

            // Check if we need to connect to more neighbors
            if (connectToRandomStreamNodes)
            {
                if (netClients.Length < 1
                    || !isConnectedTo(primaryS2Address))
                {
                    connectToRandomStreamNode();
                }
            }
        }
    }
}

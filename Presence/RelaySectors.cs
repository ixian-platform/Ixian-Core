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

using IXICore.Utils;
using System;
using System.Collections.Generic;

namespace IXICore
{
    public class RelaySectors
    {
        public static RelaySectors Instance { get; private set; }

        private PrefixIndexedTree<byte[]> relayNodes;
        private byte[] randomizer;

        private RelaySectors(int maxLevels, byte[] randomizer)
        {
            relayNodes = new(maxLevels);
            this.randomizer = randomizer;
        }

        public static void init(int maxLevels, byte[] randomizer)
        {
            Instance = new RelaySectors(maxLevels, randomizer);
        }

        public void setRandomizer(byte[] blockHash)
        {
            randomizer = blockHash;
            relayNodes.Clear();
        }

        private byte[] getRandomizedAddress(Address relayNodeAddress)
        {
            var tmpRandomizer = randomizer;
            if (tmpRandomizer == null)
            {
                tmpRandomizer = new byte[0];
            }
            
            byte[] preimage = new byte[tmpRandomizer.Length + relayNodeAddress.addressNoChecksum.Length];
            Buffer.BlockCopy(tmpRandomizer, 0, preimage, 0, tmpRandomizer.Length);
            Buffer.BlockCopy(relayNodeAddress.addressNoChecksum, 0, preimage, tmpRandomizer.Length, relayNodeAddress.addressNoChecksum.Length);

            return CryptoManager.lib.sha3_512(preimage);
        }

        public bool addRelayNode(Address relayNodeAddress)
        {
            byte[] randomizedAddress = getRandomizedAddress(relayNodeAddress);
            return relayNodes.Add(randomizedAddress, relayNodeAddress.addressNoChecksum);
        }

        public bool removeRelayNode(Address relayNodeAddress)
        {
            byte[] randomizedAddress = getRandomizedAddress(relayNodeAddress);
            return relayNodes.Remove(randomizedAddress);
        }

        public List<Address> getSectorNodes(byte[] addressPrefix, int maxRelayNodeCount)
        {
            List<Address> sectorNodes = new List<Address>();
            var closestItems = relayNodes.GetClosestItems(addressPrefix, maxRelayNodeCount);
            foreach (var item in closestItems)
            {
                sectorNodes.Add(new Address(item.Value));
            }
            return sectorNodes;
        }

        public PrefixIndexedTreeNode<byte[]> debugDump()
        {
            return relayNodes.Root;
        }
    }
}

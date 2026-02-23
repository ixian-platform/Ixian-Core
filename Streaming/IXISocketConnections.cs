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
using IXICore.Utils;
using System;
using System.Collections.Generic;
using System.Linq;

namespace IXICore.Streaming
{
    public class IXISocketConnections
    {
        public static int maxIncomingConnections = 100;
        private static Dictionary<Address, Friend> _incomingConnections = new Dictionary<Address, Friend>(new AddressComparer());
        private static List<Friend> _pendingSectorRequests = new List<Friend>();

        public static Friend? GetIncomingConnection(Address walletAddress)
        {
            Friend? friend = _incomingConnections.GetValueOrDefault(walletAddress);
            friend?.lastSeenTime = Clock.getNetworkTimestamp();
            return friend;
        }

        public static void AddPendingSectorRequest(Friend friend)
        {
            lock (_pendingSectorRequests)
            {
                _pendingSectorRequests.Add(friend);
            }
        }

        public static bool RemovePendingSectorRequest(Friend friend)
        {
            lock (_pendingSectorRequests)
            {
                return _pendingSectorRequests.Remove(friend);
            }
        }

        public static List<Friend> GetPendingSectorRequestsBySectorPrefix(byte[] sectorPrefix)
        {
            lock (_pendingSectorRequests)
            {
                List<Friend> filtered = new();
                foreach (Friend friend in _pendingSectorRequests)
                {
                    if (friend.walletAddress.sectorPrefix.SequenceEqual(sectorPrefix))
                    {
                        filtered.Add(friend);
                    }
                }
                return filtered;
            }
        }

        public static Friend? AddIncomingConnection(Address walletAddress, byte[] publicKey)
        {
            Friend friend = new Friend(FriendType.Temporary, FriendState.RequestSent, walletAddress, publicKey, null, null, null, Clock.getNetworkTimestamp(), false);
            return AddConnection(friend);
        }

        private static void RemoveExpiredConnection()
        {
            lock (_incomingConnections)
            {
                List<Address> expiredConnections = new List<Address>();
                long currentTime = Clock.getNetworkTimestamp();
                foreach (var kvp in _incomingConnections)
                {
                    Friend friend = kvp.Value;
                    if (currentTime - friend.lastSeenTime > 60) // Expire connections with no activity longer than 60 seconds
                    {
                        expiredConnections.Add(kvp.Key);
                    }
                }
                foreach (Address address in expiredConnections)
                {
                    _incomingConnections.Remove(address);
                    Logging.trace("Removed expired IXI Socket connection from " + address.ToString());
                }
            }
        }

        private static Friend? AddConnection(Friend friend)
        {
            lock (_incomingConnections)
            {
                if (_incomingConnections.Count >= maxIncomingConnections)
                {
                    RemoveExpiredConnection();
                    if (_incomingConnections.Count >= maxIncomingConnections)
                    {
                        // Reached max connections
                        Logging.warn("Max incoming IXI Socket connections reached, rejecting new connection from " + friend.walletAddress.ToString());
                        return null;
                    }
                }

                if (_incomingConnections.ContainsKey(friend.walletAddress))
                {
                    // Already in the list
                    return null;
                }

                // Add new friend to the friendlist
                _incomingConnections.Add(friend.walletAddress, friend);
            }

            return friend;
        }

        public static void Clear()
        {
            lock (_incomingConnections)
            {
                _incomingConnections.Clear();
            }
        }

        public static bool RemoveConnection(Address address)
        {
            lock (_incomingConnections)
            {
                return _incomingConnections.Remove(address);
            }
        }
    }
}

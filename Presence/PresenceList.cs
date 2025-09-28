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
using IXICore.Network;
using IXICore.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace IXICore
{
    public class PresenceList
    {
        private static Dictionary<byte[], Presence> presences = new(new ByteArrayComparer()); // The presence list
        private static Dictionary<char, SortedDictionary<long, Dictionary<byte[], Presence>>> presenceIndexTypeExpiration = new() {
            { 'C', new() },
            { 'H', new() },
            { 'M', new() },
            { 'R', new() },
            { 'W', new() }
        };

        public static PresenceAddress curNodePresenceAddress { get; private set; } = null;
        public static Presence curNodePresence { get; private set; } = null;

        // private
        private static Dictionary<char, long> presenceCount = new Dictionary<char, long>() {
            { 'C', 0 },
            { 'H', 0 },
            { 'M', 0 },
            { 'R', 0 },
            { 'W', 0 }
        };

        private static Thread keepAliveThread;
        private static bool autoKeepalive = false;
        private static ThreadLiveCheck TLC;

        volatile public static bool forceSendKeepAlive = false;


        private static string _myPublicAddress = "";
        private static char _myPresenceType = 'C';

        private static bool running = false;

        private static int keepAliveInterval = CoreConfig.serverKeepAliveInterval;

        // Generate an initial presence list
        public static void init(string initial_ip, int port, char type, int keep_alive_interval)
        {
            Logging.info("Generating presence list.");

            _myPublicAddress = string.Format("{0}:{1}", initial_ip, port);
            _myPresenceType = type;

            // Initialize with the default presence state
            curNodePresenceAddress = new PresenceAddress(CoreConfig.device_id, _myPublicAddress, type, CoreConfig.productVersion, 0, null);
            curNodePresence = new Presence(IxianHandler.getWalletStorage().getPrimaryAddress(), IxianHandler.getWalletStorage().getPrimaryPublicKey(), null, curNodePresenceAddress);

            keepAliveInterval = keep_alive_interval;
        }

        // Update a presence entry. If the wallet address is not found, it creates a new entry in the Presence List.
        // If the wallet address is found in the presence list, it adds any new addresses from the specified presence.
        public static Presence updateEntry(Presence presence, bool return_presence_only_if_updated = false)
        {
            if (presence == null)
            {
                return null;
            }

            long currentTime = Clock.getNetworkTimestamp();

            lock (presences)
            {
                presences.TryGetValue(presence.wallet.addressNoChecksum, out Presence pr);
                if (pr != null)
                {
                    lock (pr)
                    {
                        Presence diffPresence = new Presence()
                        {
                            wallet = presence.wallet,
                            pubkey = presence.pubkey,
                            metadata = presence.metadata,
                            version = presence.version
                        };
                        // Go through all addresses and add any missing ones
                        foreach (PresenceAddress remotePA in presence.addresses)
                        {
                            if (remotePA.signature == null)
                            {
                                Logging.warn("Received presence with no signature: {1} / {2} / {3}", presence.wallet.ToString(), remotePA.address, Crypto.hashToString(remotePA.device));
                                continue;
                            }

                            long lTimestamp = remotePA.lastSeenTime;

                            int expiration_time = CoreConfig.serverPresenceExpiration;

                            if (remotePA.type == 'C')
                            {
                                expiration_time = CoreConfig.clientPresenceExpiration;
                            }

                            // Check for tampering. Includes a +300, -30 second synchronization zone
                            if ((currentTime - lTimestamp) > expiration_time)
                            {
                                Logging.warn("[PL] Received expired presence for {0} {1}. Skipping; {2} - {3}", pr.wallet.ToString(), remotePA.address, currentTime, lTimestamp);
                                continue;
                            }

                            if ((currentTime - lTimestamp) < -30)
                            {
                                Logging.warn("[PL] Potential presence tampering for {0} {1}. Skipping; {2} - {3}", pr.wallet.ToString(), remotePA.address, currentTime, lTimestamp);
                                continue;
                            }

                            PresenceAddress localPA = pr.addresses.Find(x => x.device.SequenceEqual(remotePA.device));
                            if (localPA != null)
                            {
                                int interval = CoreConfig.clientKeepAliveInterval;
                                if (remotePA.type == 'M' || remotePA.type == 'H')
                                {
                                    interval = CoreConfig.serverKeepAliveInterval;
                                }
                                else if (remotePA.type == 'R')
                                {
                                    interval = CoreConfig.relayKeepAliveInterval;
                                }

                                if (localPA.signature == null
                                    || localPA.lastSeenTime + interval < remotePA.lastSeenTime
                                    || (localPA.address != remotePA.address && localPA.lastSeenTime + 10 < remotePA.lastSeenTime))
                                {
                                    localPA.version = remotePA.version;
                                    localPA.address = remotePA.address;
                                    localPA.lastSeenTime = remotePA.lastSeenTime;
                                    localPA.signature = remotePA.signature;
                                    if (remotePA.powSolution != null)
                                    {
                                        localPA.powSolution = remotePA.powSolution;
                                    }
                                    if (localPA.type != remotePA.type)
                                    {
                                        presenceCount[localPA.type]--;
                                        presenceCount[remotePA.type]++;
                                        localPA.type = remotePA.type;
                                    }
                                    addPresenceIndex(localPA, presence);

                                    diffPresence.addresses.Add(remotePA);
                                }

                                if (localPA.type == 'M' || localPA.type == 'H')
                                {
                                    PeerStorage.addPeerToPeerList(localPA.address, presence.wallet, localPA.lastSeenTime, 0, 0, 0);
                                }

                                //Logging.info("[PL] Last time updated for {0}", addr.device);
                            }
                            else
                            {
                                // Add the address if it's not found
                                //Logging.info("[PL] Adding new address for {0}", presence.wallet);
                                pr.addresses.Add(remotePA);

                                if (remotePA.type == 'M' || remotePA.type == 'H')
                                {
                                    PeerStorage.addPeerToPeerList(remotePA.address, presence.wallet, remotePA.lastSeenTime, 0, 0, 0);
                                }

                                if (remotePA.type == 'R')
                                {
                                    RelaySectors.Instance.addRelayNode(pr.wallet);
                                }

                                presenceCount[remotePA.type]++;

                                addPresenceIndex(remotePA, presence);

                                diffPresence.addresses.Add(remotePA);
                            }
                        }

                        if (diffPresence.addresses.Count == 0 && return_presence_only_if_updated)
                        {
                            return null;
                        }
                        else
                        {
                            return diffPresence;
                        }
                    }
                }
                else
                {
                    // Insert a new entry
                    //Logging.info("[PL] Adding new entry for {0}", presence.wallet);

                    presences.Add(presence.wallet.addressNoChecksum, presence);

                    foreach (PresenceAddress pa in presence.addresses)
                    {
                        if (pa.type == 'M' || pa.type == 'H')
                        {
                            PeerStorage.addPeerToPeerList(pa.address, presence.wallet, pa.lastSeenTime, 0, 0, 0);
                        }

                        if (pa.type == 'R')
                        {
                            RelaySectors.Instance.addRelayNode(presence.wallet);
                        }

                        presenceCount[pa.type]++;

                        addPresenceIndex(pa, presence);
                    }

                    return presence;
                }
            }
        }

        private static bool removePresenceIndex(char type, long lastSeenTime, byte[] address)
        {
            if (!presenceIndexTypeExpiration.TryGetValue(type, out var sd))
            {
                return false;
            }

            if (!sd.TryGetValue(lastSeenTime, out var inner))
            {
                return false;
            }

            return inner.Remove(address);
        }

        private static void addPresenceIndex(PresenceAddress presenceAddress, Presence presence)
        {
            var sd = presenceIndexTypeExpiration[presenceAddress.type];
            if (!sd.TryGetValue(presenceAddress.lastSeenTime, out var inner))
            {
                inner = new Dictionary<byte[], Presence>(new ByteArrayComparer());
                sd.Add(presenceAddress.lastSeenTime, inner);
            }

            inner[presence.wallet.addressNoChecksum] = presence;
        }

        public static bool removeAddressEntry(Address wallet_address, PresenceAddress address = null, bool remove_presence_index_entry = true)
        {
            lock (presences)
            {
                presences.TryGetValue(wallet_address.addressNoChecksum, out Presence listEntry);

                // Check if there is such an entry in the presence list
                if (listEntry != null)
                {
                    lock (listEntry)
                    {
                        List<PresenceAddress> addresses_to_remove = null;

                        if (address != null)
                        {
                            addresses_to_remove = listEntry.addresses.FindAll(x => x == address);
                        }else
                        {
                            addresses_to_remove = new List<PresenceAddress>(listEntry.addresses);
                        }

                        foreach (var addr in addresses_to_remove)
                        {
                            presenceCount[addr.type]--;

                            listEntry.addresses.Remove(addr);
                            if (remove_presence_index_entry)
                            {
                                removePresenceIndex(addr.type, addr.lastSeenTime, wallet_address.addressNoChecksum);
                            }
                        }

                        int address_count = listEntry.addresses.Count;

                        if (address_count == 0)
                        {
                            // Remove it from the list
                            presences.Remove(listEntry.wallet.addressNoChecksum);
                        }

                        if (address != null && address.type == 'R')
                        {
                            if (listEntry.addresses.Find(x => x.type == 'R') == null)
                            {
                                RelaySectors.Instance.removeRelayNode(wallet_address);
                            }
                        }

                        return true;
                    }
                }
            }

            return false;
        }

        // Update a presence from a byte array
        public static Presence updateFromBytes(byte[] bytes, IxiNumber minDifficulty)
        {
            Presence presence = new Presence(bytes);

            if(presence.verify(minDifficulty))
            {
                return updateEntry(presence, true);
            }


            return null;
        }

        public static void startKeepAlive()
        {
            if (running)
            {
                return;
            }

            running = true;


            TLC = new ThreadLiveCheck();
            // Start the keepalive thread
            autoKeepalive = true;
            keepAliveThread = new Thread(keepAlive);
            keepAliveThread.Name = "Presence_List_Keep_Alive_Thread";
            keepAliveThread.Start();
        }

        public static void stopKeepAlive()
        {
            if (!running)
            {
                return;
            }

            running = false;

            autoKeepalive = false;
            if (keepAliveThread != null)
            {
                keepAliveThread.Interrupt();
                keepAliveThread.Join();
                keepAliveThread = null;
            }
        }

        public static KeepAlive generateKeepAlive(bool force_generate)
        {
            KeepAlive ka;
            if (force_generate
                || curNodePresenceAddress.lastSeenTime > Clock.getNetworkTimestamp() + 10
                || Clock.getNetworkTimestamp() - curNodePresenceAddress.lastSeenTime >= keepAliveInterval)
            {
                ka = new KeepAlive()
                {
                    deviceId = CoreConfig.device_id,
                    hostName = curNodePresenceAddress.address,
                    nodeType = curNodePresenceAddress.type,
                    timestamp = Clock.getNetworkTimestamp(),
                    walletAddress = IxianHandler.getWalletStorage().getPrimaryAddress(),
                    powSolution = curNodePresenceAddress.powSolution
                };
                ka.sign(IxianHandler.getWalletStorage().getPrimaryPrivateKey());

                curNodePresenceAddress.lastSeenTime = ka.timestamp;
                curNodePresenceAddress.signature = ka.signature;
            }
            else
            {
                ka = new KeepAlive()
                {
                    deviceId = CoreConfig.device_id,
                    hostName = curNodePresenceAddress.address,
                    nodeType = curNodePresenceAddress.type,
                    timestamp = curNodePresenceAddress.lastSeenTime,
                    walletAddress = IxianHandler.getWalletStorage().getPrimaryAddress(),
                    powSolution = curNodePresenceAddress.powSolution,
                    signature = curNodePresenceAddress.signature
                };
            }

            return ka;
        }

        // Sends perioding keepalive network messages
        private static void keepAlive()
        {
            try
            {
                forceSendKeepAlive = true;
                while (autoKeepalive)
                {
                    TLC.Report();

                    int keepalive_interval = keepAliveInterval;

                    // Wait x seconds before rechecking
                    for (int i = 0; i < keepalive_interval; i++)
                    {
                        if (autoKeepalive == false)
                        {
                            return;
                        }
                        if (IxianHandler.publicIP == "")
                        {
                            // do not send KA
                            i = 0;
                        }
                        else
                        {
                            if (forceSendKeepAlive)
                            {
                                Thread.Sleep(1000);
                                forceSendKeepAlive = false;
                                break;
                            }
                        }
                        // Sleep for one second
                        Thread.Sleep(1000);
                    }

                    if (curNodePresenceAddress.type == 'W')
                    {
                        continue; // no need to send PL for worker nodes
                    }

                    try
                    {
                        KeepAlive ka = generateKeepAlive(false);

                        byte[] ka_bytes = ka.getBytes();

                        Address address = null;
                        long last_seen = 0;
                        byte[] device_id = null;
                        char node_type;

                        // Update self presence
                        receiveKeepAlive(ka_bytes, out address, out last_seen, out device_id, out node_type, null);

                        if (node_type == 'C')
                        {
                            // Send this keepalive to all relay nodes
                            CoreProtocolMessage.broadcastProtocolMessage(['R'], ProtocolMessageCode.keepAlivePresence, ka_bytes, address.addressNoChecksum);
                            // Send to all stream client types
                            StreamClientManager.broadcastData(ProtocolMessageCode.keepAlivePresence, ka_bytes, address.addressNoChecksum);
                        }
                        else
                        {
                            // Send this keepalive to all connected clients
                            CoreProtocolMessage.broadcastProtocolMessage(['M', 'H', 'W', 'R'], ProtocolMessageCode.keepAlivePresence, ka_bytes, address.addressNoChecksum);
                        }

                        // Send this keepalive message to all connected clients
                        CoreProtocolMessage.broadcastEventDataMessage(NetworkEvents.Type.keepAlive, address.addressNoChecksum, ProtocolMessageCode.keepAlivePresence, ka_bytes, address.addressNoChecksum);
                    }
                    catch (ThreadInterruptedException)
                    {
                        throw;
                    }
                    catch (Exception e)
                    {
                        Logging.error("Exception occurred while generating keepalive: " + e);
                    }
                }
            }
            catch (ThreadInterruptedException)
            {

            }
            catch (Exception e)
            {
                Logging.error("KeepAlive exception: {0}", e);
            }
        }

        // Called when receiving a keepalive network message. The PresenceList will update the appropriate entry based on the timestamp.
        // Returns TRUE if it updated an entry in the PL
        // Sets the out address parameter to be the KA wallet's address or null if an error occurred
        public static bool receiveKeepAlive(byte[] bytes, out Address wallet, out long last_seen, out byte[] device_id, out char node_type, RemoteEndpoint endpoint)
        {
            wallet = null;
            last_seen = 0;
            device_id = null;
            node_type = (char)0;

            // Get the current timestamp
            long currentTime = Clock.getNetworkTimestamp();

            try
            {
                KeepAlive ka = new KeepAlive(bytes);
                wallet = ka.walletAddress;
                last_seen = ka.timestamp;
                device_id = ka.deviceId;
                node_type = ka.nodeType;

                if (ka.nodeType == 'C' || ka.nodeType == 'R')
                {
                    // all good, continue
                }
                else if (ka.nodeType == 'M' || ka.nodeType == 'H')
                {
                    if (ka.version == 1)
                    {
                        if (myPresenceType == 'M' || myPresenceType == 'H')
                        {
                            if (ConsensusConfig.minimumMasterNodeFunds > 0)
                            {
                                // check balance
                                if (IxianHandler.getWalletBalance(ka.walletAddress) < ConsensusConfig.minimumMasterNodeFunds)
                                {
                                    return false;
                                }
                            }
                        }
                    }
                }
                else
                {
                    // reject everything else
                    return false;
                }

                IxiNumber minSignerPowDifficulty = IxianHandler.getMinSignerPowDifficulty(IxianHandler.getLastBlockHeight() + 1, IxianHandler.getLastBlockVersion(), 0);

                lock (presences)
                {
                    Address address = wallet;
                    presences.TryGetValue(address.addressNoChecksum, out Presence listEntry);
                    if (listEntry == null && wallet.addressNoChecksum.SequenceEqual(IxianHandler.getWalletStorage().getPrimaryAddress().addressNoChecksum))
                    {
                        Logging.warn("My entry was removed from local PL, readding.");
                        curNodePresence.addresses.Clear();
                        curNodePresence.addresses.Add(curNodePresenceAddress);
                        updateEntry(curNodePresence);
                        presences.TryGetValue(address.addressNoChecksum, out listEntry);
                    }

                    // Check if no such wallet found in presence list
                    if (listEntry == null)
                    {
                        // request for additional data
                        CoreProtocolMessage.broadcastGetPresence(wallet.addressNoChecksum, endpoint);
                        return false;
                    }

                    if(!ka.verify(listEntry.pubkey, minSignerPowDifficulty))
                    {
                        Logging.warn("[PL] KEEPALIVE tampering for {0} {1}, incorrect Sig.", listEntry.wallet.ToString(), ka.hostName);
                        return false;
                    }

                    PresenceAddress pa = listEntry.addresses.Find(x => x.device.SequenceEqual(ka.deviceId));

                    if (pa != null)
                    {
                        // Check the node type
                        if (pa.lastSeenTime != ka.timestamp)
                        {
                            // Check for outdated timestamp
                            if (ka.timestamp < pa.lastSeenTime)
                            {
                                // We already have a newer timestamp for this entry
                                return false;
                            }

                            int expiration_time = CoreConfig.serverPresenceExpiration;

                            if (pa.type == 'C')
                            {
                                expiration_time = CoreConfig.clientPresenceExpiration;
                            }

                            // Check for tampering. Includes a +300, -30 second synchronization zone
                            if ((currentTime - ka.timestamp) > expiration_time)
                            {
                                Logging.warn("[PL] Received expired KEEPALIVE for {0} {1}. Timestamp {2}", listEntry.wallet.ToString(), pa.address, ka.timestamp);
                                return false;
                            }

                            if ((currentTime - ka.timestamp) < -30)
                            {
                                Logging.warn("[PL] Potential KEEPALIVE tampering for {0} {1}. Timestamp {2}", listEntry.wallet.ToString(), pa.address, ka.timestamp);
                                return false;
                            }

                            // Update presence address
                            pa.address = ka.hostName;
                            pa.lastSeenTime = ka.timestamp;
                            pa.powSolution = ka.powSolution;
                            pa.signature = ka.signature;
                            pa.version = ka.version;
                            if (pa.type != ka.nodeType)
                            {
                                presenceCount[pa.type]--;
                                presenceCount[ka.nodeType]++;
                            }
                            pa.type = ka.nodeType;

                            addPresenceIndex(pa, listEntry);
                            //Logging.info("[PL] LASTSEEN for {0} - {1} set to {2}", hostname, deviceid, pa.lastSeenTime);
                            return true;
                        }
                    }
                    else
                    {
                        if (wallet.addressNoChecksum.SequenceEqual(IxianHandler.getWalletStorage().getPrimaryAddress().addressNoChecksum))
                        {
                            curNodePresence.addresses.Clear();
                            curNodePresence.addresses.Add(curNodePresenceAddress);
                            updateEntry(curNodePresence);
                            return true;
                        }
                        else
                        {
                            CoreProtocolMessage.broadcastGetPresence(wallet.addressNoChecksum, endpoint);
                            return false;
                        }
                    }
                }
            }
            catch(Exception e)
            {
                Logging.error("Exception occurred in receiveKeepAlive: " + e);
                return false;
            }

            return false;
        }

        private static void removeExpiredPresences(char type, long expirationTime)
        {
            if (!presenceIndexTypeExpiration.TryGetValue(type, out var sd)) return;

            long curTime = Clock.getNetworkTimestamp();
            long expiredTime = curTime - expirationTime;
            long allowedFutureTime = curTime + 30;

            List<long> keysToRemove = new List<long>();
            foreach (var kv in sd)
            {
                long timestamp = kv.Key;
                if (timestamp > expiredTime) break;

                foreach (var presKV in kv.Value)
                {
                    var presence = presKV.Value;

                    foreach (var pa in presence.addresses.ToArray())
                    {
                        if (pa.type != type)
                        {
                            continue;
                        }

                        if (pa.lastSeenTime < allowedFutureTime
                            && pa.lastSeenTime > kv.Key)
                        {
                            continue;
                        }

                        Logging.info("Expired '{0}' lastseen for {1} / {2} / {3}", type, presKV.Value.wallet.ToString(), pa.address, Crypto.hashToString(pa.device));
                        removeAddressEntry(presKV.Value.wallet, pa, false);
                    }
                }
                keysToRemove.Add(timestamp);
            }

            foreach (var k in keysToRemove)
            {
                sd.Remove(k);
            }
        }

        // Perform routine PL cleanup
        public static void performCleanup()
        {
            lock (presences)
            {
                removeExpiredPresences('C', CoreConfig.clientPresenceExpiration);
                removeExpiredPresences('H', CoreConfig.serverPresenceExpiration);
                removeExpiredPresences('M', CoreConfig.serverPresenceExpiration);
                removeExpiredPresences('R', CoreConfig.serverPresenceExpiration);
                removeExpiredPresences('W', CoreConfig.clientPresenceExpiration);
            }
        }


        // Returns the total number of presences in the current list
        public static long getTotalPresences()
        {
            long total = 0;
            lock (presences)
            {
                total = presences.LongCount();
            }
            return total;
        }

        // Clears all the presences
        public static void clear()
        {
            lock (presences)
            {
                presences.Clear();
                foreach (var p in presenceCount)
                {
                    presenceCount[p.Key] = 0;
                }
            }
        }

        public static long countPresences(char type)
        {
            lock(presenceCount)
            {
                if (presenceCount.ContainsKey(type))
                {
                    return presenceCount[type];
                }
            }
            return 0;
        }

        public static Presence getPresenceByAddress(Address address)
        {
            if (address == null)
                return null;

            try
            {
                lock (presences)
                {
                    presences.TryGetValue(address.addressNoChecksum, out Presence pr);
                    return pr;
                }
            }
            catch(Exception e)
            {
                Logging.error("Exception occurred in getPresenceByAddress: {0}", e);
                return null;
            }
        }

        public static List<Presence> getPresencesByType(char type, int maxCount)
        {
            lock (presences)
            {
                var lastTimestamps = presenceIndexTypeExpiration[type].Values.Take(maxCount);
                Dictionary<byte[], Presence> presencesByType = new();
                foreach (var timestampEntries in lastTimestamps.Reverse())
                {
                    foreach (var presence in timestampEntries)
                    {
                        presencesByType.Add(presence.Key, presence.Value);
                        if (presencesByType.Count >= maxCount)
                        {
                            break;
                        }
                    }
                }
                return presencesByType.Values.ToList();
            }
        }

        // Get a copy of all presences, should be used for debug only
        public static List<Presence> getPresences()
        {
            lock (presences)
            {
                return new Dictionary<byte[], Presence>(presences, new ByteArrayComparer()).Values.ToList();
            }
        }

        public static void setPowSolution(SignerPowSolution powSolution)
        {
            curNodePresenceAddress.powSolution = powSolution;
            generateKeepAlive(true);
            forceSendKeepAlive = true;
        }

        public static SignerPowSolution getPowSolution()
        {
            return curNodePresenceAddress.powSolution;
        }

        public static string myPublicAddress
        {
            get { return _myPublicAddress; }
            set
            {
                _myPublicAddress = value;
                if (curNodePresenceAddress != null)
                {
                    if (curNodePresenceAddress.address != value)
                    {
                        curNodePresenceAddress.address = value;
                        generateKeepAlive(true);
                        forceSendKeepAlive = true;
                    }
                }
            }
        }

        public static char myPresenceType
        {
            get { return _myPresenceType; }
            set
            {
                _myPresenceType = value;
                if (curNodePresenceAddress != null)
                {
                    curNodePresenceAddress.type = value;
                }
            }
        }
    }
}

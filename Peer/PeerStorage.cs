// Copyright (C) 2017-2020 Ixian OU
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
using System.IO;
using System.Linq;

namespace IXICore
{
    public class PeerStorage
    {
        private static List<Peer> peerList = new List<Peer>();

        private static string folderPath = "";
        private static string fullPeersPath = "peers.ixi";

        private static int initialConnectionCount = 0;

        private static bool dirty = false;

        public static void init(string path, string filename = "")
        {
            if(filename == "")
            {
                filename = "peers.ixi";
                if(IxianHandler.isTestNet)
                {
                    filename = "testnet-peers.ixi";
                }
            }
            // Obtain paths and cache them
            folderPath = path;
            fullPeersPath = Path.Combine(folderPath, filename);
            initialConnectionCount = 0;
        }

        public static bool addPeerToPeerList(string hostname, Address walletAddress, long last_seen, long last_connect_attempt, long last_connected, int rating)
        {
            if(!validateHostname(hostname))
            {
                return false;
            }
            Peer p = new Peer(hostname, walletAddress, last_seen, last_connect_attempt, last_connected, rating);

            lock (peerList)
            {
                if (peerList.Exists(x => x.hostname == hostname))
                {
                    var tmp_peer = peerList.Find(x => x.hostname == hostname);
                    p.lastConnectAttempt = tmp_peer.lastConnectAttempt;
                    if (tmp_peer.lastConnected > p.lastConnected)
                    {
                        p.lastConnected = tmp_peer.lastConnected;
                    }
                    p.rating = tmp_peer.rating;
                    p.blacklisted = tmp_peer.blacklisted;
                }

                peerList.RemoveAll(x => x.hostname == hostname);

                if (walletAddress != null)
                {
                    peerList.RemoveAll(x => x.walletAddress != null && x.walletAddress.addressNoChecksum.SequenceEqual(walletAddress.addressNoChecksum));
                }

                peerList.Add(p);

                if (peerList.Count > 2000)
                {
                    long minLastSeen = peerList.Min(x => x.lastSeen);
                    var tmp_peerList = peerList.Where(x => x.lastSeen == minLastSeen);
                    if(tmp_peerList.Count() > 0)
                    {
                        peerList.Remove(tmp_peerList.First());
                    }
                }
            }
            dirty = true;

            return true;
        }

        public static bool removePeer(string hostname)
        {
            if (peerList.RemoveAll(x => x.hostname == hostname) > 0)
            {
                dirty = true;

                return true;
            }
            return false;
        }

        public static bool validateHostname(string address)
        {
            // Check if the address format is correct
            string[] server = address.Split(':');
            if (server.Count() < 2)
            {
                return false;
            }

            // Check address
            if (server[0] == "127.0.0.1"
                || server[0] == "localhost"
                || server[0].Trim() == "")
            {
                return false;
            }

            // Check port
            int port = 0;

            try
            {
                port = Int32.Parse(server[1]);
            }catch(Exception)
            {
                return false;
            }

            if (port <= 0 || port > 65535)
            {
                return false;
            }

            return true;
        }

        public static Peer getRandomMasterNodeAddress()
        {
            lock (peerList)
            {
                long curTime = Clock.getTimestamp();
                Peer p = null;
                if(initialConnectionCount < 1)
                {
                    var connectableList = peerList.FindAll(x => x.blacklisted == 0 && curTime - x.lastConnectAttempt > 30).OrderByDescending(x => x.lastConnected);
                    if (connectableList.Count() > 0)
                    {
                        p = connectableList.First();
                    }
                }
                else
                {
                    List<Peer> connectableList = peerList.FindAll(x => x.blacklisted == 0 && curTime - x.lastConnectAttempt > 30);
                    if (connectableList.Count > 0)
                    {
                        p = connectableList[Random.Shared.Next(connectableList.Count)];
                    }
                }
                if (p != null)
                {
                    p.lastConnectAttempt = curTime;
                    return p;
                }
            }
            return null;
        }

        // Saves a list of 500 master node addresses to a file
        public static void savePeersFile()
        {
            if (!dirty)
            {
                return;
            }

            lock (peerList)
            {
                // Don't write to file if no masternode presences were found in addition to the current node
                if (peerList.Count < 2)
                    return;

                string tempPath = fullPeersPath + ".tmp";

                using (TextWriter tw = new StreamWriter(tempPath, false))
                {
                    foreach (Peer p in peerList)
                    {
                        if (p.walletAddress == null)
                        {
                            continue;
                        }
                        tw.WriteLine(p.hostname + ";" + p.walletAddress.ToString() + ";" + p.lastSeen + ";" + p.lastConnectAttempt + ";" + p.lastConnected + ";" + p.rating);
                    }
                    tw.Flush();
                    tw.Close();
                }

                File.Copy(tempPath, fullPeersPath, true);
                File.Delete(tempPath);
            }
        }

        // Retrieves the master node address file's contents
        public static bool readPeersFile()
        {
            // Check if the presence file exists
            if (File.Exists(fullPeersPath))
            {
                Logging.info("Peers file found. Adding addresses to initial connections.");
            }
            else
            {
                return false;
            }

            try
            {
                lock (peerList)
                {
                    peerList.Clear();
                    List<string> ips = File.ReadAllLines(fullPeersPath).ToList();
                    foreach (string ip in ips)
                    {
                        string[] split_hostname = ip.Split(';');
                        try
                        {
                            if (split_hostname.Length == 6)
                            {
                                addPeerToPeerList(split_hostname[0], new Address(Base58Check.Base58CheckEncoding.DecodePlain(split_hostname[1])), Int64.Parse(split_hostname[2]), Int64.Parse(split_hostname[3]), Int64.Parse(split_hostname[4]), Int32.Parse(split_hostname[5]));
                            }
                            else if (split_hostname.Length == 2)
                            {
                                addPeerToPeerList(split_hostname[0], new Address(Base58Check.Base58CheckEncoding.DecodePlain(split_hostname[1])), 0, 0, 0, 0);
                            }
                        }catch(Exception)
                        {

                        }
                    }
                }
            }
            catch (Exception)
            {
                return false;
            }

            return true;
        }

        // Deletes the presence file cache
        public static void deletePeersFile()
        {
            if (File.Exists(fullPeersPath))
            {
                File.Delete(fullPeersPath);
            }

            return;
        }

        public static void decreaseRating(string hostname, int dec)
        {
            lock (peerList)
            {
                var tmp_peer = peerList.Find(x => x.hostname == hostname);
                if (tmp_peer == null)
                {
                    return;
                }
                if (tmp_peer.rating > 0)
                {
                    tmp_peer.rating -= dec;
                }
            }
        }

        public static void updateLastConnected(string hostname)
        {
            lock (peerList)
            {
                var tmp_peer = peerList.Find(x => x.hostname == hostname);
                if(tmp_peer == null)
                {
                    return;
                }
                tmp_peer.lastConnected = Clock.getTimestamp();
                tmp_peer.rating++;
                initialConnectionCount++;
            }
        }

        public static void resetInitialConnectionCount()
        {
            initialConnectionCount = 0;
        }

        public static void blacklist(string host_name)
        {
            lock (peerList)
            {
                Peer p = peerList.Find(x => x.hostname == host_name);
                if (p == null)
                {
                    return;
                }
                p.blacklisted = Clock.getTimestamp();
            }
        }

        public static void blacklist(Address wallet)
        {
            lock (peerList)
            {
                Peer p = peerList.Find(x => x.walletAddress != null && x.walletAddress.addressNoChecksum.SequenceEqual(wallet.addressNoChecksum));
                if (p == null)
                {
                    return;
                }
                p.blacklisted = Clock.getTimestamp();
            }
        }

        public static bool isBlacklisted(string host_name)
        {
            if (peerList.Find(x => x.blacklisted != 0 && x.hostname == host_name) != null)
            {
                return true;
            }
            return false;
        }

        public static bool isBlacklisted(Address wallet_address)
        {
            if (peerList.Find(x => x.blacklisted != 0 && x.walletAddress != null && x.walletAddress.addressNoChecksum.SequenceEqual(wallet_address.addressNoChecksum)) != null)
            {
                return true;
            }
            return false;
        }

        public static bool removeFromBlacklist(string host_name)
        {
            lock (peerList)
            {
                Peer p = peerList.Find(x => x.blacklisted != 0 && x.hostname == host_name);
                if (p != null)
                {
                    p.blacklisted = 0;
                    return true;
                }
                return false;
            }
        }

        public static bool removeFromBlacklist(Address wallet_address)
        {
            lock (peerList)
            {
                Peer p = peerList.Find(x => x.blacklisted != 0 && x.walletAddress != null && x.walletAddress.addressNoChecksum.SequenceEqual(wallet_address.addressNoChecksum));
                if (p != null)
                {
                    p.blacklisted = 0;
                    return true;
                }
                return false;
            }
        }

        public static void updateBlacklist()
        {
            lock (peerList)
            {
                long bl_window = Clock.getTimestamp() - CoreConfig.NodeBlacklistExpiration;
                var peers = peerList.FindAll(x => x.blacklisted != 0 && x.blacklisted < bl_window);
                foreach(var peer in peers)
                {
                    peer.blacklisted = 0;
                }
            }
        }

        public static void clearBlacklist()
        {
            lock (peerList)
            {
                var peers = peerList.FindAll(x => x.blacklisted != 0);
                foreach (var peer in peers)
                {
                    peer.blacklisted = 0;
                }
            }
        }
    }
}

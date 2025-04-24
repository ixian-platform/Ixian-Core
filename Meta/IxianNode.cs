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

using IXICore.Network;
using IXICore.RegNames;
using IXICore.Storage;
using IXICore.Streaming;
using IXICore.Utils;
using System;
using System.Collections.Generic;
using System.Linq;

namespace IXICore.Meta
{
    public class Balance
    {
        public Address address = null;
        public IxiNumber balance = 0;
        public ulong blockHeight = 0;
        public byte[] blockChecksum = null;
        public bool verified = false;
        public long lastUpdate = 0;

        public Balance(Address address, IxiNumber balance)
        {
            this.address = address;
            this.balance = balance;
        }
    }

    public enum NetworkType
    {
        main = 0,
        test = 1,
        reg = 2
    }

    public enum NodeStatus
    {
        warmUp = 0, // when the node is warming up
        ready = 1, // when the node is ready to process all data
        stalled = 2, // when the node hasn't received any block updates from the network for over 30 minutes
        stopping = 3, // when the node is stopping
        stopped = 4
    }

    public abstract class IxianNode
    {
        // Required
        public abstract ulong getHighestKnownNetworkBlockHeight();
        public abstract Block getBlockHeader(ulong blockNum);
        public abstract byte[] getBlockHash(ulong blockNum);
        public abstract Block getLastBlock();
        public abstract ulong getLastBlockHeight();
        public abstract int getLastBlockVersion();
        public abstract bool addTransaction(Transaction tx, List<Address> relayNodeAddresses, bool force_broadcast);
        public abstract bool isAcceptingConnections();
        public abstract Wallet getWallet(Address id);
        public abstract IxiNumber getWalletBalance(Address id);
        public abstract void parseProtocolMessage(ProtocolMessageCode code, byte[] data, RemoteEndpoint endpoint);

        public abstract void shutdown();

        // Optional
        public virtual void receivedTransactionInclusionVerificationResponse(byte[] txid, bool verified) { }
        public virtual void receivedBlockHeader(Block block_header, bool verified) { }

        public abstract IxiNumber getMinSignerPowDifficulty(ulong blockNum, int curBlockVersion, long curBlockTimestamp);

        public abstract RegisteredNameRecord getRegName(byte[] name, bool useAbsoluteId);

        public virtual void processFriendMessage(FriendMessage msg) { }
        public abstract bool receivedNewTransaction(Transaction tx);

        public abstract FriendMessage addMessageWithType(byte[] id, FriendMessageType type, Address wallet_address, int channel, string message, bool local_sender = false, Address sender_address = null, long timestamp = 0, bool fire_local_notification = true, int payable_data_len = 0);

        public abstract byte[] resizeImage(byte[] imageData, int width, int height, int quality);

        public abstract void resubscribeEvents();

        public abstract void receiveStreamData(byte[] data, RemoteEndpoint endpoint, bool fireLocalNotification);

        public abstract long getTimeSinceLastBlock();

        public abstract void triggerSignerPowSolutionFound();
    }

    public static class IxianHandler
    {
        private static IxianNode handlerClass = null;

        public static LocalStorage localStorage = null;

        public static List<Balance> balances = new List<Balance>(); // Stores the last known balances for this node

        private static string _publicIP = "";
        private static int _publicPort = 0;

        public static bool forceShutdown = false;

        /// <summary>
        /// Current node status.
        /// </summary>
        public static NodeStatus status = NodeStatus.warmUp;

        /// <summary>
        /// Network type designator.
        /// </summary>
        public static NetworkType networkType { get; private set; } = NetworkType.main;

        /// <summary>
        /// Testnet designator. If false the node can only connect to mainnet, if true it can only connect to testnet or regnet.
        /// </summary>
        public static bool isTestNet { get; private set; } = false;
        public static bool isRegNet { get; private set; } = false;

        public static Address primaryWalletAddress = null;
        public static Dictionary<byte[], WalletStorage> wallets = new Dictionary<byte[], WalletStorage>(new ByteArrayComparer());

        public static void init(string product_version, IxianNode handler_class, NetworkType type, bool set_title = false,
            byte[] checksum_lock = null)
        {
            CoreConfig.productVersion = product_version;
            if (set_title)
            {
                Console.Title = product_version + " (" + CoreConfig.version + ")";
            }
            init(handler_class, type, checksum_lock);
        }

        public static void init(IxianNode handler_class, NetworkType type, byte[] checksum_lock = null)
        {
            handlerClass = handler_class;
            networkType = type;
            switch (type)
            {
                case NetworkType.main:
                    if (checksum_lock != null)
                    {
                        ConsensusConfig.ixianChecksumLock = checksum_lock;
                    }
                    else
                    {
                        ConsensusConfig.ixianChecksumLock = ConsensusConfig.ixianChecksumLockMainNet;
                    }
                    isTestNet = false;
                    isRegNet = false;
                    break;

                case NetworkType.reg:
                    if (checksum_lock != null)
                    {
                        ConsensusConfig.ixianChecksumLock = checksum_lock;
                    }
                    else
                    {
                        ConsensusConfig.ixianChecksumLock = ConsensusConfig.ixianChecksumLockRegNet;
                    }
                    isRegNet = true;
                    isTestNet = true;
                    break;

                case NetworkType.test:
                    if (checksum_lock != null)
                    {
                        ConsensusConfig.ixianChecksumLock = checksum_lock;
                    }
                    else
                    {
                        ConsensusConfig.ixianChecksumLock = ConsensusConfig.ixianChecksumLockTestNet;
                    }
                    isTestNet = true;
                    isRegNet = false;
                    break;
            }
        }

        private static void verifyHandler()
        {
            if (handlerClass == null)
            {
                throw new Exception("Handler Class must be specified in IxianHandler Class");
            }
        }

        public static ulong getHighestKnownNetworkBlockHeight()
        {
            verifyHandler();
            return handlerClass.getHighestKnownNetworkBlockHeight();
        }

        public static Block getLastBlock()
        {
            verifyHandler();
            return handlerClass.getLastBlock();
        }

        public static ulong getLastBlockHeight()
        {
            verifyHandler();
            return handlerClass.getLastBlockHeight();
        }

        public static int getLastBlockVersion()
        {
            verifyHandler();
            return handlerClass.getLastBlockVersion();
        }

        public static bool addTransaction(Transaction tx, List<Address> relayNodeAddresses, bool force_broadcast)
        {
            verifyHandler();
            return handlerClass.addTransaction(tx, relayNodeAddresses, force_broadcast);
        }

        public static bool isAcceptingConnections()
        {
            verifyHandler();
            return handlerClass.isAcceptingConnections();
        }

        public static Wallet getWallet(Address address)
        {
            verifyHandler();
            return handlerClass.getWallet(address);
        }

        public static IxiNumber getWalletBalance(Address id)
        {
            verifyHandler();
            return handlerClass.getWalletBalance(id);
        }

        public static void receivedTransactionInclusionVerificationResponse(byte[] txid, bool verified)
        {
            verifyHandler();
            handlerClass.receivedTransactionInclusionVerificationResponse(txid, verified);
        }

        public static void receivedBlockHeader(Block block_header, bool verified)
        {
            verifyHandler();
            handlerClass.receivedBlockHeader(block_header, verified);
        }

        public static Block getBlockHeader(ulong blockNum)
        {
            verifyHandler();
            return handlerClass.getBlockHeader(blockNum);
        }

        public static byte[] getBlockHash(ulong blockNum)
        {
            verifyHandler();
            return handlerClass.getBlockHash(blockNum);
        }

        public static void parseProtocolMessage(ProtocolMessageCode code, byte[] data, RemoteEndpoint endpoint)
        {
            verifyHandler();
            handlerClass.parseProtocolMessage(code, data, endpoint);
        }

        public static void shutdown()
        {
            forceShutdown = true;
            verifyHandler();
            handlerClass.shutdown();
        }

        public static IxiNumber getMinSignerPowDifficulty(ulong blockNum, int curBlockVersion, long curBlockTimestamp)
        {
            verifyHandler();
            return handlerClass.getMinSignerPowDifficulty(blockNum, curBlockVersion, curBlockTimestamp);
        }

        public static RegisteredNameRecord getRegName(byte[] name, bool useAbsoluteId = true)
        {
            verifyHandler();
            return handlerClass.getRegName(name, useAbsoluteId);
        }

        public static WalletStorage getWalletStorage(Address walletAddress = null)
        {
            if (walletAddress == null)
            {
                return wallets[primaryWalletAddress.addressNoChecksum];
            }
            return wallets[walletAddress.addressNoChecksum];
        }

        public static WalletStorage getWalletStorageByFilename(string filename)
        {
            try
            {
                return wallets.First(x => x.Value.filename == filename).Value;
            }
            catch (Exception)
            {

            }
            return null;
        }

        public static WalletStorage getWalletStorageBySecondaryAddress(Address walletAddress)
        {
            lock (wallets)
            {
                foreach (var wallet in wallets)
                {
                    if (wallet.Value.isMyAddress(walletAddress))
                    {
                        return wallet.Value;
                    }
                }
            }
            return null;
        }


        public static bool addWallet(WalletStorage ws)
        {
            lock (wallets)
            {
                if (wallets.Count == 0)
                {
                    primaryWalletAddress = ws.getPrimaryAddress();
                }
                if (wallets.ContainsKey(ws.getPrimaryAddress().addressNoChecksum))
                {
                    return false;
                }
                wallets.Add(ws.getPrimaryAddress().addressNoChecksum, ws);
            }
            return true;
        }

        public static bool removeWallet(Address walletAddress)
        {
            lock (wallets)
            {
                if (walletAddress.addressNoChecksum.SequenceEqual(primaryWalletAddress.addressNoChecksum))
                {
                    Logging.warn("Cannot remove primary wallet {0}", primaryWalletAddress.ToString());
                    return false;
                }
                return wallets.Remove(walletAddress.addressNoChecksum);
            }
        }

        public static bool isMyAddress(Address walletAddress)
        {
            lock (wallets)
            {
                foreach (var wallet in wallets)
                {
                    if (wallet.Value.isMyAddress(walletAddress))
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        public static Dictionary<byte[], List<byte[]>> extractMyAddressesFromAddressList(IDictionary<Address, Transaction.ToEntry> addressList, bool useSeedHashAsKey = true)
        {
            Dictionary<byte[], List<byte[]>> addresses = new Dictionary<byte[], List<byte[]>>();
            lock (wallets)
            {
                foreach (var wallet in wallets)
                {
                    var extractedAddresses = wallet.Value.extractMyAddressesFromAddressList(addressList);
                    if (extractedAddresses != null && extractedAddresses.Count > 0)
                    {
                        if (useSeedHashAsKey)
                        {
                            addresses.Add(wallet.Value.getSeedHash(), extractedAddresses);
                        }
                        else
                        {
                            addresses.Add(wallet.Key, extractedAddresses);
                        }
                    }
                }
            }
            if (addresses.Count == 0)
            {
                return null;
            }
            return addresses;
        }

        public static List<string> getWalletList()
        {
            List<string> walletList = new List<string>();

            lock (wallets)
            {
                foreach (var wallet in wallets)
                {
                    walletList.Add(Base58Check.Base58CheckEncoding.EncodePlain(wallet.Key));
                }
            }

            return walletList;
        }

        /// <summary>
        ///  IP Address on which the node is reachable.
        /// </summary>
        public static string publicIP
        {
            get { return _publicIP; }
            set
            {
                _publicIP = value;
                PresenceList.myPublicAddress = getFullPublicAddress();
            }
        }

        /// <summary>
        ///  Port on which the node is reachable.
        /// </summary>
        public static int publicPort
        {
            get { return _publicPort; }
            set
            {
                _publicPort = value;
                PresenceList.myPublicAddress = getFullPublicAddress();
            }
        }

        public static string getFullPublicAddress()
        {
            return publicIP + ":" + publicPort;
        }

        public static void processFriendMessage(FriendMessage msg)
        {
            verifyHandler();
            handlerClass.processFriendMessage(msg);
        }

        public static bool receivedNewTransaction(Transaction tx)
        {
            verifyHandler();
            return handlerClass.receivedNewTransaction(tx);
        }

        public static FriendMessage addMessageWithType(byte[] id, FriendMessageType type, Address wallet_address, int channel, string message, bool local_sender = false, Address sender_address = null, long timestamp = 0, bool fire_local_notification = true, int payable_data_len = 0)
        {
            verifyHandler();
            return handlerClass.addMessageWithType(id, type, wallet_address, channel, message, local_sender, sender_address, timestamp, fire_local_notification, payable_data_len);
        }
        public static byte[] resizeImage(byte[] imageData, int width, int height, int quality)
        {
            verifyHandler();
            return handlerClass.resizeImage(imageData, width, height, quality);
        }

        public static void resubscribeEvents()
        {
            verifyHandler();
            handlerClass.resubscribeEvents();
        }

        public static void receiveStreamData(byte[] data, RemoteEndpoint endpoint, bool fireLocalNotification)
        {
            verifyHandler();
            handlerClass.resubscribeEvents();
        }

        public static long getTimeSinceLastBlock()
        {
            verifyHandler();
            return handlerClass.getTimeSinceLastBlock();
        }


        public static void triggerSignerPowSolutionFound()
        {
            verifyHandler();
            handlerClass.triggerSignerPowSolutionFound();
        }
    }
}
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

namespace IXICore
{
    public class PendingTransaction
    {
        public Transaction transaction;
        public List<Address>? relayNodeAddresses;
        public long addedTimestamp;
        public List<byte[]> confirmedNodeList = new List<byte[]>();
        public List<byte[]> rejectedNodeList = new List<byte[]>();
        public Address? senderAddress;
        public bool outgoing = false;

        public PendingTransaction(Transaction t, List<Address>? relayNodeAddresses, long addedTimestamp, bool outgoing, Address? senderAddress = null)
        {
            transaction = t;
            this.relayNodeAddresses = relayNodeAddresses;
            this.addedTimestamp = addedTimestamp;
            this.senderAddress = senderAddress;
            this.outgoing = outgoing;
        }
    }

    public class PendingTransactions
    {
        public static Dictionary<byte[], PendingTransaction> pendingTransactions = new(new ByteArrayComparer());

        public static bool addIncomingTransaction(Transaction t)
        {
            lock (pendingTransactions)
            {
                if (!pendingTransactions.ContainsKey(t.id))
                {
                    pendingTransactions[t.id] = new PendingTransaction(t, null, Clock.getTimestamp(), false);
                    return true;
                }
            }
            return false;
        }

        public static bool addOutgoingTransaction(Transaction t, List<Address>? relayNodeAddresses, Address? senderAddress = null)
        {
            lock (pendingTransactions)
            {
                if (!pendingTransactions.ContainsKey(t.id))
                {
                    pendingTransactions[t.id] = new PendingTransaction(t, relayNodeAddresses, Clock.getTimestamp(), true, senderAddress);
                    return true;
                }
            }
            return false;
        }

        public static long pendingTransactionCount()
        {
            lock (pendingTransactions)
            {
                return pendingTransactions.LongCount();
            }
        }

        public static IxiNumber getPendingSendingTransactionsAmount()
        {
            IxiNumber amount = 0;
            lock (pendingTransactions)
            {
                var txs = pendingTransactions.Values;
                foreach (var entry in txs)
                {
                    Transaction tx = entry.transaction;
                    if (IxianHandler.isMyAddress(tx.pubKey))
                    {
                        if (IxianHandler.balances.TryGet(tx.pubKey)?.blockHeight > tx.blockHeight)
                        {
                            continue;
                        }
                        amount += tx.amount + tx.fee;
                    }
                }
            }
            return amount;
        }

        public static PendingTransaction? remove(byte[] txid)
        {
            lock (pendingTransactions)
            {
                var tx = pendingTransactions.TryGet(txid);
                if (tx != null)
                {
                    pendingTransactions.Remove(txid);
                }
                return tx;
            }
        }

        public static PendingTransaction getPendingTransaction(byte[] txid)
        {
            lock (pendingTransactions)
            {
                return pendingTransactions.TryGet(txid);
            }
        }

        public static IEnumerable<PendingTransaction> getPendingTransactions()
        {
            lock (pendingTransactions)
            {
                return pendingTransactions.Values.Select(tx => tx);
            }
        }

        public static IEnumerable<byte[]> getAllPendingTxids()
        {
            lock (pendingTransactions)
            {
                return pendingTransactions.Values.Select(tx => tx.transaction.id);
            }
        }

        public static void increaseReceivedCount(byte[] txid, Address address)
        {
            lock (pendingTransactions)
            {
                PendingTransaction pending = pendingTransactions.TryGet(txid);
                if (pending != null)
                {
                    if(pending.confirmedNodeList.Find(x => x.SequenceEqual(address.addressNoChecksum)) == null)
                    {
                        pending.confirmedNodeList.Add(address.addressNoChecksum);
                    }
                }
            }
        }

        public static void increaseRejectedCount(byte[] txid, Address address)
        {
            lock (pendingTransactions)
            {
                PendingTransaction pending = pendingTransactions.TryGet(txid);
                if (pending != null)
                {
                    if (pending.rejectedNodeList.Find(x => x.SequenceEqual(address.addressNoChecksum)) == null)
                    {
                        pending.rejectedNodeList.Add(address.addressNoChecksum);
                    }
                }
            }
        }

        public static void clear()
        {
            lock (pendingTransactions)
            {
                pendingTransactions.Clear();
            }
        }
    }
}

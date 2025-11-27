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
using System.Collections.Generic;
using System.Linq;

namespace IXICore
{
    public class PendingTransaction
    {
        public Transaction transaction;
        public List<Address> relayNodeAddresses;
        public long addedTimestamp;
        public List<byte[]> confirmedNodeList = new List<byte[]>();
        public List<byte[]> rejectedNodeList = new List<byte[]>();
        public byte[] messageId;
        public Address senderAddress;

        public PendingTransaction(Transaction t, List<Address> relayNodeAddresses, long addedTimestamp, byte[] message_id, Address senderAddress)
        {
            transaction = t;
            this.relayNodeAddresses = relayNodeAddresses;
            this.addedTimestamp = addedTimestamp;
            messageId = message_id;
            this.senderAddress = senderAddress;
        }
    }

    // TODO TODO TODO make PendingTransactions persistent
    public class PendingTransactions
    {
        public static List<PendingTransaction> pendingTransactions = new List<PendingTransaction>();

        public static bool addPendingLocalTransaction(Transaction t, List<Address> relayNodeAddresses, byte[] message_id = null, Address senderAddress = null)
        {
            lock (pendingTransactions)
            {
                if (pendingTransactions.Find(x => x.transaction.id.SequenceEqual(t.id)) == null)
                {
                    pendingTransactions.Add(new PendingTransaction(t, relayNodeAddresses, Clock.getTimestamp(), message_id, senderAddress));
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
                List<PendingTransaction> txs = pendingTransactions.FindAll(x => x.transaction.type == (int)Transaction.Type.Normal);
                foreach (var entry in txs)
                {
                    Transaction tx = entry.transaction;
                    if (IxianHandler.isMyAddress(tx.pubKey))
                    {
                        amount += tx.amount + tx.fee;
                    }
                }
            }
            return amount;
        }

        public static PendingTransaction remove(byte[] txid)
        {
            lock (pendingTransactions)
            {
                var txs = pendingTransactions.FindAll(x => x.transaction.id.SequenceEqual(txid));
                foreach (var tx in txs)
                {
                    pendingTransactions.Remove(tx);
                }
                return txs.Count > 0 ? txs.First() : null;
            }
        }

        public static PendingTransaction getPendingTransaction(byte[] txid)
        {
            lock (pendingTransactions)
            {
                return pendingTransactions.Find(x => x.transaction.id.SequenceEqual(txid));
            }
        }

        public static void increaseReceivedCount(byte[] txid, Address address)
        {
            lock (pendingTransactions)
            {
                PendingTransaction pending = pendingTransactions.Find(x => x.transaction.id.SequenceEqual(txid));
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
                PendingTransaction pending = pendingTransactions.Find(x => x.transaction.id.SequenceEqual(txid));
                if (pending != null)
                {
                    if (pending.rejectedNodeList.Find(x => x.SequenceEqual(address.addressNoChecksum)) == null)
                    {
                        pending.rejectedNodeList.Add(address.addressNoChecksum);
                    }
                }
            }
        }
    }
}

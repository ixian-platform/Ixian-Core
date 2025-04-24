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

using System.Collections.Generic;
using System.Linq;

namespace IXICore
{
    public class PendingTransaction
    {
        public Transaction transaction;
        public List<Address> relayNodeAddress;
        public long addedTimestamp;
        public List<byte[]> confirmedNodeList = new List<byte[]>();
        public byte[] messageId;

        public PendingTransaction(Transaction t, List<Address> relayNodeAddress, long addedTimestamp, byte[] message_id)
        {
            transaction = t;
            this.relayNodeAddress = relayNodeAddress;
            this.addedTimestamp = addedTimestamp;
            messageId = message_id;
        }
    }

    // TODO TODO TODO make PendingTransactions persistent
    public class PendingTransactions
    {
        public static List<PendingTransaction> pendingTransactions = new List<PendingTransaction>();

        public static bool addPendingLocalTransaction(Transaction t, List<Address> relayNodeAddresses, byte[] message_id = null)
        {
            lock (pendingTransactions)
            {
                if (pendingTransactions.Find(x => x.transaction.id.SequenceEqual(t.id)) == null)
                {
                    pendingTransactions.Add(new PendingTransaction( t, relayNodeAddresses, Clock.getTimestamp(), message_id));
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

        public static IxiNumber getPendingSendingTransactionsAmount(Address primary_address)
        {
            IxiNumber amount = 0;
            lock (pendingTransactions)
            {
                List<PendingTransaction> txs = pendingTransactions.FindAll(x => x.transaction.type == (int)Transaction.Type.Normal);
                foreach (var entry in txs)
                {
                    Transaction tx = entry.transaction;
                    if (primary_address == null || tx.pubKey.addressNoChecksum.SequenceEqual(primary_address.addressNoChecksum))
                    {
                        amount += tx.amount + tx.fee;
                    }
                }
            }
            return amount;
        }

        public static void remove(byte[] txid)
        {
            lock (pendingTransactions)
            {
                pendingTransactions.RemoveAll(x => x.transaction.id.SequenceEqual(txid));
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
    }
}

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
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace IXICore
{
    namespace Storage
    {
        public enum BlockSigPruningType : byte
        {
            None = 0,
            Signatures = 1,
            PoCW = 2
        }

        public abstract class IStorage
        {
            protected string pathBase;
            // Threading
            protected CancellationTokenSource? ctsLoop;
            private Task? storageTask;
            private TaskCompletionSource wakeSignal = new(TaskCreationOptions.RunContinuationsAsynchronously);
            private ThreadLiveCheck? TLC;
            private long lastCleanupPass = Clock.getTimestamp();

            protected enum QueueStorageCode
            {
                insertTransaction,
                insertBlock,
                updateTxAppliedFlag

            }
            protected struct QueueStorageMessage
            {
                public QueueStorageCode code;
                public int retryCount;
                public object data;
            }

            // Maintain a queue of sql statements
            protected readonly List<QueueStorageMessage> queueStatements = new List<QueueStorageMessage>();

            protected IStorage(string dataFolderBlocks)
            {
                pathBase = dataFolderBlocks;
            }


            public virtual bool prepareStorage(bool optimize)
            {
                if (ctsLoop != null)
                {
                    return false;
                }

                ctsLoop = new CancellationTokenSource();

                if (!prepareStorageInternal(optimize))
                {
                    ctsLoop = null;
                    return false;
                }
                // Start thread
                TLC = new ThreadLiveCheck();

                storageTask = Task.Run(() => threadLoop(ctsLoop.Token));

                return true;
            }

            public virtual void stopStorage()
            {
                if (ctsLoop == null)
                {
                    return;
                }

                Logging.info("Stopping storage, please wait...");

                ctsLoop.Cancel();
                wakeSignal.TrySetResult();
                try
                {
                    // Wait for reconnect loop to finish
                    storageTask?.GetAwaiter().GetResult();
                }
                catch (OperationCanceledException) { }
                finally
                {
                    ctsLoop.Dispose();
                    ctsLoop = null;
                    storageTask = null;
                }

                shutdown();
                Logging.info("Storage stopped.");
            }

            protected virtual async void threadLoop(CancellationToken token)
            {
                QueueStorageMessage active_message = new QueueStorageMessage();

                bool pending_statements = false;

                while (!token.IsCancellationRequested || pending_statements == true)
                {
                    bool message_found = false;
                    pending_statements = false;
                    TLC.Report();
                    try
                    {
                        lock (queueStatements)
                        {
                            int statements_count = queueStatements.Count();
                            if (statements_count > 0)
                            {
                                if (statements_count > 1)
                                {
                                    pending_statements = true;
                                }
                                QueueStorageMessage candidate = queueStatements[0];
                                active_message = candidate;
                                message_found = true;
                            }
                        }

                        if (message_found)
                        {
                            if (active_message.code == QueueStorageCode.insertTransaction)
                            {
                                insertTransactionInternal((Transaction)active_message.data);
                            }
                            else if (active_message.code == QueueStorageCode.insertBlock)
                            {
                                insertBlockInternal((Block)active_message.data);
                            }
                            lock (queueStatements)
                            {
                                queueStatements.RemoveAt(0);
                            }
                        }
                        else
                        {
                            long cur_time = Clock.getTimestamp();
                            if (cur_time - lastCleanupPass > 60)
                            {
                                lastCleanupPass = cur_time;
                                cleanupCache();
                            }
                            // Sleep for 50ms to yield CPU schedule slot

                            // setup fresh wake signal
                            var currentWake = wakeSignal;
                            wakeSignal = new(TaskCreationOptions.RunContinuationsAsynchronously);

                            // wait either interval or wake signal
                            await Task.WhenAny(Task.Delay(50, token), currentWake.Task);
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                    catch (Exception e)
                    {
                        Logging.error("Exception occurred in storage thread loop: " + e);
                        if (message_found)
                        {
                            debugDumpCrashObject(active_message);
                            active_message.retryCount += 1;
                            if (active_message.retryCount > 10)
                            {
                                lock (queueStatements)
                                {
                                    queueStatements.RemoveAt(0);
                                }
                                Logging.error("Too many retries, aborting...");
                                shutdown();
                                throw new Exception("Too many storage retries. Aborting storage thread.");
                            }
                        }
                        // setup fresh wake signal
                        var currentWake = wakeSignal;
                        wakeSignal = new(TaskCreationOptions.RunContinuationsAsynchronously);

                        // wait either interval or wake signal
                        await Task.WhenAny(Task.Delay(50, token), currentWake.Task);
                    }
                }
            }

            private void debugDumpCrashObject(QueueStorageMessage message)
            {
                Logging.error("Crashed on message: (code: {0}, retry count: {1})", message.code.ToString(), message.retryCount);
                if (message.retryCount == 1 || message.retryCount >= 10)
                {
                    if (message.code == QueueStorageCode.insertBlock)
                    {
                        debugDumpCrashBlock((Block)message.data);
                    }
                    else if (message.code == QueueStorageCode.insertTransaction)
                    {
                        debugDumpCrashTX((Transaction)message.data);
                    }
                    else
                    {
                        Logging.error("Message is 'updateTXAppliedFlag'.");
                    }
                }
            }

            private void debugDumpCrashBlock(Block b)
            {
                Logging.error("Block #{0}, hash: {1}.", b.blockNum, Base58Check.Base58CheckEncoding.EncodePlain(b.blockChecksum));
                Logging.error("Transactions: {0}, signatures: {1}, timestamp: {2}.", b.transactions.Count, b.signatures.Count, b.timestamp);
                Logging.error("Complete block: {0}", Base58Check.Base58CheckEncoding.EncodePlain(b.getBytes()));
            }

            private void debugDumpCrashTX(Transaction tx)
            {
                Logging.error("Transaction {0}, hash: {1}", tx.getTxIdString(), Base58Check.Base58CheckEncoding.EncodePlain(tx.checksum));
                Logging.error("Type: {0}, amount: {1}", tx.type, tx.amount);
                Logging.error("Complete transaction: {0}", Base58Check.Base58CheckEncoding.EncodePlain(tx.getBytes(true, true)));
            }

            public abstract void redactBlockStorage(ulong removeBlocksBelow);

            public virtual int getQueuedQueryCount()
            {
                lock (queueStatements)
                {
                    return queueStatements.Count;
                }
            }

            public virtual bool insertBlock(Block block)
            {
                // Make a copy of the block for the queue storage message processing
                QueueStorageMessage message = new QueueStorageMessage
                {
                    code = QueueStorageCode.insertBlock,
                    retryCount = 0,
                    data = new Block(block)
                };

                lock (queueStatements)
                {
                    queueStatements.Add(message);
                }
                return true;
            }


            public virtual bool insertTransaction(Transaction transaction)
            {
                // Make a copy of the transaction for the queue storage message processing
                QueueStorageMessage message = new QueueStorageMessage
                {
                    code = QueueStorageCode.insertTransaction,
                    retryCount = 0,
                    data = new Transaction(transaction)
                };

                lock (queueStatements)
                {
                    queueStatements.Add(message);
                }
                return true;
            }

            // Used when on-disk storage must be upgraded
            public virtual bool needsUpgrade() { return false; }
            public virtual bool isUpgrading() { return false; }
            public virtual int upgradePercentage() { return 0; }
            public virtual ulong upgradeBlockNum() { return 0; }
            //
            // Insert
            protected abstract bool insertBlockInternal(Block block);
            protected abstract bool insertTransactionInternal(Transaction transaction);
            //
            public abstract ulong getLowestBlockInStorage();
            public abstract ulong getHighestBlockInStorage();
            // Get - Block
            /// <summary>
            /// Retrieves a Block by its block height from the underlying storage (database).
            /// </summary>
            /// <param name="blocknum">Block height of the block you wish to retrieve.</param>
            /// <returns>Null if the Block does not exist in storage.</returns>
            public abstract Block? getBlock(ulong blocknum);
            public abstract byte[]? getBlockBytes(ulong blocknum, bool compactedSignatures, bool includeTransactions);
            // Get - Transaction
            /// <summary>
            /// Retrieves a Transaction by its txid.
            /// </summary>
            /// <param name="txid">Transaction ID of the required Transaction.</param>
            /// <param name="block_num">Block height of the Block where the Transaction can be found.</param>
            /// <returns>Null if this transaction can't be found in storage.</returns>
            public abstract Transaction? getTransaction(byte[] txid, ulong block_num);
            public abstract byte[]? getTransactionBytes(byte[] txid, ulong block_num);
            /// <summary>
            /// Retrieves all Transactions from the specified block.
            /// </summary>
            /// <param name="block_num">Block from which to read Transactions.</param>
            /// <returns>Collection with matching Transactions.</returns>
            public abstract IEnumerable<Transaction>? getTransactionsInBlock(ulong block_num, short tx_type = -1);
            public abstract IEnumerable<byte[]>? getTransactionsBytesInBlock(ulong block_num, short tx_type = -1);
            //
            // Remove
            public abstract bool removeBlock(ulong block_num);
            public abstract bool removeTransaction(byte[] txid, ulong block_num);

            public abstract (byte[]? blockHash, IxiNumber? totalSignerDifficulty) getBlockTotalSignerDifficulty(ulong blocknum);
            //
            // Prepare and cleanup
            protected abstract bool prepareStorageInternal(bool optimize);
            protected abstract void shutdown();
            protected abstract void cleanupCache();
            public abstract void sleep();
            public abstract void deleteData();

            public abstract void pruneBlocks(ulong pruneBlocksBelow, BlockSigPruningType pruningType, bool pruneSuperblocks);
            public abstract void pruneTxIDs(ulong pruneBlocksBelow);
        }
    }
}

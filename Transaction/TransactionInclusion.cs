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
using IXICore.Network;
using IXICore.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;

// TODO TODO PIT tree should be included with the transaction, it should be requested from the nodes only in cases where PIT wasn't included

namespace IXICore
{
    /// <summary>
    /// Caches information about received PIT data for each block we're interested in.
    /// Note: Because we may request a PIT for a subset of that block's transactions, we must also store
    /// all the transactions for which the PIT was requested.
    /// </summary>
    class PITCacheItem
    {
        public List<byte[]> requestedForTXIDs;
        public long requestSent;
        public PrefixInclusionTree pit;
    }
    class TransactionInclusion
    {
        private Thread tiv_thread = null;
        private bool running = false;

        Dictionary<byte[], Transaction> txQueue = new Dictionary<byte[], Transaction>(new ByteArrayComparer()); // List of all transactions that should be verified
        SortedList<ulong, PITCacheItem> pitCache = new SortedList<ulong, PITCacheItem>();
        long pitRequestTimeout = 5; // timeout (seconds) before PIT for a specific block is re-requested
        long pitCachePruneInterval = 30; // interval how often pit cache is checked and uninteresting entries removed (to save memory)

        Block lastBlockHeader = null;

        long lastRequestedBlockTime = 0;
        long lastPITPruneTime = 0;

        ulong minBlockHeightReorg = 0;

        bool pruneBlocks = true;

        ulong startingBlockHeight = 0;
        byte[] startingBlockChecksum = null;

        public ulong blockHeadersToRequestInChunk = 250;

        public TransactionInclusion()
        {
        }

        public void start(string block_header_storage_path = "", bool compacted = false, bool pruneBlocks = true)
        {
            // this method should be improved
            ulong block_height = 0;
            byte[] block_checksum = null;
            if(!IxianHandler.isTestNet)
            {
                block_height = CoreConfig.bakedBlockHeight;
                block_checksum = CoreConfig.bakedBlockChecksum;
            }
            start(block_header_storage_path, block_height, block_checksum, compacted, pruneBlocks);
        }

        public void start(string block_header_storage_path, ulong starting_block_height, byte[] starting_block_checksum, bool compacted, bool pruneBlocks = true)
        {
            this.pruneBlocks = pruneBlocks;

            if (running)
            {
                return;
            }

            running = true;

            startingBlockHeight = starting_block_height;
            startingBlockChecksum = starting_block_checksum;

            BlockHeaderStorage.init(block_header_storage_path, compacted);

            // Start the thread
            tiv_thread = new Thread(onUpdate);
            tiv_thread.Name = "TIV_Update_Thread";
            tiv_thread.Start();
        }

        public void onUpdate()
        {
            try
            {
                try
                {
                    BlockHeaderStorage.initCache();
                }
                catch (Exception e)
                {
                    Logging.error("Exception occurred in BlockHeaderStorage.init: " + e);
                }

                Block last_block_header = BlockHeaderStorage.getLastBlockHeader();

                if (last_block_header != null && last_block_header.blockNum > startingBlockHeight)
                {
                    lastBlockHeader = last_block_header;
                }
                else
                {
                    BlockHeaderStorage.deleteCache();
                    lastBlockHeader = new Block() { blockNum = startingBlockHeight, blockChecksum = startingBlockChecksum };
                }

                while (running)
                {
                    if (updateBlockHeaders())
                    {
                        verifyUnprocessedTransactions();
                        long currentTime = Clock.getTimestamp();
                        if (currentTime - lastPITPruneTime > pitCachePruneInterval)
                        {
                            prunePITCache();
                        }
                    }
                    Thread.Sleep(ConsensusConfig.blockGenerationInterval);
                }
            }
            catch (ThreadInterruptedException)
            {

            }
            catch (Exception e)
            {
                Logging.error("OnUpdate exception: {0}", e);
            }
        }

        public void stop()
        {
            if(!running)
            {
                return;
            }
            running = false;

            BlockHeaderStorage.stop();

            // Force stopping of thread
            if (tiv_thread == null)
                return;

            tiv_thread.Interrupt();
            tiv_thread.Join();
            tiv_thread = null;
        }

        private bool updateBlockHeaders(bool force_update = false, RemoteEndpoint endpoint = null)
        {
            long currentTime = Clock.getTimestamp();

            // Check if the request expired
            if (force_update || currentTime - lastRequestedBlockTime > ConsensusConfig.blockGenerationInterval)
            {
                lastRequestedBlockTime = currentTime;

                // request next blocks
                requestBlockHeaders(lastBlockHeader.blockNum + 1, blockHeadersToRequestInChunk, endpoint);

                return true;
            }

            return false;
        }

        private ulong blockHeightFromTxid(string txid)
        {
            ulong txbnum = 0;
            // Extract the blocknum from the txid
            try
            {
                string[] split_str = txid.Split(new string[] { "-" }, StringSplitOptions.None);
                txbnum = Convert.ToUInt64(split_str[0]);
            }
            catch (Exception e)
            {
                Logging.error("TIV exception: {0}", e);
                return 0;
            }
            return txbnum;
        }

        /// <summary>
        ///  Posts a verify transaction inclusion request
        /// </summary>
        /// <param name="txid">transaction id string</param>
        public bool receivedNewTransaction(Transaction t)
        {
            // TODO verify transaction checksum/validity

            lock (txQueue)
            {
                if (txQueue.Count() > 0)
                {
                    if (txQueue.ContainsKey(t.id))
                    {
                        // Already in the requests queue
                        if (txQueue[t.id].applied == 0)
                        {
                            txQueue[t.id] = t;
                        }
                        return false;
                    }
                }

                txQueue.Add(t.id, t);
                return true;
            }
        }

        private void verifyUnprocessedTransactions()
        {
            if(lastBlockHeader == null)
            {
                return;
            }
            lock (txQueue)
            {
                var tmp_txQueue = txQueue.Values.Where(x => x.applied != 0 && x.applied <= lastBlockHeader.blockNum).ToArray();
                foreach(var tx in tmp_txQueue)
                {
                    Block bh = BlockHeaderStorage.getBlockHeader(tx.applied);
                    if(bh is null)
                    {
                        // TODO: need to wait for the block to arrive, or re-request
                        // maybe something similar to PIT cache, or extend PIT cache to handle older blocks, too
                        continue;
                    }
                    if (bh.version < BlockVer.v6)
                    {
                        txQueue.Remove(tx.id);

                        if(bh.transactions.Contains(tx.id, new ByteArrayComparer()))
                        {
                            // valid
                            IxianHandler.receivedTransactionInclusionVerificationResponse(tx.id, true);
                        }else
                        {
                            // invalid
                            IxianHandler.receivedTransactionInclusionVerificationResponse(tx.id, false);
                        }

                    }
                    else
                    {
                        lock (pitCache)
                        {
                            // check if we already have the partial tree for this transaction
                            if (pitCache.ContainsKey(tx.applied) && pitCache[tx.applied].pit != null)
                            {
                                // Note: PIT has been verified against the block header when it was received, so additional verification is not needed here.
                                // Note: the PIT we have cached might have been requested for different txids (the current txid could have been added later)
                                // For that reason, the list of TXIDs we requested is stored together with the cached PIT
                                byte[] txid = null;
                                if(bh.version < BlockVer.v8)
                                {
                                    txid = UTF8Encoding.UTF8.GetBytes(tx.getTxIdString());
                                }else
                                {
                                    txid = tx.id;
                                }
                                if (pitCache[tx.applied].requestedForTXIDs.Contains(tx.id, new ByteArrayComparer()))
                                {
                                    // TODO TODO it shouldn't be immediatelly removed but checked with other nodes first
                                    txQueue.Remove(tx.id);

                                    if (pitCache[tx.applied].pit.contains(txid))
                                    {
                                        // valid
                                        IxianHandler.receivedTransactionInclusionVerificationResponse(tx.id, true);
                                    }
                                    else
                                    {
                                        // invalid
                                        IxianHandler.receivedTransactionInclusionVerificationResponse(tx.id, false);
                                    }
                                }
                                else
                                {
                                    // PIT cache for the correct block exists, but it was originally requested for different txids
                                    // we have to re-request it for any remaining txids in the queue. (We do not need to request the already-verified ids)
                                    requestPITForBlock(tx.applied,
                                        txQueue.Values
                                            .Where(x => x.applied == tx.applied && x.applied <= lastBlockHeader.blockNum)
                                            .Select(x => x.id)
                                            .ToList());
                                    continue;
                                }
                            }
                            else
                            {
                                // PIT cache has not been received yet, or maybe it has never been requested for this block
                                requestPITForBlock(tx.applied,
                                    txQueue.Values
                                        .Where(x => x.applied == tx.applied && x.applied <= lastBlockHeader.blockNum)
                                        .Select(x => x.id)
                                        .ToList());
                            }
                        }
                    }
                }
                tmp_txQueue = txQueue.Values.Where(x => x.blockHeight + ConsensusConfig.getRedactedWindowSize() < lastBlockHeader.blockNum).ToArray();
                foreach (var tx in tmp_txQueue)
                {
                    txQueue.Remove(tx.id);
                    // invalid
                    IxianHandler.receivedTransactionInclusionVerificationResponse(tx.id, false);
                }
            }
        }

        /// <summary>
        /// Requests PIT for the specified block from a random connected neighbor node.
        /// Nominally, only the transactions included in `txids` need to be verifiable with the PIT, but
        /// due to how Cuckoo filtering works, some false positives will also be included. This helps with anonymization, if the false positive rate is high enough.
        /// </summary>
        /// <param name="block_num">Block number for which the PIT should be included.</param>
        /// <param name="txids">List of interesting transactions, which we wish to verify.</param>
        private void requestPITForBlock(ulong block_num, List<byte[]> txids)
        {
            lock(pitCache)
            {
                long currentTime = Clock.getTimestamp();
                // Request might already have been sent. In that case, we re-send it we have been waiting for too long.
                if(!pitCache.ContainsKey(block_num) || currentTime - pitCache[block_num].requestSent > pitRequestTimeout)
                {
                    Cuckoo filter = new Cuckoo(txids.Count);
                    foreach (var tx in txids)
                    {
                        filter.Add(tx);
                    }
                    byte[] filter_bytes = filter.getFilterBytes();
                    MemoryStream m = new MemoryStream(filter_bytes.Length + 12);
                    using (BinaryWriter w = new BinaryWriter(m, Encoding.UTF8, true))
                    {
                        w.WriteIxiVarInt(block_num);
                        w.WriteIxiVarInt(filter_bytes.Length);
                        w.Write(filter_bytes);
                    }
                    CoreProtocolMessage.broadcastProtocolMessageToSingleRandomNode(new char[] { 'M', 'H' }, ProtocolMessageCode.getPIT2, m.ToArray(), 0);
                    PITCacheItem ci = new PITCacheItem()
                    {
                        pit = null,
                        requestedForTXIDs = txids,
                        requestSent = Clock.getTimestamp()
                    };
                    pitCache.AddOrReplace(block_num, ci);
                }
            }
        }

        private bool processBlockHeader(Block header)
        {
            if (lastBlockHeader != null && lastBlockHeader.blockChecksum != null && !header.lastBlockChecksum.SequenceEqual(lastBlockHeader.blockChecksum))
            {
                Logging.warn("TIV: Invalid last block checksum");

                // discard the block

                // TODO require previous block to get verifications from 3 nodes
                // if in verification mode, detect liar and flag him
                // below is an implementation that's good enough for now

                if (lastBlockHeader.blockNum > 100
                    && minBlockHeightReorg < lastBlockHeader.blockNum - 100)
                {
                    minBlockHeightReorg = lastBlockHeader.blockNum - 100;
                }

                Block prev_header = BlockHeaderStorage.getBlockHeader(minBlockHeightReorg);

                if(prev_header == null)
                {
                    return false;
                }

                lastBlockHeader = prev_header;

                ConsensusConfig.redactedWindowSize = ConsensusConfig.getRedactedWindowSize(lastBlockHeader.version);
                ConsensusConfig.minRedactedWindowSize = ConsensusConfig.getRedactedWindowSize(lastBlockHeader.version);

                return false;
            }

            if (!header.calculateChecksum().SequenceEqual(header.blockChecksum))
            {
                Logging.warn("TIV: Invalid block checksum");
                return false;
            }

            lastBlockHeader = header;

            ConsensusConfig.redactedWindowSize = ConsensusConfig.getRedactedWindowSize(lastBlockHeader.version);
            ConsensusConfig.minRedactedWindowSize = ConsensusConfig.getRedactedWindowSize(lastBlockHeader.version);

            if(BlockHeaderStorage.saveBlockHeader(lastBlockHeader))
            {
                if (pruneBlocks)
                {
                    // Cleanup every n blocks
                    if ((header.blockNum > CoreConfig.maxBlockHeadersPerDatabase * 5) && header.blockNum % CoreConfig.maxBlockHeadersPerDatabase == 0)
                    {
                        BlockHeaderStorage.removeAllBlocksBefore(header.blockNum - (CoreConfig.maxBlockHeadersPerDatabase * 5));
                    }
                }
            }

            IxianHandler.receivedBlockHeader(lastBlockHeader, true);

            return true;
        }

        /// <summary>
        /// When a response to a PIT request is received, this function validates and caches it so transactions may be verified in a separate thread.
        /// </summary>
        /// <param name="data">PIT response bytes.</param>
        /// <param name="endpoint">Neighbor, who sent this data.</param>
        public void receivedPIT2(byte[] data, RemoteEndpoint endpoint)
        {
            MemoryStream m = new MemoryStream(data);
            using (BinaryReader r = new BinaryReader(m))
            {
                ulong block_num = r.ReadIxiVarUInt();
                int len = (int)r.ReadIxiVarUInt();
                if (len > 0)
                {
                    byte[] pit_data = r.ReadBytes(len);
                    PrefixInclusionTree pit = new PrefixInclusionTree(44, 3);
                    try
                    {
                        pit.reconstructMinimumTree(pit_data);
                        Block h = BlockHeaderStorage.getBlockHeader(block_num);
                        if (h == null)
                        {
                            Logging.warn("TIV: Received PIT information for block {0}, but we do not have that block header in storage!", block_num);
                            return;
                        }
                        if (!h.receivedPitChecksum.SequenceEqual(pit.calculateTreeHash()))
                        {
                            Logging.error("TIV: Received PIT information for block {0}, but the PIT checksum does not match the one in the block header!", block_num);
                            // TODO: more drastic action? Maybe blacklist or something.
                            return;
                        }
                        lock (pitCache)
                        {
                            if (pitCache.ContainsKey(block_num))
                            {
                                Logging.info("TIV: Received valid PIT information for block {0}", block_num);
                                pitCache[block_num].pit = pit;
                            }
                        }
                    }
                    catch (Exception)
                    {
                        Logging.warn("TIV: Invalid or corrupt data received for block {0}.", block_num);
                    }
                }
            }
        }

        /// <summary>
        ///  Called when receiving multiple block headers at once from a remote endpoint
        /// </summary>
        /// <param name="data">byte array of received data</param>
        /// <param name="endpoint">corresponding remote endpoint</param>
        public void receivedBlockHeaders3(byte[] data, RemoteEndpoint endpoint)
        {
            using (MemoryStream m = new MemoryStream(data))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    bool processed = false;
                    try
                    {
                        int blockCnt = 0;
                        long startTime = Clock.getTimestampMillis();
                        while (m.Position < m.Length)
                        {
                            int header_len = (int)reader.ReadIxiVarUInt();
                            byte[] header_bytes = reader.ReadBytes(header_len);

                            lastRequestedBlockTime = Clock.getTimestamp();

                            // Create the blockheader from the data and process it
                            Block header = new Block(header_bytes, true);
                            if (lastBlockHeader != null && header.blockNum <= lastBlockHeader.blockNum)
                            {
                                continue;
                            }
                            if (!processBlockHeader(header))
                            {
                                break;
                            }
                            processed = true;
                            Thread.Yield();
                            blockCnt++;
                        }
                        Logging.info("Processed {0} block headers in {1}ms.", blockCnt, Clock.getTimestampMillis() - startTime);
                        if (processed)
                        {
                            updateBlockHeaders(true);
                            verifyUnprocessedTransactions();
                        }
                    }
                    catch (Exception e)
                    {
                        Logging.error("Exception occurred while processing block header: " + e);
                        // TODO blacklist sender
                        updateBlockHeaders(true);
                    }
                }
            }
        }

        private void requestBlockHeaders(ulong from, ulong count, RemoteEndpoint endpoint = null)
        {
            Logging.info("Requesting block headers from {0} to {1}", from, from + count);
            using (MemoryStream mOut = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(mOut))
                {
                    writer.WriteIxiVarInt(from);
                    writer.WriteIxiVarInt(count);
                }

                if (endpoint != null)
                {
                    endpoint.sendData(ProtocolMessageCode.getBlockHeaders3, mOut.ToArray());
                }
                else
                {
                    // Request from a single random node
                    CoreProtocolMessage.broadcastProtocolMessageToSingleRandomNode(new char[] { 'M', 'H', 'R' }, ProtocolMessageCode.getBlockHeaders3, mOut.ToArray(), 0);
                }
            }
        }

        private void prunePITCache()
        {
            lock (txQueue)
            {
                lock (pitCache)
                {
                    List<ulong> to_remove = new List<ulong>();
                    foreach (var i in pitCache)
                    {
                        if (i.Value.requestedForTXIDs.Intersect(txQueue.Values.Select(tx => tx.id), new ByteArrayComparer()).Any())
                        {
                            // PIT cache item is still needed
                        }
                        else
                        {
                            to_remove.Add(i.Key);
                        }
                    }
                    foreach(ulong b_num in to_remove)
                    {
                        pitCache.Remove(b_num);
                    }
                }
            }
        }

        public Block getLastBlockHeader()
        {
            return lastBlockHeader;
        }

        public void clearCache()
        {
            lock (txQueue)
            {
                txQueue.Clear();
                lock (pitCache)
                {
                    pitCache.Clear();
                }
            }
        }

        public void requestNewBlockHeaders(ulong blockNum, RemoteEndpoint endpoint)
        {
            if (blockNum <= lastBlockHeader.blockNum)
            {
                return;
            }

            updateBlockHeaders(true, endpoint);
            verifyUnprocessedTransactions();
        }
    }
}

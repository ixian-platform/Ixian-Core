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

using IXICore.Activity;
using IXICore.Inventory;
using IXICore.Meta;
using IXICore.Network;
using IXICore.Storage;
using IXICore.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;

namespace IXICore
{
    public enum TIVBlockVerificationMode
    {
        /// <summary>
        /// Minimal verification, only basic checks (version, previous block hash, timestamp) are performed. No signature or PoW
        /// verification is performed. This mode uses minimal bandwidth as only superblocks contain the full signature set.
        /// </summary>
        Minimal = 0,
        /// <summary>
        /// Verification of PoW is performed, but the signatures are not included. This mode uses more bandwidth than Minimal,
        /// as all blocks contain the PoW signature set without actual PK signatures, but it allows for better security against
        /// malicious nodes sending invalid blocks with fake transactions.
        /// </summary>
        PoCW = 1,
        /// <summary>
        /// Full verification of signatures is performed. This mode uses even more bandwidth than PoCW as it contains full
        /// signature sets.
        /// </summary>
        Signatures = 2,
        /// <summary>
        /// Full verification of signatures is performed. Blocks contain full signatures and a full list of txids included in the
        /// block, not just the merkle/PIT root. This mode uses the most bandwidth and is generally not intended for end-clients.
        /// </summary>
        Transactions = 3
    }

    public interface TransactionInclusionCallbacks
    {
        public void receivedBlockHeader(Block blockHeader, bool verified);
        public void transactionVerified(Transaction tx);
        public void transactionRejected(Transaction tx);
        public void transactionExpired(Transaction tx);
        public void blockReorg(Block blockHeader);
    }

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
        private Thread? tiv_thread = null;
        private bool running = false;

        SortedList<ulong, PITCacheItem> pitCache = new SortedList<ulong, PITCacheItem>();
        long pitRequestTimeout = 5; // timeout (seconds) before PIT for a specific block is re-requested
        long pitCachePruneInterval = 30; // interval how often pit cache is checked and uninteresting entries removed (to save memory)

        Block? lastBlockHeader = null;

        long lastRequestedBlockTime = 0;
        long lastPITPruneTime = 0;

        ulong minBlockHeightReorg = 0;

        bool pruneBlocks = true;

        ulong startingBlockHeight = 0;
        byte[]? startingBlockChecksum = null;

        public ulong blockHeadersToRequestInChunk = 250;

        private TransactionInclusionCallbacks transactionInclusionCallbacks;

        private TIVBlockVerificationMode blockVerificationMode;

        private IStorage blockStorage;

        public TransactionInclusion(IStorage blockStorage, TransactionInclusionCallbacks transactionInclusionCallbacks, TIVBlockVerificationMode blockVerificationMode)
        {
            this.transactionInclusionCallbacks = transactionInclusionCallbacks;
            this.blockStorage = blockStorage;
            this.blockVerificationMode = blockVerificationMode;
        }

        public void start(ulong starting_block_height, byte[]? starting_block_checksum, bool pruneBlocks = true)
        {
            if (running)
            {
                return;
            }

            running = true;
            this.pruneBlocks = pruneBlocks;

            startingBlockHeight = starting_block_height;
            startingBlockChecksum = starting_block_checksum;

            // Start the thread
            tiv_thread = new Thread(onUpdate);
            tiv_thread.Name = "TIV_Update_Thread";
            tiv_thread.Start();
        }

        public void onUpdate()
        {
            try
            {
                Block? last_block_header = blockStorage.getBlock(blockStorage.getHighestBlockInStorage());

                if (last_block_header != null && last_block_header.blockNum > startingBlockHeight)
                {
                    lastBlockHeader = last_block_header;
                }
                else
                {
                    blockStorage.stopStorage();
                    blockStorage.deleteData();
                    blockStorage.prepareStorage(false);
                    lastBlockHeader = new Block() { blockNum = startingBlockHeight, blockChecksum = startingBlockChecksum };
                }

                while (running)
                {
                    if (requestBlockHeaders())
                    {
                        processUnverifiedTransactions();
                        processOutgoingTransactions();
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

            // Force stopping of thread
            if (tiv_thread == null)
                return;

            tiv_thread.Interrupt();
            tiv_thread.Join();
            tiv_thread = null;
        }

        private bool requestBlockHeaders(bool force_update = false, RemoteEndpoint endpoint = null)
        {
            long currentTime = Clock.getTimestamp();

            // Check if the request expired
            if (force_update || currentTime - lastRequestedBlockTime > ConsensusConfig.blockGenerationInterval)
            {
                lastRequestedBlockTime = currentTime;

                // request next blocks
                requestBlockHeaders(lastBlockHeader!.blockNum + 1, blockHeadersToRequestInChunk, endpoint);

                return true;
            }

            return false;
        }

        private void processUnverifiedTransactions()
        {
            if(lastBlockHeader == null)
            {
                return;
            }
            lock (pitCache)
            {
                var tmp_txQueue = PendingTransactions.getPendingTransactions().Where(x => x.blockHeight <= lastBlockHeader.blockNum).ToArray();
                foreach(var tx in tmp_txQueue)
                {
                    if (tx.applied == 0)
                    {
                        tx.applied = tx.blockHeight;
                    }
                    Block? bh = blockStorage.getBlock(tx.applied);
                    if(bh is null)
                    {
                        // TODO: need to wait for the block to arrive, or re-request
                        // maybe something similar to PIT cache, or extend PIT cache to handle older blocks, too
                        continue;
                    }
                    if (bh.version < BlockVer.v6)
                    {
                        if (bh.transactions.Contains(tx.id, new ByteArrayComparer()))
                        {
                            // valid
                            transactionInclusionCallbacks.transactionVerified(tx);
                            PendingTransactions.remove(tx.id);
                        }
                        else
                        {
                            // not in this block
                            tx.applied++;
                        }
                    }
                    else
                    {
                        // check if we already have the partial tree for this transaction
                        if (pitCache.ContainsKey(tx.applied) && pitCache[tx.applied].pit != null)
                        {
                            // Note: PIT has been verified against the block header when it was received, so additional verification is not needed here.
                            // Note: the PIT we have cached might have been requested for different txids (the current txid could have been added later)
                            // For that reason, the list of TXIDs we requested is stored together with the cached PIT
                            byte[] txid;
                            if (bh.version < BlockVer.v8)
                            {
                                txid = UTF8Encoding.UTF8.GetBytes(tx.getTxIdString());
                            }else
                            {
                                txid = tx.id;
                            }
                            if (pitCache[tx.applied].requestedForTXIDs.Contains(tx.id, new ByteArrayComparer()))
                            {
                                if (pitCache[tx.applied].pit.contains(txid))
                                {
                                    // valid
                                    transactionInclusionCallbacks.transactionVerified(tx);
                                    PendingTransactions.remove(tx.id);
                                }
                                else
                                {
                                    // not in this block
                                    tx.applied++;
                                }
                            }
                            else
                            {
                                // PIT cache for the correct block exists, but it was originally requested for different txids
                                // we have to re-request it for any remaining txids in the queue. (We do not need to request the already-verified ids)
                                requestPITForBlock(tx.applied,
                                    PendingTransactions.pendingTransactions.Values
                                        .Where(x => x.transaction.applied == tx.applied && x.transaction.applied <= lastBlockHeader.blockNum)
                                        .Select(x => x.transaction.id)
                                        .ToList());
                                continue;
                            }
                        }
                        else
                        {
                            // PIT cache has not been received yet, or maybe it has never been requested for this block
                            requestPITForBlock(tx.applied,
                                PendingTransactions.pendingTransactions.Values
                                    .Where(x => x.transaction.applied == tx.applied && x.transaction.applied <= lastBlockHeader.blockNum)
                                    .Select(x => x.transaction.id)
                                    .ToList());
                        }
                    }
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

                    char[] node_types = new char[] { 'M', 'H' };
                    if (PresenceList.myPresenceType == 'C')
                    {
                        node_types = new char[] { 'M', 'H', 'R' };
                    }
                    CoreProtocolMessage.broadcastProtocolMessageToSingleRandomNode(node_types, ProtocolMessageCode.getPIT2, m.ToArray(), 0);

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

        /// <summary>
        /// - Check previous block hash
        /// - Check version
        /// - Check signer bits (if superblock)
        /// - Check superblock segments (if superblock)
        /// - Check timestamp (with some tolerance, to prevent time manipulation)
        /// - Verify signatures
        /// - Check signature count
        /// - Check total difficulty
        /// - Check sigfreeze checksum
        /// </summary>
        /// <param name="header"></param>
        /// <param name="previousBlockHeader"></param>
        /// <returns></returns>
        private bool verifyBlockHeader(Block header, Block? previousBlockHeader)
        {
            if (header.version < IxianHandler.getLastBlockVersion())
            {
                Logging.error("TIV: Invalid block header version. Block number: {0} - {1}", header.blockNum, Crypto.hashToString(header.blockChecksum));
                return false;
            }

            // Advanced verification for Blocks v10+
            if (header.version < BlockVer.v10)
            {
                return true;
            }

            if (header.timestamp + ConsensusConfig.minBlockTimeDifference < previousBlockHeader.timestamp)
            {
                Logging.error("TIV: Invalid block header timestamp. Block number: {0} - {1}", header.blockNum, Crypto.hashToString(header.blockChecksum));
                return false;
            }

            populateBlockSignatures(header);

            //return true;

            /*if (header.signatures != null
                && !header.verifySignatures(null, false))
            {
                Logging.error("TIV: Invalid block header signature. Block number: {0} - {1}", header.blockNum, Crypto.hashToString(header.blockChecksum));
                return false;
            }*/

            // Signature difficulty verification
            Block? lastSuperBlock = null;
            bool isSuperBlock = header.blockNum % ConsensusConfig.superblockInterval == 0;
            if (isSuperBlock)
            {
                lastSuperBlock = blockStorage.getBlock(header.blockNum - ConsensusConfig.superblockInterval);
                if (lastSuperBlock != null)
                {
                    if (SignerPowSolution.bitsToDifficulty(header.signerBits) > SignerPowSolution.bitsToDifficulty(lastSuperBlock.signerBits) * 4)
                    {
                        Logging.error("TIV: Block header signer difficulty is too high compared to the previous superblock. Block number: {0} - {1}", header.blockNum, Crypto.hashToString(header.blockChecksum));
                        return false;
                    }
                    else if (SignerPowSolution.bitsToDifficulty(header.signerBits) < SignerPowSolution.bitsToDifficulty(lastSuperBlock.signerBits) / 4)
                    {
                        Logging.error("TIV: Block header signer difficulty is too low compared to the previous superblock. Block number: {0} - {1}", header.blockNum, Crypto.hashToString(header.blockChecksum));
                        return false;
                    }
                    // TODO verify sig count
                }
            }
            else
            {
                lastSuperBlock = blockStorage.getBlock((header.blockNum / ConsensusConfig.superblockInterval) * ConsensusConfig.superblockInterval);
                // TODO verify sig count
            }

            if (lastSuperBlock != null)
            {
                var requiredDifficulty = (SignerPowSolution.bitsToDifficulty(lastSuperBlock.signerBits) * ConsensusConfig.networkSignerDifficultyConsensusRatio) / 100;
                if (header.getTotalSignerDifficulty() < requiredDifficulty)
                {
                    Logging.error("TIV: Block header does not meet minimum signer difficulty. Block number: {0} - {1}", header.blockNum, Crypto.hashToString(header.blockChecksum));
                    return false;
                }
            }
            //
            return true;
        }

        private void populateBlockSignatures(Block header)
        {
            bool isSuperBlock = header.blockNum % ConsensusConfig.superblockInterval == 0;
            if (isSuperBlock)
            {
                foreach (var sig in header.signatures)
                {
                    sig.powSolution.blockHash = header.superBlockSegments[sig.powSolution.blockNum].blockChecksum;
                }
            }
            else
            {
                Block? lastSuperBlock = blockStorage.getBlock((header.blockNum / ConsensusConfig.superblockInterval) * ConsensusConfig.superblockInterval);
                foreach (var sig in header.signatures)
                {
                    lastSuperBlock.superBlockSegments.TryGetValue(sig.powSolution.blockNum, out SuperBlockSegment? seg);
                    sig.powSolution.blockHash = seg?.blockChecksum;
                    if (sig.powSolution.blockHash == null)
                    {
                        sig.powSolution.blockHash = IxianHandler.getBlockHash(sig.powSolution.blockNum);
                    }
                }
            }
        }

        private bool processBlockHeader(Block header)
        {
            if (lastBlockHeader != null
                && lastBlockHeader.blockChecksum != null
                && !header.lastBlockChecksum.SequenceEqual(lastBlockHeader.blockChecksum))
            {
                Logging.warn("TIV: Invalid last block checksum");

                // revert the block

                if (!verifyBlockHeader(header, null))
                {
                    Logging.error("TIV: Invalid block header received, and it failed verification. Block number: {0} - {1}", header.blockNum, Crypto.hashToString(header.blockChecksum));
                    return false;
                }

                if (lastBlockHeader.blockNum > 100
                    && minBlockHeightReorg < lastBlockHeader.blockNum - 100)
                {
                    minBlockHeightReorg = lastBlockHeader.blockNum - 100;
                }

                if (minBlockHeightReorg >= lastBlockHeader.blockNum)
                {
                    Logging.error("TIV: Reorg detected, but the block height reorg limit was reached. Please resolve manually. Block number: {0}, min reorg height: {1}", lastBlockHeader.blockNum, minBlockHeightReorg);
                    return false;
                }

                Block? prev_header = blockStorage.getBlock(lastBlockHeader.blockNum - 1);

                if(prev_header == null)
                {
                    return false;
                }

                lastBlockHeader = prev_header;

                ConsensusConfig.redactedWindowSize = ConsensusConfig.getRedactedWindowSize(lastBlockHeader.version);
                ConsensusConfig.minRedactedWindowSize = ConsensusConfig.getRedactedWindowSize(lastBlockHeader.version);

                transactionInclusionCallbacks.blockReorg(lastBlockHeader);

                return false;
            }

            if (!verifyBlockHeader(header, lastBlockHeader))
            {
                Logging.error("TIV: Invalid block header received, and it failed verification. Block number: {0} - {1}", header.blockNum, Crypto.hashToString(header.blockChecksum));
                return false;
            }

            if (blockStorage.insertBlock(header))
            {
                lastBlockHeader = header;

                ConsensusConfig.redactedWindowSize = ConsensusConfig.getRedactedWindowSize(lastBlockHeader.version);
                ConsensusConfig.minRedactedWindowSize = ConsensusConfig.getRedactedWindowSize(lastBlockHeader.version);

                if (pruneBlocks)
                {
                    // Cleanup every n blocks
                    if ((header.blockNum > CoreConfig.maxBlockHeadersPerDatabase * 11)
                        && header.blockNum % CoreConfig.maxBlockHeadersPerDatabase == 0)
                    {
                        blockStorage.redactBlockStorage(header.blockNum - (CoreConfig.maxBlockHeadersPerDatabase * 11));
                    }
                }

                transactionInclusionCallbacks.receivedBlockHeader(lastBlockHeader, true);

                return true;
            }

            return false;
        }

        /// <summary>
        /// When a response to a PIT request is received, this function validates and caches it so transactions may be verified in a separate thread.
        /// </summary>
        /// <param name="data">PIT response bytes.</param>
        /// <param name="endpoint">Neighbor, who sent this data.</param>
        public void receivedPIT2(byte[] data, RemoteEndpoint endpoint)
        {
            using (MemoryStream m = new MemoryStream(data))
            {
                using (BinaryReader r = new BinaryReader(m))
                {
                    ulong block_num = r.ReadIxiVarUInt();
                    if (!pitCache.ContainsKey(block_num))
                    {
                        return;
                    }
                    Block? h = blockStorage.getBlock(block_num);
                    if (h == null)
                    {
                        Logging.warn("TIV: Received PIT information for block {0}, but we do not have that block header in storage!", block_num);
                        return;
                    }
                    int len = (int)r.ReadIxiVarUInt();
                    if (len > 0)
                    {
                        byte[] pit_data = r.ReadBytes(len);
                        PrefixInclusionTree pit = new PrefixInclusionTree(44, 3);
                        try
                        {
                            pit.reconstructMinimumTree(pit_data);
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

                            if (InventoryCache.Instance != null)
                            {
                                InventoryCache.Instance.setProcessedFlag(InventoryItemTypes.block, header.blockChecksum);
                            }

                            if (lastBlockHeader != null && header.blockNum <= lastBlockHeader.blockNum)
                            {
                                continue;
                            }
                            if (!processBlockHeader(header))
                            {
                                break;
                            }
                            processed = true;
                            blockCnt++;
                        }
                        Logging.info("Processed {0} block headers in {1}ms.", blockCnt, Clock.getTimestampMillis() - startTime);
                        if (processed)
                        {
                            requestBlockHeaders(true);
                            processUnverifiedTransactions();
                            processOutgoingTransactions();
                        }
                    }
                    catch (Exception e)
                    {
                        Logging.error("Exception occurred while processing block header: " + e);
                        // TODO blacklist sender
                        requestBlockHeaders(true);
                    }
                }
            }
        }

        private void requestBlockHeaders(ulong from, ulong count, RemoteEndpoint? endpoint = null)
        {
            Logging.info("Requesting block headers from {0} to {1}", from, from + count);
            using (MemoryStream mOut = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(mOut))
                {
                    writer.WriteIxiVarInt(from);
                    writer.WriteIxiVarInt(count);
                    Cuckoo filter = CoreProtocolMessage.getMyAddressesCuckooFilter();
                    byte[] filterBytes = filter.getFilterBytes();
                    writer.WriteIxiVarInt(filterBytes.Length);
                    writer.Write(filterBytes);
                    writer.WriteIxiVarInt((int)blockVerificationMode);
                }

                if (endpoint != null)
                {
                    endpoint.sendData(ProtocolMessageCode.getRelevantBlockTransactions, mOut.ToArray());
                }
                else
                {
                    // Request from a single random node
                    char[] node_types = new char[] { 'M', 'H' };
                    if (PresenceList.myPresenceType == 'C')
                    {
                        node_types = new char[] { 'M', 'H', 'R' };
                    }
                    CoreProtocolMessage.broadcastProtocolMessageToSingleRandomNode(node_types, ProtocolMessageCode.getRelevantBlockTransactions, mOut.ToArray(), 0);
                }
            }
        }

        private void prunePITCache()
        {
            lock (pitCache)
            {
                List<ulong> to_remove = new List<ulong>();
                foreach (var i in pitCache)
                {
                    if (i.Value.requestedForTXIDs.Intersect(PendingTransactions.getAllPendingTxids(), new ByteArrayComparer()).Any())
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

        public Block? getLastBlockHeader()
        {
            return lastBlockHeader;
        }

        public void clearCache()
        {
            lock (pitCache)
            {
                pitCache.Clear();
            }
        }

        public void requestNewBlockHeaders(ulong blockNum, RemoteEndpoint endpoint)
        {
            if (blockNum <= lastBlockHeader!.blockNum)
            {
                return;
            }

            requestBlockHeaders(true, endpoint);
        }

        private void processOutgoingTransactions()
        {
            ulong last_block_height = IxianHandler.getLastBlockHeight();
            lock (PendingTransactions.pendingTransactions)
            {
                long cur_time = Clock.getTimestamp();
                List<PendingTransaction> tmp_pending_transactions = new(PendingTransactions.pendingTransactions.Values);
                foreach (var entry in tmp_pending_transactions)
                {
                    long tx_time = entry.addedTimestamp;

                    if (entry.transaction.blockHeight > last_block_height)
                    {
                        // not ready yet, syncing to the network
                        continue;
                    }

                    Transaction t = entry.transaction;

                    // if transaction expired, remove it from pending transactions
                    if (last_block_height > ConsensusConfig.getRedactedWindowSize()
                        && t.blockHeight < last_block_height - ConsensusConfig.getRedactedWindowSize())
                    {
                        Logging.error("Error sending the transaction {0}, expired", t.getTxIdString());
                        transactionInclusionCallbacks.transactionExpired(t);
                        PendingTransactions.remove(t.id);
                        continue;
                    }

                    if (entry.rejectedNodeList.Count() > 3
                        && entry.rejectedNodeList.Count() > entry.confirmedNodeList.Count())
                    {
                        Logging.error("Error sending the transaction {0}, rejected", t.getTxIdString());
                        transactionInclusionCallbacks.transactionRejected(t);
                        PendingTransactions.remove(t.id);
                        continue;
                    }

                    if (cur_time - tx_time > 60) // if the transaction is pending for over 60 seconds, resend
                    {
                        Logging.warn("Transaction {0} pending for a while, resending", t.getTxIdString());
                        entry.addedTimestamp = cur_time;

                        if (!entry.outgoing)
                        {
                            continue;
                        }

                        if (entry.relayNodeAddresses != null)
                        {
                            foreach (var address in entry.relayNodeAddresses)
                            {
                                NetworkClientManager.sendToClient(address, ProtocolMessageCode.transactionData2, t.getBytes(true, true), null);
                            }
                        }
                        else
                        {
                            CoreProtocolMessage.broadcastProtocolMessage(new char[] { 'M', 'H' }, ProtocolMessageCode.transactionData2, t.getBytes(true, true), null);
                        }
                    }
                }
            }
        }
    }
}

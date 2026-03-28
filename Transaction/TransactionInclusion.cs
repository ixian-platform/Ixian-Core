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

using IXICore.Inventory;
using IXICore.Meta;
using IXICore.Network;
using IXICore.Storage;
using IXICore.Utils;
using System.Text;

namespace IXICore
{
    class RequiredSignerDifficultyCache
    {
        public ulong BlockNum = 0;
        public int BlockVersion = 0;
        public IxiNumber Difficulty = 0;
        public long Timestamp = 0;

        public void Set(ulong blockNum, int blockVersion, IxiNumber difficulty, long timestamp)
        {
            BlockNum = blockNum;
            BlockVersion = blockVersion;
            Difficulty = difficulty;
            Timestamp = timestamp;
        }
    }

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
        /// Full verification of signatures is performed. This mode uses even more bandwidth than PoCW as block headers contain
        /// full signature sets (if available).
        /// </summary>
        Signatures = 2,
        /// <summary>
        /// Full verification of signatures is performed. Blocks contain full signatures (if available) and a full list of txids
        /// included in the block, not just the merkle/PIT root. This mode uses the most bandwidth and is generally not intended
        /// for end-clients.
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

        private RequiredSignerDifficultyCache cachedRequiredSignerDifficulty = new();

        private object tivLock = new object();

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

                if (last_block_header != null)
                {
                    lastBlockHeader = last_block_header;
                }
                else
                {
                    blockStorage.stopStorage();
                    blockStorage.deleteData();
                    blockStorage.prepareStorage(false);
                    lastBlockHeader = new Block() { blockNum = startingBlockHeight, blockChecksum = startingBlockChecksum! };
                }

                while (running)
                {
                    if (requestBlockHeaders())
                    {
                        processUnverifiedTransactions();
                        processOutgoingTransactions();
                    }

                    long currentTime = Clock.getTimestamp();
                    if (currentTime - lastPITPruneTime > pitCachePruneInterval)
                    {
                        prunePITCache();
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
            if (!running)
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

        private bool requestBlockHeaders(bool force_update = false, RemoteEndpoint? endpoint = null)
        {
            long currentTime = Clock.getTimestamp();

            // Check if the request expired
            if (force_update || currentTime - lastRequestedBlockTime > ConsensusConfig.blockGenerationInterval)
            {
                lastRequestedBlockTime = currentTime;

                // request next blocks
                if (lastBlockHeader!.blockNum > 0
                    && lastBlockHeader.version == 0)
                {
                    requestBlockHeaders(lastBlockHeader.blockNum, blockHeadersToRequestInChunk, CoreProtocolMessage.getMyAddressesCuckooFilter(), endpoint);
                }
                else
                {
                    requestBlockHeaders(lastBlockHeader.blockNum + 1, blockHeadersToRequestInChunk, CoreProtocolMessage.getMyAddressesCuckooFilter(), endpoint);
                }

                return true;
            }

            return false;
        }

        private void processUnverifiedTransactions()
        {
            if (lastBlockHeader == null)
            {
                return;
            }
            lock (PendingTransactions.pendingTransactions)
            {
                var tmp_txQueue = PendingTransactions.getPendingTransactions().Where(x => x.blockHeight <= lastBlockHeader.blockNum).ToArray();
                foreach (var tx in tmp_txQueue)
                {
                    if (tx.applied == 0)
                    {
                        tx.applied = tx.blockHeight;
                    }
                    Block? bh = blockStorage.getBlock(tx.applied);
                    if (bh is null)
                    {
                        // TODO: need to wait for the block to arrive, or re-request
                        // maybe something similar to PIT cache, or extend PIT cache to handle older blocks, too
                        continue;
                    }
                    if (bh.version < BlockVer.v6
                        || blockVerificationMode == TIVBlockVerificationMode.Transactions)
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
                            }
                            else
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
            return;
            lock (pitCache)
            {
                long currentTime = Clock.getTimestamp();
                // Request might already have been sent. In that case, we re-send it we have been waiting for too long.
                if (!pitCache.ContainsKey(block_num) || currentTime - pitCache[block_num].requestSent > pitRequestTimeout)
                {
                    Cuckoo filter = new Cuckoo(txids.Count);
                    foreach (var tx in txids)
                    {
                        filter.Add(tx);
                    }
                    byte[] filter_bytes = filter.getFilterBytes();
                    using (MemoryStream m = new MemoryStream(filter_bytes.Length + 12))
                    using (BinaryWriter w = new BinaryWriter(m))
                    {
                        w.WriteIxiVarInt(block_num);
                        w.WriteIxiVarInt(filter_bytes.Length);
                        w.Write(filter_bytes);

                        char[] node_types = new char[] { 'M', 'H' };
                        if (PresenceList.myPresenceType == 'C')
                        {
                            node_types = new char[] { 'M', 'H', 'R' };
                        }
                        CoreProtocolMessage.broadcastProtocolMessageToSingleRandomNode(node_types, ProtocolMessageCode.getPIT2, m.ToArray(), 0);
                    }

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

        private bool isSigRecoveryMode()
        {
            return false;
        }

        private int getMinRequiredSigCount(Block header, bool adjustToRatio)
        {
            if (header.blockNum <= ConsensusConfig.averageSigCalculationBlockCount + ConsensusConfig.requiredConsensusOffset)
            {
                return 1;
            }
            int blockCount = 0;
            int totalSigCount = 0;
            for (ulong i = 0; i < ConsensusConfig.averageSigCalculationBlockCount; i++)
            {
                ulong consensusBlockNum = header.blockNum - i - ConsensusConfig.requiredConsensusOffset;
                Block? block = blockStorage.getBlock(consensusBlockNum);
                if (block == null)
                {
                    Logging.warn("TIV: Cannot get min required signatures for block {0} - {1} because one of the blocks from which to check the signatures is not available in storage.", header.blockNum, Crypto.hashToString(header.blockChecksum));
                    return 1;
                }
                totalSigCount += block.getFrozenSignatureCount();
                blockCount++;
            }

            if (blockCount == 0)
            {
                return ConsensusConfig.maximumBlockSigners;
            }

            int consensus = (int)Math.Ceiling((double)totalSigCount / blockCount);

            if (consensus > ConsensusConfig.maximumBlockSigners)
            {
                consensus = ConsensusConfig.maximumBlockSigners;
                if (adjustToRatio)
                {
                    consensus = (int)Math.Floor(consensus * ConsensusConfig.networkSignerConsensusRatio);
                }
            }
            else
            {
                if (adjustToRatio)
                {
                    consensus = (int)Math.Floor(totalSigCount / blockCount * ConsensusConfig.networkSignerConsensusRatio);
                }
            }

            if (consensus < 2)
            {
                consensus = 2;
            }

            return consensus;
        }

        private int getOverlappingSigCount(Block header)
        {
            if (header.blockNum <= ConsensusConfig.sigOverlapOffset)
            {
                return 1;
            }
            int overlappedSigCount = 0;
            Block? block = blockStorage.getBlock(header.blockNum - ConsensusConfig.sigOverlapOffset);
            if (block == null)
            {
                Logging.warn("TIV: Cannot verify overlapping signatures for block {0} - {1} because the block from which to check the overlapping signatures is not available in storage.", header.blockNum, Crypto.hashToString(header.blockChecksum));
                return header.getFrozenSignatureCount();
            }
            // Minimal verification mode or when upgrading from minimal
            if (blockVerificationMode == TIVBlockVerificationMode.Minimal
                || block.signatures.Count == 0)
            {
                return header.getFrozenSignatureCount();
            }
            foreach (var sig in header.signatures)
            {
                if (block.containsSignature(sig.recipientPubKeyOrAddress))
                {
                    overlappedSigCount++;
                }
            }
            return overlappedSigCount;
        }

        private bool verifySigfreezeChecksum(Block header)
        {
            Block? targetBlock = blockStorage.getBlock(header.blockNum - ConsensusConfig.sigfreezeOffset);
            if (targetBlock == null)
            {
                // We don't have the full blockchain history, so we cannot verify the sigfreeze checksum.
                // In this case, we will just skip the verification to avoid blocking the chain sync.
                return true;
            }

            if (!targetBlock.calculateSignatureChecksum().SequenceEqual(header.signatureFreezeChecksum))
            {
                return false;
            }

            return true;
        }

        private bool verifyTimestamp(Block header, Block? previousBlockHeader)
        {
            if (header.timestamp > Clock.getNetworkTimestamp())
            {
                Logging.error("TIV: Invalid block header timestamp. Block number: {0} - {1}", header.blockNum, Crypto.hashToString(header.blockChecksum));
                return false;
            }

            if (previousBlockHeader != null
                && header.timestamp + ConsensusConfig.minBlockTimeDifference < previousBlockHeader.timestamp)
            {
                Logging.error("TIV: Invalid block header timestamp. Block number: {0} - {1}", header.blockNum, Crypto.hashToString(header.blockChecksum));
                return false;
            }

            return true;
        }

        private bool verifyBlockSignatures(Block header)
        {
            // Signature verification for Blocks v13+
            if (header.version < BlockVer.v13)
            {
                return true;
            }

            bool isSuperBlock = this.isSuperBlock(header.blockNum);

            Block? lastSuperBlock = null;
            if (isSuperBlock)
            {
                var expectedDifficulty = getRequiredSignerDifficulty(header.blockNum, false, header.version, header.timestamp);
                if (expectedDifficulty == null)
                {
                    Logging.warn("TIV: Failed to calculate expected signer difficulty for block header. Block number: {0} - {1}", header.blockNum, Crypto.hashToString(header.blockChecksum));
                    return true;
                }
                lastSuperBlock = blockStorage.getBlock(header.blockNum - ConsensusConfig.superblockInterval);
            }
            else
            {
                lastSuperBlock = blockStorage.getBlock((header.blockNum / ConsensusConfig.superblockInterval) * ConsensusConfig.superblockInterval);
            }

            if (isSuperBlock || blockVerificationMode != TIVBlockVerificationMode.Minimal)
            {
                if (header.signatures.Count == 0)
                {
                    Logging.error("TIV: Block header does not contain signatures. Block number: {0} - {1}", header.blockNum, Crypto.hashToString(header.blockChecksum));
                    return false;
                }
                if (header.blockNum > 1)
                {
                    populateBlockSignatures(header);
                    IxiNumber minPowDifficulty = IxianHandler.getMinSignerPowDifficulty(header.blockNum, header.version, header.timestamp);
                    bool skipSigVerification = !isSuperBlock && blockVerificationMode == TIVBlockVerificationMode.PoCW;
                    if (header.signatures.Count == 0
                        || !header.verifySignatures(null, minPowDifficulty, false, skipSigVerification))
                    {
                        Logging.error("TIV: Invalid block header signature. Block number: {0} - {1}", header.blockNum, Crypto.hashToString(header.blockChecksum));
                        return false;
                    }
                }
            }

            int minRequiredSigCount = getMinRequiredSigCount(header, true);
            int frozenSigCount = header.getFrozenSignatureCount();
            var totalSignerDifficulty = header.getTotalSignerDifficulty();
            var overlappingSigCount = getOverlappingSigCount(header);
            if (frozenSigCount < minRequiredSigCount
                && !handleBlockchainRecoveryMode(header, overlappingSigCount, frozenSigCount, totalSignerDifficulty, getRequiredSignerDifficulty(header.blockNum, false, header.version, header.timestamp)))
            {
                Logging.error("TIV: Block header does not contain enough frozen signatures. Block number: {0} - {1}", header.blockNum, Crypto.hashToString(header.blockChecksum));
                return false;
            }

            int requiredOverlappingSigs = 1;
            if (minRequiredSigCount > 1)
            {
                requiredOverlappingSigs = (minRequiredSigCount / 2) + 1;
            }
            if (overlappingSigCount < requiredOverlappingSigs)
            {
                Logging.error("TIV: Block header does not contain enough overlapping signatures. Block number: {0} - {1}", header.blockNum, Crypto.hashToString(header.blockChecksum));
                return false;
            }

            // Signature difficulty verification
            if (lastSuperBlock != null)
            {
                var requiredDifficulty = (SignerPowSolution.bitsToDifficulty(lastSuperBlock.signerBits) * ConsensusConfig.networkSignerDifficultyConsensusRatio) / 100;
                if (totalSignerDifficulty < requiredDifficulty)
                {
                    Logging.error("TIV: Block header does not meet minimum signer difficulty. Block number: {0} - {1}", header.blockNum, Crypto.hashToString(header.blockChecksum));
                    return false;
                }
            }
            return true;
        }

        /// <summary>
        /// - Check previous block hash
        /// - Check version
        /// - Check timestamp
        /// - Check sigfreeze checksum
        /// - Check last superblock hash and number (if superblock)
        /// - Check signer bits (if superblock)
        /// - TODO Check superblock segments (if superblock)
        /// - Check signatures
        /// - Check overlapping signer count
        /// - Check signature count
        /// - Check total difficulty
        /// </summary>
        /// <param name="header"></param>
        /// <param name="previousBlockHeader"></param>
        /// <returns></returns>
        private bool verifyBlockHeader(Block header, Block? previousBlockHeader)
        {
            if (header.version < getLastBlockHeader()?.version)
            {
                Logging.error("TIV: Invalid block header version. Block number: {0} - {1}", header.blockNum, Crypto.hashToString(header.blockChecksum));
                return false;
            }

            if (header.blockNum > ConsensusConfig.rewardMaturity + 1
                && blockVerificationMode == TIVBlockVerificationMode.Transactions)
            {
                if (header.transactions.Count == 0)
                {
                    Logging.error("TIV: Block header does not contain transactions, but transaction verification mode is enabled. Block number: {0} - {1}", header.blockNum, Crypto.hashToString(header.blockChecksum));
                    return false;
                }
            }

            if (blockVerificationMode != TIVBlockVerificationMode.Minimal
                && !verifySigfreezeChecksum(header))
            {
                Logging.warn("TIV: Invalid block header sigfreeze checksum. Block number: {0} - {1}", header.blockNum, Crypto.hashToString(header.blockChecksum));
                requestBlockHeaders(header.blockNum - ConsensusConfig.sigfreezeOffset, 1, null);

                return false;
            }

            // Advanced verification for Blocks v13+
            if (header.version < BlockVer.v13)
            {
                return true;
            }

            if (!verifyTimestamp(header, previousBlockHeader))
            {
                Logging.error("TIV: Invalid block header timestamp. Block number: {0} - {1}", header.blockNum, Crypto.hashToString(header.blockChecksum));
                return false;
            }

            bool isSuperBlock = this.isSuperBlock(header.blockNum);

            Block? lastSuperBlock = null;
            if (isSuperBlock)
            {
                lastSuperBlock = blockStorage.getBlock(header.blockNum - ConsensusConfig.superblockInterval);
                if (lastSuperBlock != null)
                {
                    if (lastSuperBlock.blockNum != header.lastSuperBlockNum
                        || !lastSuperBlock.blockChecksum.SequenceEqual(header.lastSuperBlockChecksum))
                    {
                        Logging.error("TIV: Invalid block header last superblock checksum. Block number: {0} - {1}", header.blockNum, Crypto.hashToString(header.blockChecksum));
                        return false;
                    }
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
                    if (blockVerificationMode != TIVBlockVerificationMode.Minimal)
                    {
                        var expectedDifficulty = getRequiredSignerDifficulty(header.blockNum, false, header.version, header.timestamp);
                        if (expectedDifficulty == null)
                        {
                            Logging.warn("TIV: Failed to calculate expected signer difficulty for block header. Block number: {0} - {1}", header.blockNum, Crypto.hashToString(header.blockChecksum));
                            return true;
                        }
                        if (SignerPowSolution.difficultyToBits(expectedDifficulty) != header.signerBits)
                        {
                            Logging.error("TIV: Block header signer bits do not match the expected retargeted difficulty. Block number: {0} - {1}", header.blockNum, Crypto.hashToString(header.blockChecksum));
                            return false;
                        }
                    }
                }
            }
            else
            {
                lastSuperBlock = blockStorage.getBlock((header.blockNum / ConsensusConfig.superblockInterval) * ConsensusConfig.superblockInterval);
            }

            return verifyBlockSignatures(header);
        }

        private bool isSuperBlock(ulong blockNum)
        {
            return blockNum == 1 || blockNum % ConsensusConfig.superblockInterval == 0;
        }

        private void populateBlockSignatures(Block header)
        {
            bool isSuperBlock = this.isSuperBlock(header.blockNum);
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
                    if (lastSuperBlock != null)
                    {
                        lastSuperBlock.superBlockSegments.TryGetValue(sig.powSolution.blockNum, out SuperBlockSegment? seg);
                        sig.powSolution.blockHash = seg?.blockChecksum;
                    }
                    if (sig.powSolution.blockHash == null)
                    {
                        sig.powSolution.blockHash = IxianHandler.getBlockHash(sig.powSolution.blockNum);
                    }
                }
            }
        }

        private bool processSigfreezedBlockHeader(Block header)
        {
            Block? localBlock = blockStorage.getBlock(header.blockNum);
            if (localBlock == null
                || !header.blockChecksum.SequenceEqual(localBlock.blockChecksum))
            {
                return false;
            }

            if (verifyBlockSignatures(header))
            {
                // TODO 'header.overrideCompactedCheck = true;' can be removed after Block.getBytes() compacted safety is removed
                header.overrideCompactedCheck = true;
                localBlock.setFrozenSignatures(header.signatures);
                blockStorage.insertBlock(localBlock);

                return true;
            }

            return false;
        }

        private bool processBlockHeader(Block header)
        {
            if (lastBlockHeader != null
                && lastBlockHeader.blockChecksum != null
                && !header.lastBlockChecksum.SequenceEqual(lastBlockHeader.blockChecksum))
            {
                // revert the block
                // TODO check with multiple nodes before reorg

                Logging.warn("TIV: Invalid last block checksum, preparing for possible reorg.");

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

                Block? prevHeader = blockStorage.getBlock(lastBlockHeader.blockNum - 1);

                if (prevHeader == null)
                {
                    Logging.error("TIV: Cannot reorg due to missing Block {0}", lastBlockHeader.blockNum - 1);
                    return false;
                }

                pitCache.Remove(lastBlockHeader.blockNum);
                blockStorage.removeBlock(lastBlockHeader.blockNum);
                Block reorgedBlockHeader = lastBlockHeader;
                lastBlockHeader = prevHeader;
                cachedRequiredSignerDifficulty.Set(0, 0, 0, 0);

                ConsensusConfig.redactedWindowSize = ConsensusConfig.getRedactedWindowSize(lastBlockHeader.version);
                ConsensusConfig.minRedactedWindowSize = ConsensusConfig.getRedactedWindowSize(lastBlockHeader.version);

                transactionInclusionCallbacks.blockReorg(reorgedBlockHeader);

                return false;
            }

            if (!verifyBlockHeader(header, lastBlockHeader))
            {
                Logging.error("TIV: Invalid block header received, and it failed verification. Block number: {0} - {1}", header.blockNum, Crypto.hashToString(header.blockChecksum));
                return false;
            }

            if (!header.compacted
                && header.version >= BlockVer.v13)
            {
                header.setFrozenSignatures(header.signatures.OrderBy(x => x.powSolution.difficulty, Comparer<IxiNumber>.Default).ThenBy(x => x.recipientPubKeyOrAddress.addressNoChecksum, new ByteArrayComparer()).ToList());
            }

            // TODO 'header.overrideCompactedCheck = true;' can be removed after Block.getBytes() compacted safety is removed
            header.overrideCompactedCheck = true;
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
                            bool processed = false;
                            lock (pitCache)
                            {
                                if (pitCache.ContainsKey(block_num))
                                {
                                    Logging.info("TIV: Received valid PIT information for block {0}", block_num);
                                    pitCache[block_num].pit = pit;
                                    processed = true;
                                }
                            }
                            if (processed)
                            {
                                processUnverifiedTransactions();
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
            lock (tivLock)
            {
                using (MemoryStream m = new MemoryStream(data))
                using (BinaryReader reader = new BinaryReader(m))
                {
                    bool sigFreezedBlock = false;
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

                            if (lastBlockHeader != null)
                            {
                                if (lastBlockHeader.lastBlockChecksum == null)
                                {
                                    // First block 
                                    if (header.blockChecksum.SequenceEqual(lastBlockHeader.blockChecksum))
                                    {
                                        // Correct first block, replace with full data
                                        if (header.blockNum > 1)
                                        {
                                            populateBlockSignatures(header);
                                        }
                                        if (!blockStorage.insertBlock(header))
                                        {
                                            break;
                                        }

                                        lastBlockHeader = header;

                                        ConsensusConfig.redactedWindowSize = ConsensusConfig.getRedactedWindowSize(lastBlockHeader.version);
                                        ConsensusConfig.minRedactedWindowSize = ConsensusConfig.getRedactedWindowSize(lastBlockHeader.version);

                                        blockCnt++;
                                        continue;
                                    }
                                }
                                if (header.blockNum + ConsensusConfig.sigfreezeOffset == lastBlockHeader.blockNum + 1)
                                {
                                    if (!processSigfreezedBlockHeader(header))
                                    {
                                        break;
                                    }
                                    sigFreezedBlock = true;
                                    blockCnt++;
                                }
                                if (header.blockNum <= lastBlockHeader.blockNum)
                                {
                                    continue;
                                }
                            }
                            if (!processBlockHeader(header))
                            {
                                break;
                            }
                            blockCnt++;
                        }
                        Logging.info("Processed {0} block headers in {1}ms.", blockCnt, Clock.getTimestampMillis() - startTime);
                        if (sigFreezedBlock || blockCnt > 2)
                        {
                            requestBlockHeaders(true);
                        }
                        if (blockCnt > 0)
                        {
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
                    Thread.Yield();
                }
            }
        }

        private void requestBlockHeaders(ulong from, ulong count, Cuckoo? filter, RemoteEndpoint? endpoint = null)
        {
            Logging.info("Requesting block headers from {0} to {1}", from, from + count);
            using (MemoryStream mOut = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(mOut))
                {
                    writer.WriteIxiVarInt(from);
                    writer.WriteIxiVarInt(count);
                    byte[]? filterBytes = filter?.getFilterBytes();
                    writer.WriteIxiBytes(filterBytes);
                    writer.WriteIxiVarInt((int)blockVerificationMode);
                }

                if (endpoint != null)
                {
                    endpoint.sendData(ProtocolMessageCode.getBlockHeaders4, mOut.ToArray());
                }
                else
                {
                    // Request from a single random node
                    char[] node_types = new char[] { 'M', 'H' };
                    if (PresenceList.myPresenceType == 'C')
                    {
                        node_types = new char[] { 'M', 'H', 'R' };
                    }
                    CoreProtocolMessage.broadcastProtocolMessageToSingleRandomNode(node_types, ProtocolMessageCode.getBlockHeaders4, mOut.ToArray(), 0);
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
                foreach (ulong b_num in to_remove)
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

                    if (!entry.outgoing)
                    {
                        continue;
                    }

                    if (cur_time - tx_time > 60) // if the transaction is pending for over 60 seconds, resend
                    {
                        Logging.warn("Transaction {0} pending for a while, resending", t.getTxIdString());
                        entry.addedTimestamp = cur_time;

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

        // TODO Move and unify this region across DLT and Core
        #region Ixiac related functions
        private IxiNumber adjustSignerDifficultyToRatio(IxiNumber difficulty)
        {
            return (difficulty * ConsensusConfig.networkSignerDifficultyConsensusRatio) / 100;
        }

        public IxiNumber? getRequiredSignerDifficulty(ulong blockNum, bool adjustToRatio, int curBlockVersion = 0, long curBlockTimestamp = 0)
        {
            IxiNumber? difficulty = null;
            if (blockNum == lastBlockHeader.blockNum + 1 && blockNum % ConsensusConfig.superblockInterval == 0)
            {
                if (curBlockVersion != 0 && curBlockTimestamp != 0)
                {
                    difficulty = calculateRequiredSignerDifficulty(curBlockVersion, curBlockTimestamp);
                    if (difficulty == null)
                    {
                        Logging.warn("DAA: Failed to calculate required signer difficulty for block #{0} using DAA calculation.", blockNum);
                        return null;
                    }
                }
            }
            if (difficulty == null)
            {
                ulong superBlockNum = (blockNum / ConsensusConfig.superblockInterval) * ConsensusConfig.superblockInterval;
                if (superBlockNum == 0)
                {
                    superBlockNum = 1;
                }
                var block = blockStorage.getBlock(superBlockNum);
                if (block == null)
                {
                    Logging.warn("DAA: Cannot calculate required signer difficulty for block #{0} because the block is not available in storage.", blockNum);
                    return null;
                }
                if (block.version < BlockVer.v13)
                {
                    difficulty = ConsensusConfig.minBlockSignerPowDifficulty;
                }
                else
                {
                    if (block.signerBits == 0)
                    {
                        Logging.warn("DAA: Cannot calculate required signer difficulty for block #{0} because the signer bits of the block is 0.", blockNum);
                        difficulty = ConsensusConfig.minBlockSignerPowDifficulty;
                    }
                    else
                    {
                        difficulty = SignerPowSolution.bitsToDifficulty(block.signerBits);
                    }
                }
            }
            if (adjustToRatio)
            {
                difficulty = adjustSignerDifficultyToRatio(difficulty);
            }
            return difficulty;
        }

        public IxiNumber getMinSignerPowDifficulty(ulong blockNum, int curBlockVersion, long curBlockTimestamp)
        {
            if (blockNum < 8)
            {
                return ConsensusConfig.minBlockSignerPowDifficulty;
            }
            uint minDiffRatio = 7;
            ulong frozenSignatureCount = (ulong)ConsensusConfig.maximumBlockSigners;
            var difficulty = getRequiredSignerDifficulty(blockNum, true, curBlockVersion, curBlockTimestamp);
            if (difficulty == null)
            {
                Logging.warn("Failed to calculate minimum signer difficulty, difficulty is null.");
                difficulty = ConsensusConfig.minBlockSignerPowDifficulty;
            }
            difficulty = difficulty / (frozenSignatureCount * minDiffRatio);
            if (difficulty < ConsensusConfig.minBlockSignerPowDifficulty)
            {
                difficulty = ConsensusConfig.minBlockSignerPowDifficulty;
            }
            return difficulty;
        }

        private Block? findLastDifficultyChangedSuperBlock(ulong blockNum, int blockVersion)
        {
            // Make sure that it's a superblock
            if (blockNum % ConsensusConfig.superblockInterval != 0)
            {
                throw new Exception("DAA: Cannot find last difficulty changed super block, block number is not a superblock.");
            }

            // Edge case for initial blocks
            if (blockNum == ConsensusConfig.superblockInterval)
            {
                return blockStorage.getBlock(1);
            }

            Block? sb = blockStorage.getBlock(blockNum - ConsensusConfig.superblockInterval);
            if (sb == null)
            {
                Logging.warn("DAA: Cannot find last difficulty changed super block for block #{0} because the previous superblock is not available in storage.", blockNum);
                return null;
            }
            IxiNumber? diff = getRequiredSignerDifficulty(sb.blockNum, false);
            if (diff == null)
            {
                Logging.warn("DAA: Cannot calculate required signer difficulty for block #{0} because the difficulty of the previous superblock is not available.", blockNum);
                return null;
            }
            while (sb.lastSuperBlockNum != 0)
            {
                var cmpDiff = getRequiredSignerDifficulty(sb.lastSuperBlockNum, false);
                if (cmpDiff == null)
                {
                    Logging.warn("DAA: Cannot calculate required signer difficulty for block #{0} because the difficulty of the previous superblock is not available.", sb.lastSuperBlockNum);
                    return null;
                }
                if (diff != cmpDiff)
                {
                    Logging.trace("DAA: Found diff block #{0}", sb.blockNum);
                    return sb;
                }
                if (blockVersion <= BlockVer.v12)
                {
                    // regression fix, which searched only last 11000 blocks
                    if (blockNum - sb.blockNum == 11000)
                    {
                        return sb;
                    }
                }
                sb = blockStorage.getBlock(sb.lastSuperBlockNum);
                if (sb == null)
                {
                    Logging.warn("DAA: Cannot find last difficulty changed super block for block #{0} because a previous superblock is not available in storage.", blockNum);
                    return null;
                }
            }
            return sb;
        }

        private IxiNumber? calculateRequiredSignerDifficulty(int blockVersion, long curBlockTimestamp)
        {
            if (blockVersion < BlockVer.v13)
            {
                return ConsensusConfig.minBlockSignerPowDifficulty;
            }
            if (curBlockTimestamp == 0)
            {
                throw new Exception("Current block timestamp must be provided to calculate required signer difficulty.");
            }
            ulong blockNum = lastBlockHeader.blockNum + 1;
            ulong blockOffset = 7;
            if (blockNum < blockOffset + 1) return ConsensusConfig.minBlockSignerPowDifficulty; // special case for first X blocks - since sigFreeze happens n-5 blocks

            if (cachedRequiredSignerDifficulty.BlockNum == blockNum
                && cachedRequiredSignerDifficulty.BlockVersion == blockVersion
                && cachedRequiredSignerDifficulty.Difficulty != 0
                && cachedRequiredSignerDifficulty.Timestamp <= curBlockTimestamp)
            {
                return cachedRequiredSignerDifficulty.Difficulty;
            }

            Block? lastDiffChangeSuperblock = findLastDifficultyChangedSuperBlock(blockNum, blockVersion);
            if (lastDiffChangeSuperblock == null)
            {
                Logging.warn("DAA: Could not find previous retarget block.");
                return null;
            }
            if (curBlockTimestamp - lastDiffChangeSuperblock.timestamp < ConsensusConfig.difficultyAdjustmentTimeInterval)
            {
                Logging.info("DAA: Not enough time has passed to do the calculation, using same difficulty as on previous block.");
                // Edge case for initial blocks
                if (blockNum == ConsensusConfig.superblockInterval)
                {
                    return SignerPowSolution.bitsToDifficulty(blockStorage.getBlock(1).signerBits);
                }

                return SignerPowSolution.bitsToDifficulty(blockStorage.getBlock(blockNum - ConsensusConfig.superblockInterval).signerBits);
            }

            IxiNumber totalDifficulty = 0;
            ulong blockCount = 0;
            ulong blocksToUseForDifficultyCalculation = blockNum - lastDiffChangeSuperblock.blockNum;

            IxiNumber maxSingleBlockDifficulty = null;
            if (lastDiffChangeSuperblock != null && lastDiffChangeSuperblock.signerBits > 0)
            {
                maxSingleBlockDifficulty = SignerPowSolution.bitsToDifficulty(lastDiffChangeSuperblock.signerBits) * 4;
            }

            for (ulong i = 0; i < blocksToUseForDifficultyCalculation; i++)
            {
                ulong consensusBlockNum = blockNum - i - blockOffset;
                Logging.trace("DAA: Using block #{0} for DAA calculation", consensusBlockNum);
                var btsd = blockStorage.getBlockTotalSignerDifficulty(consensusBlockNum);
                var blockTotalSignerDifficulty = btsd.totalSignerDifficulty;
                if (blockTotalSignerDifficulty == null)
                {
                    Logging.warn("DAA: Cannot calculate required signer difficulty for block #{0} because the total signer difficulty of a block used for calculation is not available.", consensusBlockNum);
                    return null;
                }
                Logging.trace("DAA: Using block #{0} with diff {1} for DAA calculation", consensusBlockNum, blockTotalSignerDifficulty);

                // Smooth-out difficulty spikes
                if (maxSingleBlockDifficulty != null
                    && blockTotalSignerDifficulty > maxSingleBlockDifficulty)
                {
                    blockTotalSignerDifficulty = maxSingleBlockDifficulty;
                }
                totalDifficulty += blockTotalSignerDifficulty;
                blockCount++;
            }

            Logging.info("DAA: Used {0} blocks for DAA calculation, expected {1}", blockCount, blocksToUseForDifficultyCalculation);
            if (lastDiffChangeSuperblock.blockNum != 1 && blockCount != blocksToUseForDifficultyCalculation)
            {
                if ((blockNum - blockOffset) != blockCount)
                {
                    throw new Exception(String.Format("An error occured while calculating required signer difficulty for block #{0}. Actual block samples different than expected: {1} != {2}", blockNum, blockCount, blocksToUseForDifficultyCalculation));
                }
            }

            if (blockCount == 0)
            {
                return ConsensusConfig.minBlockSignerPowDifficulty;
            }

            if (blockCount < (ulong)ConsensusConfig.difficultyAdjustmentExpectedBlockCount)
            {
                blockCount = (ulong)ConsensusConfig.difficultyAdjustmentExpectedBlockCount;
            }
            var newDifficulty = totalDifficulty / blockCount;
            cachedRequiredSignerDifficulty.Set(blockNum, blockVersion, newDifficulty, curBlockTimestamp);
            return newDifficulty;
        }

        private bool isBlockchainRecoveryMode(ulong blockNum, long blockTimestamp, int totalBlockSignatures)
        {
            Block prevBlock = IxianHandler.getBlockHeader(blockNum - 1);
            if (prevBlock == null || prevBlock.timestamp + ConsensusConfig.blockChainRecoveryTimeout > blockTimestamp)
            {
                return false;
            }

            if (totalBlockSignatures < 3)
            {
                return false;
            }

            return true;
        }

        private bool handleBlockchainRecoveryMode(Block curBlock, int requiredSignatureCount, int totalBlockSignatures, IxiNumber totalSignerDifficulty, IxiNumber requiredSignerDifficulty)
        {
            if (!isBlockchainRecoveryMode(curBlock.blockNum, curBlock.timestamp, totalBlockSignatures))
            {
                return false;
            }

            int requiredConsensus = getMinRequiredSigCount(curBlock, false);
            int requiredConsensusAdj = getMinRequiredSigCount(curBlock, true);

            int missingRequiredSigs = ((requiredConsensus / 2) + 1) - requiredSignatureCount;
            int missingSigs = requiredConsensusAdj - totalBlockSignatures;

            // no missing sigs, no need for recovery mode
            if (missingRequiredSigs <= 0 && missingSigs <= 0)
            {
                return false;
            }

            // missing sigs and no block for a period of time, run recovery checks

            IxiNumber recoveryRequiredSignerDifficulty = 0;
            if (missingRequiredSigs > 0)
            {
                recoveryRequiredSignerDifficulty = recoveryRequiredSignerDifficulty + (missingRequiredSigs * requiredSignerDifficulty * ConsensusConfig.blockChainRecoveryMissingRequiredSignerRatio / 100);
                if (totalSignerDifficulty < recoveryRequiredSignerDifficulty)
                {
                    return false;
                }
            }

            if (missingSigs > 0)
            {
                if (totalSignerDifficulty < recoveryRequiredSignerDifficulty + (missingSigs * IxianHandler.getMinSignerPowDifficulty(curBlock.blockNum, curBlock.version, curBlock.timestamp) * ConsensusConfig.blockChainRecoveryMissingSignerMultiplier))
                {
                    return false;
                }
            }

            Logging.warn("Recovery mode activated for block #{0} {1}, missing required sigs:{2}, missing sigs: {3}, cur time: {4}, block time: {5}, total signer difficulty: {6}, requiredSignerDifficultyAdjusted: {7}.",
                curBlock.blockNum, Crypto.hashToString(curBlock.calculateChecksum()), missingRequiredSigs, missingSigs, Clock.getNetworkTimestamp(), curBlock.timestamp, totalSignerDifficulty, requiredSignerDifficulty);

            return true;
        }
        #endregion
    }
}

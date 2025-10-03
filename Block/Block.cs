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
using IXICore.Utils;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IXICore
{
    public static class BlockVer
    {
        public static int v0 = 0;
        public static int v1 = 1;
        public static int v2 = 2;
        public static int v3 = 3;
        public static int v4 = 4;
        public static int v5 = 5;
        public static int v6 = 6;
        public static int v7 = 7;
        public static int v8 = 8;
        public static int v9 = 9;
        public static int v10 = 10; // Omega Lock-in (partial activation)
        public static int v11 = 11; // Omega Full activation
        public static int v12 = 12;
        public static int v13 = 13;
        public static int v14 = 14;
    }

    public class SuperBlockSegment
    {
        public ulong blockNum = 0;
        public byte[] blockChecksum = null;

        public SuperBlockSegment(ulong block_num, byte[] block_checksum)
        {
            blockNum = block_num;
            blockChecksum = block_checksum;
        }
    }

    /// <summary>
    ///  An Ixian DLT Block.
    ///  A block contains all the transactions which act on the WalletState and various checksums which validate the actions performed on the blockchain.
    ///  Blocks are the fundamental data structure of Distributed Ledger Technology (DLT) and form a chain of valid states from the so-called 'Genesis Block' to the present moment.
    ///  An Ixian Block must include checksums of the previous block, checksums of the internal data structures (WalletState) and a list of transactions which have updated the WalletState
    ///  from its previous value to its current value.
    ///  In addition, a block contains cryptographic signatures of Master nodes, which is the basis for the Ixian Consensus algorithm.
    /// </summary>
    public class Block
    {
        /// <summary>
        /// Latest possible version of the Block structure. New blocks should usually be created with the latest version.
        /// </summary>
        public static int maxVersion = BlockVer.v13;

        /// <summary>
        /// Block height (block number). This is a sequential index in the blockchain which uniquely identifies each block.
        /// </summary>
        public ulong blockNum { get; set; }

        /// <summary>
        /// The list of transactions which should act on the WalletState from the previous block to produce the WalletState for this block.
        /// </summary>
        public HashSet<byte[]> transactions = new HashSet<byte[]>(new ByteArrayComparer());

        /// <summary>
        /// The list of Master Node signatures which enable the Ixian Consensus algorithm.
        /// </summary>
        public List<BlockSignature> signatures = new List<BlockSignature> { };

        /// <summary>
        /// Prefix Inclusion Tree (PIT) checksum which enables the TIV protocol.
        /// </summary>
        public byte[] pitChecksum { get { return transactionPIT.calculateTreeHash(); } }
        public byte[] receivedPitChecksum = null;


        private PrefixInclusionTree transactionPIT;

        /// <summary>
        /// The list of Frozen Master Node signatures which enable the Ixian Consensus algorithm.
        /// </summary>
        public List<BlockSignature> frozenSignatures { get; private set; } = null;

        public int signatureCount = 0; // used only when block is compacted
        public IxiNumber totalSignerDifficulty = 0; // used only when block is compacted

        /// <summary>
        /// Block version.
        /// </summary>
        /// <remarks>
        ///  New blocks should always be generated with the latest version - `maxVersion`, except during the transitional period while the network
        ///  is upgrading from one block version to the next. Older blocks, retrieved from files or the network may have an older version and this field identifies
        ///  which version the specific block has.
        ///  Some Block features are only enabled from specific versions forward.
        /// </remarks>
        public int version = 0;
        /// <summary>
        ///  Checksum of all the data in the block. This value serves as the basis for block signatures since no block contents may be changed without
        ///  affecting the block checksum.
        /// </summary>
        public byte[] blockChecksum = null;
        /// <summary>
        ///  Checksum of the previous block, so that accepting a new block indirectly confirms and validates all past blocks. This is the basic functionality of DLT.
        /// </summary>
        public byte[] lastBlockChecksum = null;
        /// <summary>
        ///  Checksum of the WalletState after the transactions in this block are applied to the WalletState from the previous block.
        /// </summary>
        /// <remarks>
        ///  This allows Ixian Master Nodes to operate on the WalletState and be certain that it matches all other Master nodes without exchanging all the wallet data.
        ///  WalletState is synchornized when the node first boots up, but is never transferred between nodes later, since it can be updated in a consistent manner
        ///  using the transactions and wallet state checksums in each block.
        /// </remarks>
        public byte[] walletStateChecksum = null;
        /// <summary>
        ///  Checksum of the final list of signatures for block `blockNum - 5`.
        /// </summary>
        /// <remarks>
        ///  In this way, the signers list is 'frozen' and may no longer be changed, preventing various possible tampering attacks. Since the payout of many of the Ixian DLT's
        ///  Master Node functions is tied to the accepted signature list, this field protects that list from malicious tinkering.
        ///  Changes are permitted for five blocks to allow slower nodes to process and apply their signatures.
        /// </remarks>
        public byte[] signatureFreezeChecksum = null;
        /// <summary>
        ///  Unix Epoch value of when the block was generated.
        /// </summary>
        public long timestamp = 0;
        /// <summary>
        ///  Ixian Mining PoW difficulty value.
        /// </summary>
        /// <remarks>
        ///  Ixian Blockchain works on a consensus model and mining is not strictly required. An optional mining system is included to enable initial coin supply distribution.
        ///  The mining algorithm is Argon2id and the solutions are not included in blocks themselves. There is a special Transaction type which submits a solution to a block.
        ///  Miners are able to work on any block in the Redacted History window, with the target block specifying its difficulty to which the posted solution must conform.
        /// </remarks>
        public ulong difficulty = 0;
        /// <summary>
        ///  List of blocks and their checksums - used only in the superblock functionality.
        /// </summary>
        public Dictionary<ulong, SuperBlockSegment> superBlockSegments = new Dictionary<ulong, SuperBlockSegment>();
        /// <summary>
        ///  Checksum of the previous superblock - used only in superblock functionality.
        /// </summary>
        public byte[] lastSuperBlockChecksum = null;
        /// <summary>
        ///  Block height of the previous superblock - used only in superblock functionality.
        /// </summary>
        public ulong lastSuperBlockNum = 0;

        /// <summary>
        ///  Ixian Hybrid PoW solution, if it exists for this block.
        /// </summary>
        /// <remarks>
        ///  This field is not included in the block checksum, nor is it transmitted over the network. Master Nodes fill this information for themselves from the
        ///  special PoW-Solution transaction types in the TransactionPool.
        /// </remarks>
        public byte[] powField = null;


        /// <summary>
        ///  Indicator which shows if the block was processed through the Consensus algorithm, or read from cold storage.
        /// </summary>
        public bool fromLocalStorage = false;

        /// <summary>
        ///  Indicator to show if the block has already been compacted through the superblock functionality.
        /// </summary>
        public bool compacting = false;
        public bool compacted = false;
        /// <summary>
        ///  Indicator to show if the block's signatures have been compacted through the superblock functionality.
        /// </summary>
        public bool compactedSigs = false;

        /// <summary>
        ///  Address of the block proposer/first signer.
        /// </summary>
        public byte[] blockProposer = null;

        /// <summary>
        ///  Ixian Hybrid PoW difficulty value.
        /// </summary>
        public ulong signerBits = 0;

        public ulong txCount = 0;

        public IxiNumber totalFee = 0;

        public byte[] regNameStateChecksum = null;


        public Block()
        {
            version = BlockVer.v0;
            blockNum = 0;
            transactions = new HashSet<byte[]>(new ByteArrayComparer());
            initPITTree();
        }

        /// <summary>
        ///  Copies the given block rather than making a reference to it.
        /// </summary>
        /// <remarks>
        ///  This constructor is used in some places of the DLT software where copies of the block data are required and where such a copy
        ///  would improve performance by requiring less thread synchronziation.
        /// </remarks>
        /// <param name="block">Source block.</param>
        public Block(Block block)
        {
            version = block.version;
            blockNum = block.blockNum;
            initPITTree();

            lastSuperBlockNum = block.lastSuperBlockNum;

            foreach (var entry in block.superBlockSegments)
            {
                superBlockSegments.Add(entry.Key, new SuperBlockSegment(entry.Key, entry.Value.blockChecksum));
            }

            txCount = block.txCount;
            totalFee = block.totalFee;

            if (block.receivedPitChecksum != null)
            {
                receivedPitChecksum = new byte[block.receivedPitChecksum.Length];
                Array.Copy(block.receivedPitChecksum, receivedPitChecksum, receivedPitChecksum.Length);
            }

            // Add transactions and signatures from the old block
            foreach (byte[] txid in block.transactions)
            {
                transactions.Add(txid);
                if (version < BlockVer.v8)
                {
                    transactionPIT.add(UTF8Encoding.UTF8.GetBytes(Transaction.getTxIdString(txid)));
                }
                else
                {
                    transactionPIT.add(txid);
                }
            }

            lock (block.signatures)
            {
                foreach (BlockSignature signature in block.signatures)
                {
                    signatures.Add(new BlockSignature(signature));
                }

                if (block.frozenSignatures != null)
                {
                    List<BlockSignature> frozen_signatures = new List<BlockSignature>();
                    foreach (BlockSignature signature in block.frozenSignatures)
                    {
                        frozen_signatures.Add(new BlockSignature(signature));
                    }
                    setFrozenSignatures(frozen_signatures);
                }
            }

            if (block.blockChecksum != null)
            {
                blockChecksum = new byte[block.blockChecksum.Length];
                Array.Copy(block.blockChecksum, blockChecksum, blockChecksum.Length);
            }

            if (block.lastBlockChecksum != null)
            {
                lastBlockChecksum = new byte[block.lastBlockChecksum.Length];
                Array.Copy(block.lastBlockChecksum, lastBlockChecksum, lastBlockChecksum.Length);
            }

            if (block.lastSuperBlockChecksum != null)
            {
                lastSuperBlockChecksum = new byte[block.lastSuperBlockChecksum.Length];
                Array.Copy(block.lastSuperBlockChecksum, lastSuperBlockChecksum, lastSuperBlockChecksum.Length);
            }

            if (block.walletStateChecksum != null)
            {
                walletStateChecksum = new byte[block.walletStateChecksum.Length];
                Array.Copy(block.walletStateChecksum, walletStateChecksum, walletStateChecksum.Length);
            }

            if (block.regNameStateChecksum != null)
            {
                regNameStateChecksum = new byte[block.regNameStateChecksum.Length];
                Array.Copy(block.regNameStateChecksum, regNameStateChecksum, regNameStateChecksum.Length);
            }

            if (block.signatureFreezeChecksum != null)
            {
                signatureFreezeChecksum = new byte[block.signatureFreezeChecksum.Length];
                Array.Copy(block.signatureFreezeChecksum, signatureFreezeChecksum, signatureFreezeChecksum.Length);
            }

            if (block.powField != null)
            {
                powField = new byte[block.powField.Length];
                Array.Copy(block.powField, powField, powField.Length);
            }

            timestamp = block.timestamp;
            difficulty = block.difficulty;

            fromLocalStorage = block.fromLocalStorage;

            compacted = block.compacted;
            compacting = block.compacting;
            compactedSigs = block.compactedSigs;
            signatureCount = block.signatureCount;
            totalSignerDifficulty = block.totalSignerDifficulty;

            if (block.blockProposer != null)
            {
                blockProposer = new byte[block.blockProposer.Length];
                Array.Copy(block.blockProposer, blockProposer, blockProposer.Length);
            }

            signerBits = block.signerBits;
        }

        /// <summary>
        ///  Reconstructs a Block from the bytestream. See also `getBytes`.
        /// </summary>
        /// <remarks>
        ///  Each block has a `getBytes()` function which serializes the block data into a byte buffer, suitable for sending over the network.
        ///  This constructor can re-create the block from the given bytestream.
        /// </remarks>
        /// <param name="bytes">Block bytes, usually received from the network.</param>
        /// <param name="forceV10Structure">Forces V10 Structure even if it's a pre-V10 block.</param>
        public Block(byte[] bytes, bool forceV10Structure)
        {
            initPITTree();
            if (forceV10Structure || bytes[0] >= BlockVer.v10)
            {
                fromBytesV10(bytes, null, null);
            }
            else if (bytes[0] < BlockVer.v8)
            {
                fromBytesLegacy(bytes);
            }
            else if (bytes[0] < BlockVer.v10)
            {
                fromBytesV8(bytes);
            }
        }

        public Block(byte[] checksum, byte[] bytes, byte[] txIDsBytes)
        {
            initPITTree();
            fromBytesV10(bytes, checksum, txIDsBytes);
        }

        private void fromBytesLegacy(byte[] bytes)
        {
            try
            {
                using (MemoryStream m = new MemoryStream(bytes))
                {
                    using (BinaryReader reader = new BinaryReader(m))
                    {
                        version = reader.ReadInt32();

                        blockNum = reader.ReadUInt64();

                        if (version < BlockVer.v6)
                        {
                            if (bytes.Length > 49152000)
                            {
                                throw new Exception("Block #" + blockNum + " size is bigger than 49MB.");
                            }
                        }
                        else
                        {
                            if (bytes.Length > 10240000)
                            {
                                throw new Exception("Block #" + blockNum + " size is bigger than 19MB.");
                            }
                        }

                        if (version <= maxVersion)
                        {

                            // Get the transaction ids
                            int num_transactions = reader.ReadInt32();
                            for (int i = 0; i < num_transactions; i++)
                            {
                                string txid = reader.ReadString();
                                byte[] b_txid = Transaction.txIdLegacyToV8(txid);
                                if (transactions.Contains(b_txid))
                                {
                                    // Block contains duplicate txid
                                    throw new Exception("Block #" + blockNum + " contains duplicate txid");
                                }
                                transactions.Add(b_txid);
                                transactionPIT.add(UTF8Encoding.UTF8.GetBytes(txid));
                            }

                            // Get the signatures
                            int num_signatures = reader.ReadInt32();

                            if (num_signatures > ConsensusConfig.maximumBlockSigners * 2)
                            {
                                throw new Exception("Block #" + blockNum + " has more than " + (ConsensusConfig.maximumBlockSigners * 2) + " signatures");
                            }


                            for (int i = 0; i < num_signatures; i++)
                            {
                                int sigLen = reader.ReadInt32();
                                byte[] sig = null;
                                if (sigLen > 0)
                                {
                                    sig = reader.ReadBytes(sigLen);
                                }

                                int sigAddresLen = reader.ReadInt32();
                                Address sigAddress = null;
                                if (sigAddresLen > 0)
                                {
                                    sigAddress = new Address(reader.ReadBytes(sigAddresLen));
                                }

                                if (!containsSignature(sigAddress))
                                {
                                    BlockSignature newSig = new BlockSignature() { signature = sig, recipientPubKeyOrAddress = sigAddress };
                                    signatures.Add(newSig);
                                }
                            }

                            int dataLen = reader.ReadInt32();
                            if (dataLen > 0)
                            {
                                blockChecksum = reader.ReadBytes(dataLen);
                            }

                            dataLen = reader.ReadInt32();
                            if (dataLen > 0)
                            {
                                lastBlockChecksum = reader.ReadBytes(dataLen);
                            }

                            dataLen = reader.ReadInt32();
                            if (dataLen > 0)
                            {
                                walletStateChecksum = reader.ReadBytes(dataLen);
                            }

                            dataLen = reader.ReadInt32();
                            if (dataLen > 0)
                            {
                                signatureFreezeChecksum = reader.ReadBytes(dataLen);
                            }

                            difficulty = reader.ReadUInt64();
                            timestamp = reader.ReadInt64();

                            if (version > BlockVer.v4)
                            {
                                lastSuperBlockNum = reader.ReadUInt64();

                                dataLen = reader.ReadInt32();
                                if (dataLen > 0)
                                {
                                    lastSuperBlockChecksum = reader.ReadBytes(dataLen);
                                }

                                int super_block_seg_count = reader.ReadInt32();
                                for (int i = 0; i < super_block_seg_count; i++)
                                {
                                    ulong seg_block_num = reader.ReadUInt64();
                                    int seg_bc_len = reader.ReadInt32();
                                    byte[] seg_bc = null;
                                    if (seg_bc_len > 0)
                                    {
                                        seg_bc = reader.ReadBytes(seg_bc_len);
                                    }
                                    superBlockSegments.Add(seg_block_num, new SuperBlockSegment(seg_block_num, seg_bc));
                                }
                            }

                            blockChecksum = calculateChecksum();
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Logging.warn(string.Format("Cannot create block from bytes: {0}", e.ToString()));
                throw;
            }
        }

        private void fromBytesV8(byte[] bytes)
        {
            try
            {
                using (MemoryStream m = new MemoryStream(bytes))
                {
                    using (BinaryReader reader = new BinaryReader(m))
                    {
                        version = (int)reader.ReadIxiVarUInt();

                        blockNum = reader.ReadIxiVarUInt();

                        if (bytes.Length > 10240000)
                        {
                            throw new Exception("Block #" + blockNum + " size is bigger than 19MB.");
                        }

                        if (version > maxVersion)
                        {
                            return;
                        }

                        // Get the transaction ids
                        int num_transactions = (int)reader.ReadIxiVarUInt();
                        for (int i = 0; i < num_transactions; i++)
                        {
                            int txid_len = (int)reader.ReadIxiVarUInt();
                            byte[] txid = reader.ReadBytes(txid_len);
                            if (transactions.Contains(txid))
                            {
                                // Block contains duplicate txid
                                throw new Exception("Block #" + blockNum + " contains duplicate txid");
                            }
                            transactions.Add(txid);
                            transactionPIT.add(txid);
                        }

                        // Get the signatures
                        int num_signatures = (int)reader.ReadIxiVarUInt();

                        if (num_signatures > ConsensusConfig.maximumBlockSigners * 2)
                        {
                            throw new Exception("Block #" + blockNum + " has more than " + (ConsensusConfig.maximumBlockSigners * 2) + " signatures");
                        }


                        for (int i = 0; i < num_signatures; i++)
                        {
                            int sigLen = (int)reader.ReadIxiVarUInt();
                            byte[] sig = null;

                            if (sigLen > 0)
                            {
                                sig = reader.ReadBytes(sigLen);
                            }

                            int sigAddresLen = (int)reader.ReadIxiVarUInt();
                            Address sigAddress = null;
                            if (sigAddresLen > 0)
                            {
                                sigAddress = new Address(reader.ReadBytes(sigAddresLen));
                            }

                            if (!containsSignature(sigAddress))
                            {
                                BlockSignature newSig = new BlockSignature() { signature = sig, recipientPubKeyOrAddress = sigAddress };
                                signatures.Add(newSig);
                            }
                        }

                        int dataLen = (int)reader.ReadIxiVarUInt();
                        if (dataLen > 0)
                        {
                            blockChecksum = reader.ReadBytes(dataLen);
                        }

                        dataLen = (int)reader.ReadIxiVarUInt();
                        if (dataLen > 0)
                        {
                            lastBlockChecksum = reader.ReadBytes(dataLen);
                        }

                        dataLen = (int)reader.ReadIxiVarUInt();
                        if (dataLen > 0)
                        {
                            walletStateChecksum = reader.ReadBytes(dataLen);
                        }

                        dataLen = (int)reader.ReadIxiVarUInt();
                        if (dataLen > 0)
                        {
                            signatureFreezeChecksum = reader.ReadBytes(dataLen);
                        }

                        difficulty = reader.ReadIxiVarUInt();
                        timestamp = (long)reader.ReadIxiVarUInt();

                        lastSuperBlockNum = reader.ReadIxiVarUInt();

                        dataLen = (int)reader.ReadIxiVarUInt();
                        if (dataLen > 0)
                        {
                            lastSuperBlockChecksum = reader.ReadBytes(dataLen);
                        }

                        int super_block_seg_count = (int)reader.ReadIxiVarUInt();
                        for (int i = 0; i < super_block_seg_count; i++)
                        {
                            ulong seg_block_num = reader.ReadIxiVarUInt();
                            int seg_bc_len = (int)reader.ReadIxiVarUInt();
                            byte[] seg_bc = null;
                            if (seg_bc_len > 0)
                            {
                                seg_bc = reader.ReadBytes(seg_bc_len);
                            }
                            superBlockSegments.Add(seg_block_num, new SuperBlockSegment(seg_block_num, seg_bc));
                        }

                        try
                        {
                            dataLen = (int)reader.ReadIxiVarUInt();
                            if (dataLen > 0)
                            {
                                blockProposer = reader.ReadBytes(dataLen);
                            }
                        }
                        catch (Exception)
                        {

                        }

                        blockChecksum = calculateChecksum();
                    }
                }
            }
            catch (Exception e)
            {
                Logging.warn("Cannot create block from bytes: {0}", e.ToString());
                throw;
            }
        }

        private void fromBytesV10(byte[] bytes, byte[] checksum, byte[] txIDBytes)
        {
            try
            {
                using (MemoryStream m = new MemoryStream(bytes))
                {
                    using (BinaryReader reader = new BinaryReader(m))
                    {
                        version = (int)reader.ReadIxiVarUInt();

                        blockNum = reader.ReadIxiVarUInt();

                        if (version >= BlockVer.v6)
                        {
                            if (bytes.Length > ConsensusConfig.maximumBlockSize)
                            {
                                throw new Exception("Block #" + blockNum + " size " + bytes.Length + "B is bigger than " + ConsensusConfig.maximumBlockSize + "B.");
                            }
                        }

                        if (version > maxVersion)
                        {
                            throw new Exception("Block #" + blockNum + " version is higher than max supported version " + version + " > " + maxVersion + ".");
                        }

                        int dataLen = (int)reader.ReadIxiVarUInt();
                        if (dataLen > 64)
                        {
                            throw new Exception("Block #" + blockNum + " lastBlockChecksum len " + dataLen + "B is bigger than 64B.");
                        }
                        if (dataLen > 0)
                        {
                            lastBlockChecksum = reader.ReadBytes(dataLen);
                        }

                        dataLen = (int)reader.ReadIxiVarUInt();
                        if (dataLen > 64)
                        {
                            throw new Exception("Block #" + blockNum + " signatureFreezeChecksum len " + dataLen + "B is bigger than 64B.");
                        }
                        if (dataLen > 0)
                        {
                            signatureFreezeChecksum = reader.ReadBytes(dataLen);
                        }

                        txCount = reader.ReadIxiVarUInt();

                        dataLen = (int)reader.ReadIxiVarUInt();
                        if (dataLen > 64)
                        {
                            throw new Exception("Block #" + blockNum + " pit/merkle hash len " + dataLen + "B is bigger than 64B.");
                        }
                        if (dataLen > 0)
                        {
                            receivedPitChecksum = reader.ReadBytes(dataLen);
                        }

                        timestamp = (long)reader.ReadIxiVarUInt();

                        difficulty = reader.ReadIxiVarUInt();

                        if (blockNum == 1)
                        {
                            signerBits = reader.ReadUInt64();
                        }
                        else if (blockNum != 0
                            && version >= BlockVer.v5
                            && blockNum % ConsensusConfig.superblockInterval == 0)
                        {
                            signerBits = reader.ReadUInt64();

                            lastSuperBlockNum = reader.ReadIxiVarUInt();

                            dataLen = (int)reader.ReadIxiVarUInt();
                            if (dataLen > 64)
                            {
                                throw new Exception("Block #" + blockNum + " lastSuperBlockChecksum len " + dataLen + "B is bigger than 64B.");
                            }
                            if (dataLen > 0)
                            {
                                lastSuperBlockChecksum = reader.ReadBytes(dataLen);
                            }

                            int super_block_seg_count = (int)reader.ReadIxiVarUInt();
                            for (int i = 0; i < super_block_seg_count; i++)
                            {
                                ulong seg_block_num = blockNum - (ulong)super_block_seg_count + (ulong)i;
                                int seg_bc_len = (int)reader.ReadIxiVarUInt();
                                if (seg_bc_len > 64)
                                {
                                    throw new Exception("Block #" + blockNum + " seg_bc len " + dataLen + "B is bigger than 64B.");
                                }
                                byte[] seg_bc = null;
                                if (seg_bc_len > 0)
                                {
                                    seg_bc = reader.ReadBytes(seg_bc_len);
                                }
                                superBlockSegments.Add(seg_block_num, new SuperBlockSegment(seg_block_num, seg_bc));
                            }
                        }

                        dataLen = (int)reader.ReadIxiVarUInt();
                        if (dataLen > 64)
                        {
                            throw new Exception("Block #" + blockNum + " walletStateChecksum len " + dataLen + "B is bigger than 64B.");
                        }
                        if (dataLen > 0)
                        {
                            walletStateChecksum = reader.ReadBytes(dataLen);
                        }

                        if (version >= BlockVer.v11)
                        {
                            dataLen = (int)reader.ReadIxiVarUInt();
                            if (dataLen > 64)
                            {
                                throw new Exception("Block #" + blockNum + " regNameStateChecksum len " + dataLen + "B is bigger than 64B.");
                            }
                            if (dataLen > 0)
                            {
                                regNameStateChecksum = reader.ReadBytes(dataLen);
                            }
                            totalFee = reader.ReadIxiNumber();
                        }

                        int v10HeaderPosition = (int)m.Position;

                        if (m.Position < m.Length)
                        {
                            // Get the signatures
                            int num_signatures = (int)reader.ReadIxiVarUInt();

                            if (num_signatures == 0)
                            {
                                signatureCount = (int)reader.ReadIxiVarUInt();
                                ulong tmpSignerDiff = reader.ReadIxiVarUInt();
                                if (version >= BlockVer.v10)
                                {
                                    totalSignerDifficulty = SignerPowSolution.bitsToDifficulty(tmpSignerDiff);
                                }
                            }
                            else
                            {
                                if (num_signatures > ConsensusConfig.maximumBlockSigners * 2)
                                {
                                    throw new Exception("Block #" + blockNum + " has more than " + (ConsensusConfig.maximumBlockSigners * 2) + " signatures");
                                }

                                for (int i = 0; i < num_signatures; i++)
                                {
                                    int sigLen = (int)reader.ReadIxiVarUInt();
                                    BlockSignature sig = new BlockSignature(reader.ReadBytes(sigLen), false);

                                    if (!containsSignature(sig.recipientPubKeyOrAddress))
                                    {
                                        signatures.Add(sig);
                                    }
                                }
                            }
                        }

                        if (m.Position < m.Length)
                        {
                            if (txCount > 0)
                            {
                                // Get the transaction ids
                                for (ulong i = 0; i < txCount; i++)
                                {
                                    int txid_len = (int)reader.ReadIxiVarUInt();
                                    if (txid_len > 128)
                                    {
                                        throw new Exception("Block #" + blockNum + " txid len " + txid_len + "B is bigger than 128B.");
                                    }
                                    byte[] txid = reader.ReadBytes(txid_len);
                                    if (transactions.Contains(txid))
                                    {
                                        // Block contains duplicate txid
                                        throw new Exception("Block #" + blockNum + " contains duplicate txid");
                                    }
                                    transactions.Add(txid);
                                    if (version < BlockVer.v8)
                                    {
                                        transactionPIT.add(UTF8Encoding.UTF8.GetBytes(Transaction.getTxIdString(txid)));
                                    }
                                    else
                                    {
                                        transactionPIT.add(txid);
                                    }

                                }

                                if (receivedPitChecksum != null
                                    && version >= BlockVer.v6
                                    && !pitChecksum.SequenceEqual(receivedPitChecksum))
                                {
                                    throw new Exception("Invalid PIT Checksum.");
                                }
                            }
                        }

                        if (txIDBytes != null)
                        {
                            setTransactionIDsFromBytes(txIDBytes);
                        }

                        if (checksum != null)
                        {
                            blockChecksum = checksum;
                        }
                        else
                        {
                            if (version >= BlockVer.v10)
                            {
                                blockChecksum = CryptoManager.lib.sha3_512sq(bytes, 0, v10HeaderPosition);
                            }
                            else
                            {
                                blockChecksum = calculateChecksum();
                            }
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Logging.warn("Cannot create block from bytes: {0}", e.ToString());
                throw;
            }
        }

        private void initPITTree()
        {
            // Number of levels is intended for 2K transactions in block. Increase when num of transactions increases.
            transactionPIT = new PrefixInclusionTree(44, 3);
        }

        /// <summary>
        ///  Retrieves the block in its serialized, 'byte stream' format. See also `Block(byte[] bytes)`.
        /// </summary>
        /// <remarks>
        ///  A block can be serialized for network transmission using this function. All relevant fields will be encoded and a byte buffer will
        ///  be returned. The byte buffer contains a copy of the block, so no thread synchronization is required.
        /// </remarks>
        /// <param name="include_sb_segments">Includes superblock segments if true.</param>
        /// <param name="frozen_sigs_only">Returns only frozen signatures if true. If false it returns all signatures, if they are still available, otherwise falls back to frozen signatures.</param>
        /// <returns>Byte buffer with the serialized block.</returns>
        public byte[] getBytes(bool include_sb_segments = true, bool frozen_sigs_only = true, bool forceV10Structure = false, bool asBlockHeader = false, bool forChecksum = false)
        {
            if (compacted)
            {
                Logging.error("Trying to use getBytes() from a compacted Block {0}", blockNum);
                return null;
            }

            if (forceV10Structure || version >= BlockVer.v10)
            {
                return getBytesV10(include_sb_segments, frozen_sigs_only, forChecksum, asBlockHeader);
            }
            else if (version < BlockVer.v8)
            {
                return getBytesLegacy(include_sb_segments, frozen_sigs_only);
            }
            else if (version < BlockVer.v10)
            {
                return getBytesV8(include_sb_segments, frozen_sigs_only);
            }
            return null;
        }

        private byte[] getBytesLegacy(bool include_sb_segments = true, bool frozen_sigs_only = true)
        {
            using (MemoryStream m = new MemoryStream(5120))
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.Write(version);

                    writer.Write(blockNum);

                    // Write the number of transactions
                    int num_transactions = transactions.Count;
                    writer.Write(num_transactions);

                    // Write each wallet
                    foreach (byte[] txid in transactions)
                    {
                        writer.Write(Transaction.getTxIdString(txid));
                    }

                    lock (signatures)
                    {
                        List<BlockSignature> tmp_signatures = signatures;
                        if (frozen_sigs_only && frozenSignatures != null)
                        {
                            tmp_signatures = frozenSignatures;
                        }

                        // Write the number of signatures
                        int num_signatures = tmp_signatures.Count;

                        if (num_signatures > ConsensusConfig.maximumBlockSigners * 2)
                        {
                            num_signatures = ConsensusConfig.maximumBlockSigners * 2;
                        }

                        writer.Write(num_signatures);

                        // Write each signature
                        for (int i = 0; i < num_signatures; i++)
                        {
                            BlockSignature signature = tmp_signatures[i];

                            if (signature.signature != null)
                            {
                                writer.Write(signature.signature.Length);
                                writer.Write(signature.signature);
                            }
                            else
                            {
                                writer.Write((int)0);
                            }
                            var signerAddress = signature.recipientPubKeyOrAddress.getInputBytes(true);
                            writer.Write(signerAddress.Length);
                            writer.Write(signerAddress);
                        }
                    }

                    writer.Write(blockChecksum.Length);
                    writer.Write(blockChecksum);

                    if (lastBlockChecksum != null)
                    {
                        writer.Write(lastBlockChecksum.Length);
                        writer.Write(lastBlockChecksum);
                    }
                    else
                    {
                        writer.Write((int)0);
                    }

                    if (walletStateChecksum != null)
                    {
                        writer.Write(walletStateChecksum.Length);
                        writer.Write(walletStateChecksum);
                    }
                    else
                    {
                        writer.Write((int)0);
                    }

                    if (signatureFreezeChecksum != null)
                    {
                        writer.Write(signatureFreezeChecksum.Length);
                        writer.Write(signatureFreezeChecksum);
                    }
                    else
                    {
                        writer.Write((int)0);
                    }

                    writer.Write(difficulty);
                    writer.Write(timestamp);

                    writer.Write(lastSuperBlockNum);

                    if (lastSuperBlockChecksum != null)
                    {
                        writer.Write(lastSuperBlockChecksum.Length);
                        writer.Write(lastSuperBlockChecksum);
                    }
                    else
                    {
                        writer.Write((int)0);
                    }

                    if (include_sb_segments)
                    {
                        writer.Write(superBlockSegments.Count);
                        foreach (var entry in superBlockSegments)
                        {
                            writer.Write(entry.Key);
                            writer.Write(entry.Value.blockChecksum.Length);
                            writer.Write(entry.Value.blockChecksum);
                        }
                    }
                    else
                    {
                        writer.Write((int)0);
                    }
#if TRACE_MEMSTREAM_SIZES
                    Logging.info(String.Format("Block::getBytes: {0}", m.Length));
#endif
                }

                return m.ToArray();
            }
        }

        private byte[] getBytesV8(bool include_sb_segments = true, bool frozen_sigs_only = true)
        {
            using (MemoryStream m = new MemoryStream(5120))
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.WriteIxiVarInt(version);

                    writer.WriteIxiVarInt(blockNum);

                    // Write the number of transactions
                    int num_transactions = transactions.Count;
                    writer.WriteIxiVarInt(num_transactions);

                    // Write each wallet
                    foreach (byte[] txid in transactions)
                    {
                        writer.WriteIxiVarInt(txid.Length);
                        writer.Write(txid);
                    }

                    lock (signatures)
                    {
                        List<BlockSignature> tmp_signatures = signatures;
                        if (frozen_sigs_only && frozenSignatures != null)
                        {
                            tmp_signatures = frozenSignatures;
                        }

                        // Write the number of signatures
                        int num_signatures = tmp_signatures.Count;

                        if (num_signatures > ConsensusConfig.maximumBlockSigners * 2)
                        {
                            num_signatures = ConsensusConfig.maximumBlockSigners * 2;
                        }

                        writer.WriteIxiVarInt(num_signatures);

                        // Write each signature
                        for (int i = 0; i < num_signatures; i++)
                        {
                            BlockSignature signature = tmp_signatures[i];

                            if (signature.signature != null)
                            {
                                writer.WriteIxiVarInt(signature.signature.Length);
                                writer.Write(signature.signature);
                            }
                            else
                            {
                                writer.WriteIxiVarInt((int)0);
                            }
                            var signerAddress = signature.recipientPubKeyOrAddress.getInputBytes(true);
                            writer.WriteIxiVarInt(signerAddress.Length);
                            writer.Write(signerAddress);
                        }
                    }

                    writer.WriteIxiVarInt(blockChecksum.Length);
                    writer.Write(blockChecksum);

                    if (lastBlockChecksum != null)
                    {
                        writer.WriteIxiVarInt(lastBlockChecksum.Length);
                        writer.Write(lastBlockChecksum);
                    }
                    else
                    {
                        writer.WriteIxiVarInt((int)0);
                    }

                    if (walletStateChecksum != null)
                    {
                        writer.WriteIxiVarInt(walletStateChecksum.Length);
                        writer.Write(walletStateChecksum);
                    }
                    else
                    {
                        writer.WriteIxiVarInt((int)0);
                    }

                    if (signatureFreezeChecksum != null)
                    {
                        writer.WriteIxiVarInt(signatureFreezeChecksum.Length);
                        writer.Write(signatureFreezeChecksum);
                    }
                    else
                    {
                        writer.WriteIxiVarInt((int)0);
                    }

                    writer.WriteIxiVarInt(difficulty);
                    writer.WriteIxiVarInt(timestamp);

                    writer.WriteIxiVarInt(lastSuperBlockNum);

                    if (lastSuperBlockChecksum != null)
                    {
                        writer.WriteIxiVarInt(lastSuperBlockChecksum.Length);
                        writer.Write(lastSuperBlockChecksum);
                    }
                    else
                    {
                        writer.WriteIxiVarInt((int)0);
                    }

                    if (include_sb_segments)
                    {
                        writer.WriteIxiVarInt(superBlockSegments.Count);
                        foreach (var entry in superBlockSegments)
                        {
                            writer.WriteIxiVarInt(entry.Key);
                            writer.WriteIxiVarInt(entry.Value.blockChecksum.Length);
                            writer.Write(entry.Value.blockChecksum);
                        }
                    }
                    else
                    {
                        writer.WriteIxiVarInt((int)0);
                    }

                    if (blockProposer != null)
                    {
                        writer.WriteIxiVarInt(blockProposer.Length);
                        writer.Write(blockProposer);
                    }
                    else
                    {
                        writer.WriteIxiVarInt((int)0);
                    }

#if TRACE_MEMSTREAM_SIZES
                    Logging.info(String.Format("Block::getBytes: {0}", m.Length));
#endif
                }

                return m.ToArray();
            }
        }

        private byte[] getBytesV10(bool include_sb_segments = true, bool frozen_sigs_only = true, bool for_checksum = false, bool asBlockHeader = false)
        {
            using (MemoryStream m = new MemoryStream(1048576))
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.WriteIxiVarInt(version);

                    writer.WriteIxiVarInt(blockNum);

                    if (lastBlockChecksum != null)
                    {
                        writer.WriteIxiVarInt(lastBlockChecksum.Length);
                        writer.Write(lastBlockChecksum);
                    }
                    else
                    {
                        writer.WriteIxiVarInt((int)0);
                    }

                    if (signatureFreezeChecksum != null)
                    {
                        writer.WriteIxiVarInt(signatureFreezeChecksum.Length);
                        writer.Write(signatureFreezeChecksum);
                    }
                    else
                    {
                        writer.WriteIxiVarInt((int)0);
                    }

                    // Write the number of transactions
                    ulong num_transactions = getTransactionsCount();
                    writer.WriteIxiVarInt(num_transactions);

                    if (receivedPitChecksum != null)
                    {
                        writer.WriteIxiVarInt(receivedPitChecksum.Length);
                        writer.Write(receivedPitChecksum);
                    }
                    else
                    {
                        if (pitChecksum != null)
                        {
                            writer.WriteIxiVarInt(pitChecksum.Length);
                            writer.Write(pitChecksum);
                        }
                        else
                        {
                            writer.WriteIxiVarInt((int)0);
                        }
                    }

                    writer.WriteIxiVarInt(timestamp);

                    writer.WriteIxiVarInt(difficulty);

                    if (blockNum == 1)
                    {
                        writer.Write(signerBits);
                    }
                    else if (lastSuperBlockChecksum != null)
                    {
                        writer.Write(signerBits);

                        writer.WriteIxiVarInt(lastSuperBlockNum);

                        writer.WriteIxiVarInt(lastSuperBlockChecksum.Length);
                        writer.Write(lastSuperBlockChecksum);

                        if (include_sb_segments)
                        {
                            writer.WriteIxiVarInt(superBlockSegments.Count);

                            // TODO optimize
                            // Ensure the correct order; superblock segments are built in the reverse order
                            var orderedSbSegments = superBlockSegments.OrderBy(x => x.Key);
                            foreach (var entry in orderedSbSegments)
                            {
                                writer.WriteIxiVarInt(entry.Value.blockChecksum.Length);
                                writer.Write(entry.Value.blockChecksum);
                            }
                        }
                        else
                        {
                            writer.WriteIxiVarInt((int)0);
                        }
                    }

                    writer.WriteIxiVarInt(walletStateChecksum.Length);
                    writer.Write(walletStateChecksum);

                    if (version >= BlockVer.v11)
                    {
                        writer.WriteIxiVarInt(regNameStateChecksum.Length);
                        writer.Write(regNameStateChecksum);
                        writer.WriteIxiNumber(totalFee);
                    }

                    if (!for_checksum)
                    {
                        writer.Write(getSignaturesBytes(frozen_sigs_only, asBlockHeader));

                        if (version < BlockVer.v6
                            || !asBlockHeader)
                        {
                            // Write each txid
                            writer.Write(getTransactionIDsBytes());
                        }
                    }

#if TRACE_MEMSTREAM_SIZES
                    Logging.info(String.Format("Block::getBytes: {0}", m.Length));
#endif
                }

                return m.ToArray();
            }
        }

        /// <summary>
        ///  Retrieves the block header in its serialized, 'byte stream' format. See also `BlockHeader(byte[] bytes)`.
        /// </summary>
        /// <remarks>
        ///  A block header can be serialized for network transmission using this function. All relevant fields will be encoded and a byte buffer will
        ///  be returned. The byte buffer contains a copy of the block header, so no thread synchronization is required.
        /// </remarks>
        /// <returns>Byte buffer with the serialized block header.</returns>
        /// TODO Omega remove
        public byte[] getBytesLegacyHeader()
        {
            using (MemoryStream m = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.Write(version);

                    writer.Write(blockNum);

                    if (version < BlockVer.v6)
                    {
                        // Write the number of transactions
                        int num_transactions = transactions.Count;
                        writer.Write(num_transactions);

                        // Write each wallet
                        foreach (byte[] txid in transactions)
                        {
                            writer.Write(Transaction.getTxIdString(txid));
                        }
                    }
                    else
                    {
                        if (receivedPitChecksum != null)
                        {
                            writer.Write(receivedPitChecksum.Length);
                            writer.Write(receivedPitChecksum);
                        }
                        else
                        {
                            writer.Write(pitChecksum.Length);
                            writer.Write(pitChecksum);
                        }
                    }

                    writer.Write(blockChecksum.Length);
                    writer.Write(blockChecksum);

                    if (lastBlockChecksum != null)
                    {
                        writer.Write(lastBlockChecksum.Length);
                        writer.Write(lastBlockChecksum);
                    }
                    else
                    {
                        writer.Write((int)0);
                    }

                    if (walletStateChecksum != null)
                    {
                        writer.Write(walletStateChecksum.Length);
                        writer.Write(walletStateChecksum);
                    }
                    else
                    {
                        writer.Write((int)0);
                    }

                    if (signatureFreezeChecksum != null)
                    {
                        writer.Write(signatureFreezeChecksum.Length);
                        writer.Write(signatureFreezeChecksum);
                    }
                    else
                    {
                        writer.Write((int)0);
                    }

                    writer.Write(difficulty);

                    writer.Write(lastSuperBlockNum);

                    if (lastSuperBlockChecksum != null)
                    {
                        writer.Write(lastSuperBlockChecksum.Length);
                        writer.Write(lastSuperBlockChecksum);
                    }
                    else
                    {
                        writer.Write((int)0);
                    }

                    writer.Write(superBlockSegments.Count);
                    foreach (var entry in superBlockSegments)
                    {
                        writer.Write(entry.Key);
                        writer.Write(entry.Value.blockChecksum.Length);
                        writer.Write(entry.Value.blockChecksum);
                    }

                    writer.Write(timestamp);

                    if (version == 9)
                    {
                        byte[] proposer;
                        if (blockProposer != null)
                        {
                            proposer = blockProposer;
                        }
                        else
                        {
                            proposer = signatures.First().recipientPubKeyOrAddress.addressWithChecksum;
                        }
                        writer.WriteIxiVarInt(proposer.Length);
                        writer.Write(proposer);
                    }
                    else
                    {
                        writer.WriteIxiVarInt((int)0);
                    }
                }
                return m.ToArray();
            }
        }

        /// <summary>
        ///  Implementation of block equality.
        /// </summary>
        /// <remarks>
        ///  Due to how a distributed ledger works as a technology, the comparison must only examine certain checksums of both blocks
        ///  to verify whether they are equal or not.
        /// </remarks>
        /// <param name="b">Other block, sometimes called the RHS (Right-hand-side)</param>
        /// <returns>True if the blocks are equal.</returns>
        public bool Equals(Block b)
        {
            if (!b.blockChecksum.SequenceEqual(blockChecksum))
            {
                return false;
            }

            if (b.signatureFreezeChecksum != null && signatureFreezeChecksum != null)
            {
                if (!b.signatureFreezeChecksum.SequenceEqual(signatureFreezeChecksum))
                {
                    return false;
                }
            }
            else if (b.signatureFreezeChecksum != null || signatureFreezeChecksum != null)
            {
                return false;
            }

            if (!b.calculateSignatureChecksum().SequenceEqual(calculateSignatureChecksum()))
            {
                return false;
            }
            return true;
        }

        /// <summary>
        ///  Adds an Ixian `Transaction` to the block. The transaction must already be present in the TransactionPool.
        /// </summary>
        /// <remarks>
        ///  Note that the transaction is not executed against the `WalletState` when it's added to the block with this function.
        ///  It is the responsibiltiy of the Master Node implementation to ensure that all transactions, which are added to a specific block,
        ///  are also applied against the WalletState, so that the walletStateSchecksum represents the finishing state.
        /// </remarks>
        /// <param name="txid">ID of the transaction to add.</param>
        /// <returns>True, if the transaction was added successfully.</returns>
        public bool addTransaction(byte[] txid)
        {
            if (compacted)
            {
                Logging.error("Trying to add transaction on a compacted block {0}", blockNum);
                return false;
            }
            // TODO: this assumes the transaction is properly validated as it's already in the Transaction Pool
            // Could add an additional layer of checks here, just as in the TransactionPool - to avoid tampering
            if (!transactions.Contains(txid))
            {
                transactions.Add(txid);
                if (version < BlockVer.v8)
                {
                    transactionPIT.add(UTF8Encoding.UTF8.GetBytes(Transaction.getTxIdString(txid)));
                }
                else
                {
                    transactionPIT.add(txid);
                }
            }
            else
            {
                Logging.warn("Tried to add a duplicate transaction {0} to block {1}.", txid, blockNum);
            }

            return true;
        }

        /// <summary>
        ///  Calculates the `blockChecksum` of the DLT Block, using the relevant fields.
        /// </summary>
        /// <returns>Byte value of the checksum result.</returns>
        public byte[] calculateChecksum()
        {
            if (compacted)
            {
                Logging.error("Trying to calculate checksum on a compacted block {0}", blockNum);
                return null;
            }
            if (version >= BlockVer.v10)
            {
                byte[] bytes = getBytesV10(true, false, true);
                return CryptoManager.lib.sha3_512sq(bytes);
            }
            else
            {
                return calculateChecksumLegacy();
            }
        }

        /// <summary>
        ///  Calculates the `blockChecksum` of the DLT Block header, using the relevant fields.
        /// </summary>
        /// <returns>Byte value of the checksum result.</returns>
        private byte[] calculateChecksumLegacy()
        {
            List<byte> merged_segments = new List<byte>();
            foreach (var entry in superBlockSegments.OrderBy(x => x.Key))
            {
                merged_segments.AddRange(BitConverter.GetBytes(entry.Key));
                merged_segments.AddRange(entry.Value.blockChecksum);
            }

            List<byte> rawData = new List<byte>();
            rawData.AddRange(ConsensusConfig.ixianChecksumLock);
            rawData.AddRange(BitConverter.GetBytes(version));
            rawData.AddRange(BitConverter.GetBytes(blockNum));
            if (version < BlockVer.v6)
            {
                StringBuilder merged_txids = new StringBuilder();
                foreach (byte[] txid in transactions)
                {
                    merged_txids.Append(Transaction.getTxIdString(txid));
                }

                rawData.AddRange(Encoding.UTF8.GetBytes(merged_txids.ToString()));
            }
            else
            {
                // PIT is included in checksum since v6
                if (receivedPitChecksum != null)
                {
                    rawData.AddRange(receivedPitChecksum);
                }
                else
                {
                    rawData.AddRange(pitChecksum);
                }
            }

            if (lastBlockChecksum != null)
            {
                rawData.AddRange(lastBlockChecksum);
            }

            if (walletStateChecksum != null)
            {
                rawData.AddRange(walletStateChecksum);
            }

            if (signatureFreezeChecksum != null)
            {
                rawData.AddRange(signatureFreezeChecksum);
            }

            rawData.AddRange(BitConverter.GetBytes(difficulty));
            rawData.AddRange(merged_segments);

            if (lastSuperBlockChecksum != null)
            {
                rawData.AddRange(BitConverter.GetBytes(lastSuperBlockNum));
                rawData.AddRange(lastSuperBlockChecksum);
            }

            if (version >= BlockVer.v7)
            {
                rawData.AddRange(BitConverter.GetBytes(timestamp));
            }

            if (version == BlockVer.v9)
            {
                if (blockProposer == null)
                {
                    blockProposer = signatures.First().recipientPubKeyOrAddress.addressWithChecksum;
                }
                rawData.AddRange(blockProposer);
            }

            if (version <= BlockVer.v2)
            {
                return Crypto.sha512quTrunc(rawData.ToArray());
            }
            else
            {
                return Crypto.sha512sqTrunc(rawData.ToArray());
            }
        }

        /// <summary>
        ///  Calculates the checksum of all signatures on this block.
        /// </summary>
        /// <remarks>
        ///  This is used for the signature freeze functionality of the Ixian DLT. See remarks  on the `signatureFreezeChecksum` field for details.
        /// </remarks>
        /// <returns>Byte value of the signature checksum.</returns>
        public byte[] calculateSignatureChecksum()
        {
            if (compacted)
            {
                Logging.error("Trying to calculate signature checksum on a compacted block {0}", blockNum);
                return null;
            }

            // Sort the signature first
            List<BlockSignature> sortedSigs = null;
            lock (signatures)
            {
                if (frozenSignatures != null)
                {
                    sortedSigs = new List<BlockSignature>(frozenSignatures);
                }
                else
                {
                    sortedSigs = new List<BlockSignature>(signatures);
                }
            }
            if (blockNum != 1 && version >= BlockVer.v10 && IxianHandler.getBlockHeader(blockNum - 1).version >= BlockVer.v10)
            {
                //sortedSigs = sortedSigs.OrderBy(x => x.powSolution.difficulty, Comparer<IxiNumber>.Default).ThenBy(x => x.recipientPubKeyOrAddress.addressNoChecksum, new ByteArrayComparer()).ToList();
            }
            else
            {
                sortedSigs.Sort((x, y) => _ByteArrayComparer.Compare(x.recipientPubKeyOrAddress.getInputBytes(true), y.recipientPubKeyOrAddress.getInputBytes(true)));
            }

            // Merge the sorted signatures
            using (MemoryStream m = new MemoryStream(1536000))
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.Write(BitConverter.GetBytes(blockNum));
                    foreach (BlockSignature sig in sortedSigs)
                    {
                        if (version >= BlockVer.v10)
                        {
                            byte[] sigBytes = sig.getBytesForBlock(false, true);
                            writer.WriteIxiVarInt(sigBytes.Length);
                            writer.Write(sigBytes);
                        }
                        else if (version > BlockVer.v3)
                        {
                            writer.Write(sig.recipientPubKeyOrAddress.getInputBytes(true));
                        }
                        else
                        {
                            writer.Write(sig.signature);
                        }
                    }
                }

                // Generate a checksum from the merged sorted signatures
                byte[] checksum = null;
                if (version <= BlockVer.v2)
                {
                    checksum = Crypto.sha512quTrunc(m.ToArray());
                }
                else if (version < BlockVer.v10)
                {
                    checksum = Crypto.sha512sqTrunc(m.ToArray());
                }
                else
                {
                    checksum = CryptoManager.lib.sha3_512sq(m.ToArray());
                }
                return checksum;
            }
        }

        /// <summary>
        ///  Signs the Block with the running DLT Master Node's private key.
        /// </summary>
        /// <remarks>
        ///  Signing the block indicates that the node has executed all transactions, specified in this block and has confirmed that the resulting
        ///  state of all wallets (`WalletState`) matches the one in the `walletStateChecksum` field. The starting point for the transactions is
        ///  the Wallet State from the previous block.
        ///  The resulting signature may include either the node's public key, or its signing address, depending if the public key can be obtained through other means.
        ///  An example of this is when this node's public key is present in the Presence List.
        /// </remarks>
        /// <returns>Byte array with the node's signature and public key or address.</returns>
        public BlockSignature applySignature(SignerPowSolution powSolution)
        {
            if (compacted)
            {
                Logging.error("Trying to apply signature on a compacted block {0}", blockNum);
                return null;
            }

            // Note: we don't need any further validation, since this block has already passed through BlockProcessor.verifyBlock() at this point.
            Address myAddress = IxianHandler.getWalletStorage().getPrimaryAddress();
            var sig = getSignature(myAddress);
            if (sig != null)
            {
                if (powSolution == null
                    || (powSolution != null && powSolution.difficulty <= sig.powSolution.difficulty))
                {
                    return null;
                }
                signatures.Remove(sig);
            }

            BlockSignature newSig = new BlockSignature();
            newSig.blockNum = blockNum;
            newSig.blockHash = blockChecksum;
            newSig.recipientPubKeyOrAddress = myAddress;

            byte[] dataToSign = blockChecksum;
            if (blockNum != 1 && version >= BlockVer.v10 && IxianHandler.getLastBlockVersion() >= BlockVer.v10)
            {
                if (powSolution == null)
                {
                    Logging.warn("Trying to apply signature on block #{0} but PoW Signing solution isn't ready yet.", blockNum);
                    return null;
                }
                if (powSolution.blockNum + ConsensusConfig.getPlPowBlocksValidity(version) < blockNum)
                {
                    Logging.warn("Trying to apply signature on block #{0} but PoW Signing solution is too old {1} < {2}.", blockNum, powSolution.blockNum + ConsensusConfig.getPlPowBlocksValidity(version), blockNum);
                    return null;
                }
                if (powSolution.difficulty < IxianHandler.getMinSignerPowDifficulty(blockNum, version, timestamp))
                {
                    Logging.warn("Trying to apply signature on block #{0} but difficulty of PoW Signing solution is too small {1} < {2}.", blockNum, powSolution.difficulty, IxianHandler.getMinSignerPowDifficulty(blockNum, version, timestamp));
                    return null;
                }
                newSig.powSolution = powSolution;
                dataToSign = new byte[blockChecksum.Length + powSolution.solution.Length];
                Array.Copy(blockChecksum, dataToSign, blockChecksum.Length);
                Array.Copy(powSolution.solution, 0, dataToSign, blockChecksum.Length, powSolution.solution.Length);
                newSig.signature = powSolution.sign(dataToSign);
            }
            else
            {
                byte[] private_key = IxianHandler.getWalletStorage().getPrimaryPrivateKey();

                Wallet w = IxianHandler.getWallet(myAddress);

                if (w.publicKey == null)
                {
                    byte[] myPubKey = IxianHandler.getWalletStorage().getPrimaryPublicKey();
                    newSig.recipientPubKeyOrAddress = new Address(myPubKey);
                }

                newSig.signature = CryptoManager.lib.getSignature(dataToSign, private_key);
            }

            lock (signatures)
            {
                signatures.Add(newSig);
            }

            Logging.info("Signed block #{0}.", blockNum);

            return newSig;
        }

        /// <summary>
        ///  Checks if the block's signatures field contains the signature of the specified node. Either the node's address or its public key is accepted.
        /// </summary>
        /// <param name="p_address">The signer's address.</param>
        /// <returns></returns>
        public bool containsSignature(Address p_address)
        {
            if (compacted)
            {
                Logging.error("Trying to check if compacted block {0} contains signature", blockNum);
                return false;
            }

            byte[] cmp_address = p_address.addressNoChecksum;

            lock (signatures)
            {
                foreach (BlockSignature sig in signatures)
                {
                    if (cmp_address.SequenceEqual(sig.recipientPubKeyOrAddress.addressNoChecksum))
                    {
                        return true;
                    }
                }
                return false;
            }
        }

        public BlockSignature getSignature(Address p_address)
        {
            if (compacted)
            {
                Logging.error("Trying to get signature on compacted block {0}.", blockNum);
                return null;
            }

            byte[] cmp_address = p_address.addressNoChecksum;

            lock (signatures)
            {
                foreach (BlockSignature sig in signatures)
                {
                    if (cmp_address.SequenceEqual(sig.recipientPubKeyOrAddress.addressNoChecksum))
                    {
                        return sig;
                    }
                }
                return null;
            }
        }

        /// <summary>
        ///  Checks if the block's signatures field contains exactly the same signature of the specified node.
        /// </summary>
        /// <param name="sigToCheck">Signature to check.</param>
        /// <returns></returns>
        public bool containsSignature(BlockSignature sigToCheck)
        {
            if (compacted)
            {
                Logging.error("Trying to check if compacted block {0} contains signature", blockNum);
                return false;
            }

            byte[] addressToCheck = sigToCheck.recipientPubKeyOrAddress.addressNoChecksum;

            lock (signatures)
            {
                foreach (BlockSignature sig in signatures)
                {
                    if (sig.recipientPubKeyOrAddress.addressNoChecksum.SequenceEqual(addressToCheck))
                    {
                        if (sig.powSolution == null && sigToCheck.powSolution == null)
                        {
                            return true;
                        }

                        if (sig.powSolution != null && sigToCheck.powSolution != null
                            && sig.powSolution.blockNum == sigToCheck.powSolution.blockNum
                            && sig.powSolution.solution.SequenceEqual(sigToCheck.powSolution.solution))
                        {
                            return true;
                        }
                    }
                }
                return false;
            }
        }

        /// <summary>
        ///  Mergest the signatures of two blocks without duplicating.
        /// </summary>
        /// <remarks>
        ///  This is used when the Master Node has been working on one set of signatures but receives the same block with a different set of signatures and wishes
        ///  to merge the two lists together.
        ///  The function returns the list signatures which were in the `other` block, but not in this, while at the same time adding the new signatures to this block.
        /// </remarks>
        /// <param name="other">The other block (should be the same `blockNum`) whose signatures will be merged.</param>
        /// <returns>The list of 'new' signatures.</returns>
        public List<BlockSignature> addSignaturesFrom(Block other, bool verifySigs)
        {
            if (compacted)
            {
                Logging.error("Trying to add signature from block on a compacted block {0}", blockNum);
                return null;
            }
            // Note: we don't need any further validation, since this block has already passed through BlockProcessor.verifyBlock() at this point.
            int count = 0;
            List<BlockSignature> added_signatures = new List<BlockSignature>();
            foreach (BlockSignature sig in other.signatures)
            {
                var localSig = getSignature(sig.recipientPubKeyOrAddress);
                if (localSig != null)
                {
                    if (localSig.powSolution == null
                        || (localSig.powSolution != null && localSig.powSolution.difficulty >= sig.powSolution.difficulty))
                    {
                        continue;
                    }
                }

                /* Should be already handled by verifyBlock
                if (PresenceList.getPresenceByAddress(sig.recipientPubKeyOrAddress) == null)
                {
                    Logging.info("Received signature for block {0} whose signer isn't in the PL", blockNum);
                    continue;
                }*/

                if (verifySigs)
                {
                    if (!verifySignature(sig))
                    {
                        continue;
                    }
                }

                lock (signatures)
                {
                    if (localSig != null)
                    {
                        signatures.Remove(localSig);
                    }
                    signatures.Add(sig);
                }
                added_signatures.Add(sig);
                count++;
            }
            if (count > 0)
            {
                //Logging.info(String.Format("Merged {0} new signatures from incoming block.", count));
                return added_signatures;
            }
            return null;
        }

        /// <summary>
        ///  Verifies if the given signature is valid for this block.
        /// </summary>
        /// <remarks>
        ///  Please note that this function only accepts a public key. If the signature is supplied with an address, the public key must somehow be obtained
        ///  prior to calling this function, either by taking it from the Presence List, or querying the network.
        /// </remarks>
        /// <param name="signature">Signature's byte value.</param>
        /// <param name="signer_pub_key">Public key of the signer.</param>
        /// <returns>True, if the signature validates this block.</returns>
        public bool verifySignature(BlockSignature sig)
        {
            byte[] dataToVerify = blockChecksum;
            if (blockNum != 1 && version >= BlockVer.v10 && IxianHandler.getBlockHeader(blockNum - 1).version >= BlockVer.v10)
            {
                if (sig.powSolution == null)
                {
                    Logging.error("VerifySig: powSolution == null");
                    return false;
                }

                IxiNumber minPowDifficulty = IxianHandler.getMinSignerPowDifficulty(blockNum, version, timestamp);
                if (sig.powSolution.blockNum >= blockNum
                    || sig.powSolution.blockNum + ConsensusConfig.getPlPowBlocksValidity(version) < blockNum
                    || !sig.powSolution.verifySolution(minPowDifficulty))
                {
                    Logging.error("VerifySig: invalid solution");
                    return false;
                }

                dataToVerify = new byte[blockChecksum.Length + sig.powSolution.solution.Length];
                Array.Copy(blockChecksum, dataToVerify, blockChecksum.Length);
                Array.Copy(sig.powSolution.solution, 0, dataToVerify, blockChecksum.Length, sig.powSolution.solution.Length);
                dataToVerify = CryptoManager.lib.sha3_512sq(dataToVerify);
            }

            byte[] publicKey = null;
            if (blockNum != 1 && version >= BlockVer.v10 && IxianHandler.getBlockHeader(blockNum - 1).version >= BlockVer.v10)
            {
                publicKey = sig.powSolution.signingPubKey;
            }
            else
            {
                publicKey = getSignerPubKey(sig.recipientPubKeyOrAddress);
            }

            if (!CryptoManager.lib.verifySignature(dataToVerify, publicKey, sig.signature))
            {
                Logging.error("VerifySig: invalid sig");
                return false;
            }
            return true;
        }

        /// <summary>
        ///  Adds the provided signature to the block's signature list.
        /// </summary>
        /// <param name="signature">Byte value of the signature.</param>
        /// <param name="address_or_pub_key">Address or public key of the signer.</param>
        /// <returns>True, if the signature was successfully added. False is returned if the signature was already present, or was not valid.</returns>
        public bool addSignature(BlockSignature sig)
        {
            if (compacted)
            {
                Logging.error("Trying to add signature on a compacted block {0}", blockNum);
                return false;
            }
            var signer_address = sig.recipientPubKeyOrAddress;
            var local_sig = getSignature(signer_address);
            if (local_sig != null)
            {
                if (version < BlockVer.v10)
                {
                    return false;
                }
                if (local_sig.powSolution.difficulty >= sig.powSolution.difficulty)
                {
                    Logging.warn("Received signature with a lower powSolution from {0}", sig.recipientPubKeyOrAddress.ToString());
                    return false;
                }
            }

            if (!verifySignature(sig))
            {
                return false;
            }

            lock (signatures)
            {
                if (local_sig != null)
                {
                    signatures.Remove(local_sig);
                }
                signatures.Add(sig);
            }
            return true;
        }

        /// <summary>
        ///  Attempts to retrieve the public key of the signer address.
        /// </summary>
        /// <remarks>
        ///  This function accepts either a wallet address or a public key. In the latter case, the public key is returned directly, but in the former case,
        ///  the public key is looked up from the wallet. This allows easy conversion from the signatures field for use in the verify function.
        /// </remarks>
        /// <param name="address_or_pub_key">Signer address or public key.</param>
        /// <returns>Public key, matching the given address, or null, if the public key is not known.</returns>
        public byte[] getSignerPubKey(Address address)
        {
            if (compacted)
            {
                Logging.error("Trying to set signer pubkey on a compacted block {0}", blockNum);
                return null;
            }

            if (address == null)
            {
                return null;
            }

            if (address.pubKey != null)
            {
                return address.pubKey;
            }

            // Extract the public key from the walletstate
            Wallet signer_wallet = IxianHandler.getWallet(address);
            if (signer_wallet.publicKey != null)
            {
                if (signer_wallet.publicKey.Length < 50)
                {
                    Logging.error("Wallet {0} has an invalid value stored for public key ({1} bytes)!", address.ToString(), signer_wallet.publicKey == null ? 0 : signer_wallet.publicKey.Length);
                    return null;
                }
                return signer_wallet.publicKey;
            }

            return null;
        }

        /// <summary>
        ///  Verifies that the first signer of the block is block proposer.
        /// </summary>
        /// <returns>True if all signatures are valid and (optionally) match the block's checksum.</returns>
        public bool verifyBlockProposer()
        {
            if (version < BlockVer.v9
                || version >= BlockVer.v10)
            {
                return true;
            }
            if (blockProposer == null)
            {
                return true;
            }
            lock (signatures)
            {
                List<BlockSignature> tmp_sigs = null;
                if (frozenSignatures != null)
                {
                    tmp_sigs = frozenSignatures;
                }
                else
                {
                    tmp_sigs = signatures;
                }
                if (tmp_sigs != null && tmp_sigs.Count > 0)
                {
                    byte[] proposer_address = tmp_sigs[0].recipientPubKeyOrAddress.addressWithChecksum;
                    if (!blockProposer.SequenceEqual(proposer_address))
                    {
                        Logging.error("First signature on block #{0} is not from block proposer {1}.", blockNum, Base58Check.Base58CheckEncoding.EncodePlain(proposer_address));
                        return false;
                    }
                    return true;
                }
            }
            return false;
        }

        /// <summary>
        ///  Verifies that all signatures on this block are valid.
        /// </summary>
        /// <remarks>
        ///  Checks if all the given signatures and signer addresses match and are valid. In the simpler form (`skip_sig_verification`), this function
        ///  only checks that public keys for all signatures exist and that all signers are known, without cryptographically verifying that each signature
        ///  matches the block.
        /// </remarks>
        /// <param name="skip_sig_verification">False for simpler, non-cryptographic verification.</param>
        /// <returns>True if all signatures are valid and (optionally) match the block's checksum.</returns>
        public bool verifySignatures(Block local_block, bool skip_sig_verification = false)
        {
            if (compacted)
            {
                Logging.error("Trying to verify signatures on a compacted block {0}", blockNum);
                return false;
            }

            if (skip_sig_verification)
            {
                return true;
            }

            List<BlockSignature> safe_sigs;
            lock (signatures)
            {
                if (signatures.Count == 0)
                {
                    return false;
                }

                safe_sigs = new List<BlockSignature>(signatures);
            }

            int n = safe_sigs.Count;
            var results = new BlockSignature?[n];
            var seenAddresses = new ConcurrentDictionary<byte[], int>(new ByteArrayComparer());

            Parallel.For(0, n,
                new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount },
                i =>
                {
                    var sig = safe_sigs[i];
                    var signerAddress = sig.recipientPubKeyOrAddress.addressNoChecksum;

                    // Skip verification if local block already has it
                    if (local_block != null && local_block.containsSignature(sig))
                    {
                        // Skip duplicates
                        if (!seenAddresses.TryAdd(signerAddress, i))
                        {
                            return;
                        }

                        results[i] = sig;
                        return;
                    }

                    if (verifySignature(sig))
                    {
                        // Skip duplicates
                        if (!seenAddresses.TryAdd(signerAddress, i))
                        {
                            return;
                        }

                        results[i] = sig;
                    }
                });

            lock (signatures)
            {
                signatures.Clear();
                foreach (var sig in results)
                {
                    if (sig != null)
                    {
                        signatures.Add(sig);
                    }
                }

                return signatures.Count > 0;
            }
        }

        /// <summary>
        ///  Checks the signatures on the block and returns true, if the block has already been signed by the given address.
        /// </summary>
        /// <param name="address">The address to check.</param>
        /// <returns>True, if the address has already signed the block.</returns>
        public bool hasNodeSignature(Address address)
        {
            if (getNodeSignature(address) != null)
            {
                return true;
            }

            return false;
        }


        /// <summary>
        ///  Checks the signatures on the block and returns true, if the block has already been signed by the given solution.
        /// </summary>
        /// <param name="solution">The solution to check.</param>
        /// <returns>True, if the solution has already signed the block.</returns>
        public bool hasNodeSignature(byte[] solution)
        {
            if (getNodeSignature(solution) != null)
            {
                return true;
            }

            return false;
        }

        /// <summary>
        ///  Finds the signatures on the block and returns it, if the block has already been signed by the given address.
        /// </summary>
        /// <param name="address">The address to check.</param>
        /// <returns>signature, if the address has already signed the block.</returns>
        public BlockSignature getNodeSignature(Address address)
        {
            if (compacted)
            {
                Logging.error("Trying to execute hasNodeSignature on a compacted block {0}", blockNum);
                return null;
            }

            if (address == null)
            {
                return null;
            }

            // Generate an address
            byte[] node_address = address.addressNoChecksum;

            lock (signatures)
            {
                var sigs = signatures;
                if (sigs == null)
                {
                    sigs = frozenSignatures;
                }
                if (sigs == null)
                {
                    return null;
                }
                foreach (BlockSignature merged_signature in signatures)
                {
                    // Check if it matches
                    if (node_address.SequenceEqual(merged_signature.recipientPubKeyOrAddress.addressNoChecksum))
                    {
                        return merged_signature;
                    }
                }
            }

            return null;
        }

        /// <summary>
        ///  Finds the signatures on the block and returns it, if the block has already been signed by the given solution.
        /// </summary>
        /// <param name="solution">The solution to check.</param>
        /// <returns>signature, if the solution has already signed the block.</returns>
        public BlockSignature getNodeSignature(byte[] solution)
        {
            if (compacted)
            {
                Logging.error("Trying to execute hasNodeSignature on a compacted block {0}", blockNum);
                return null;
            }

            if (solution == null)
            {
                return null;
            }

            lock (signatures)
            {
                var sigs = signatures;
                if (sigs == null)
                {
                    sigs = frozenSignatures;
                }
                if (sigs == null)
                {
                    return null;
                }
                foreach (BlockSignature merged_signature in signatures)
                {
                    // Check if it matches
                    if (solution.SequenceEqual(merged_signature.powSolution.solution))
                    {
                        return merged_signature;
                    }
                }
            }

            return null;
        }

        /// <summary>
        ///  Retrieves a list of Ixian Wallet addresses from the list of signatures on this block.
        /// </summary>
        /// <remarks>
        ///  Since signatures on the block may include either an address or a public key, this function performs the necessary lookups
        ///  to return only the Wallet addresses of all signers. If the parameter `convert_pubkeys` is specified false, then the public
        ///  key lookups aren't performed and only the addresses from the signature list are returned.
        /// </remarks>
        /// <param name="convert_pubkeys">True if public key signatures should be converted back to their respective Ixian Wallet addresses.</param>
        /// <returns>List of Ixian wallets which have signed this block.</returns>
        public List<(Address address, IxiNumber difficulty)> getSignaturesWalletAddressesWithDifficulty()
        {
            if (compacted)
            {
                Logging.error("Trying to get signer wallet addresses from a compacted block {0}", blockNum);
                return null;
            }

            List<(Address address, IxiNumber difficulty)> result = new List<(Address, IxiNumber)>();

            List<BlockSignature> tmp_sigs;
            lock (signatures)
            {
                if (frozenSignatures != null)
                {
                    tmp_sigs = frozenSignatures;
                }
                else
                {
                    tmp_sigs = signatures;
                }
            }

            foreach (BlockSignature merged_signature in tmp_sigs)
            {
                // Add the address to the list
                if (merged_signature.powSolution != null)
                {
                    result.Add((merged_signature.recipientPubKeyOrAddress, merged_signature.powSolution.difficulty));
                }
                else
                {
                    result.Add((merged_signature.recipientPubKeyOrAddress, 1));
                }
            }
            if (version < BlockVer.v10)
            {
                result.Sort((x, y) => _ByteArrayComparer.Compare(x.address.addressNoChecksum, y.address.addressNoChecksum));
            }
            //result = result.OrderBy(x => x.difficulty, Comparer<IxiNumber>.Default).ThenBy(x => x.address.addressNoChecksum, new ByteArrayComparer()).ToList();
            return result;
        }

        /// <summary>
        ///  Retrives the number of signatures on this block. This function might return a larger value, because it does not check for potential duplicates.
        /// </summary>
        /// <returns>Number of signatures.</returns>
        private int getSignatureCount()
        {
            if (compacted)
            {
                return signatureCount;
            }
            else
            {
                return signatures.Count;
            }
        }

        /// <summary>
        ///  Retrives the number of signatures on this block.
        /// </summary>
        /// <returns>Number of signatures.</returns>
        public int getFrozenSignatureCount()
        {
            if (frozenSignatures != null)
            {
                return frozenSignatures.Count;
            }
            else
            {
                return getSignatureCount();
            }
        }

        /// <summary>
        ///  Allocates and sets the `walletStateChecksum`.
        /// </summary>
        /// <param name="checksum">Checksum byte value.</param>
        public void setWalletStateChecksum(byte[] checksum)
        {
            walletStateChecksum = new byte[checksum.Length];
            Array.Copy(checksum, walletStateChecksum, walletStateChecksum.Length);
        }

        /// <summary>
        ///  Allocates and sets the `regNameStateChecksum`.
        /// </summary>
        /// <param name="checksum">Checksum byte value.</param>
        public void setRegNameStateChecksum(byte[] checksum)
        {
            if (checksum == null)
            {
                regNameStateChecksum = null;
                return;
            }

            regNameStateChecksum = new byte[checksum.Length];
            Array.Copy(checksum, regNameStateChecksum, regNameStateChecksum.Length);
        }

        /// <summary>
        ///  ?
        /// </summary>
        /// <returns></returns>
        public bool pruneSignatures()
        {
            return false; // disabled for now

            if (version < BlockVer.v4)
            {
                return false;
            }

            if (compactedSigs)
            {
                return false;
            }

            compactedSigs = true;

            // TODO TODO prune frozen sigs as well
            // TODO TODO locking?

            int compacted_cnt = 0;
            List<BlockSignature> new_sigs = new List<BlockSignature>();
            foreach (var entry in signatures)
            {
                if (entry.signature != null)
                {
                    compacted_cnt++;
                    entry.signature = null;
                }
                new_sigs.Add(entry);
            }

            if (compacted_cnt > 0)
            {
                signatures = new_sigs;
                return true;
            }

            return false;
        }

        /// <summary>
        ///  Removes the signatures as part of the compaction process (superblock functionality).
        /// </summary>
        /// <returns>True if compaction was performed, false if the block is already compacted.</returns>
        public bool compact()
        {
            if (compacting || compacted)
            {
                return false;
            }

            compacting = true;

            // The following two functions should be executed before compacted is set to true
            signatureCount = getFrozenSignatureCount();
            totalSignerDifficulty = getTotalSignerDifficulty();

            frozenSignatures = null;
            signatures.Clear();

            superBlockSegments = null;

            txCount = (ulong)transactions.Count;
            transactions = null;

            compacted = true;

            return true;

        }

        /// <summary>
        ///  Writes the block's details to the log for debugging purposes.
        /// </summary>
        public void logBlockDetails()
        {
            string last_block_chksum = "";
            if (lastBlockChecksum != null)
            {
                last_block_chksum = Crypto.hashToString(lastBlockChecksum);
            }
            if (last_block_chksum.Length == 0)
            {
                last_block_chksum = "G E N E S I S  B L O C K";
            }
            Logging.info(String.Format("\t\t|- Block Number:\t {0}", blockNum));
            Logging.info(String.Format("\t\t|- Block Version:\t {0}", version));
            Logging.info(String.Format("\t\t|- Signatures:\t\t {0}", signatures.Count));
            Logging.info(String.Format("\t\t|- Block Checksum:\t {0}", Crypto.hashToString(blockChecksum)));
            Logging.info(String.Format("\t\t|- Last Block Checksum:\t {0}", last_block_chksum));
            Logging.info(String.Format("\t\t|- WalletState Checksum: {0}", Crypto.hashToString(walletStateChecksum)));
            Logging.info(String.Format("\t\t|- RegNameState Checksum: {0}", Crypto.hashToString(regNameStateChecksum)));
            Logging.info(String.Format("\t\t|- Sig Freeze Checksum:\t {0}", Crypto.hashToString(signatureFreezeChecksum)));
            Logging.info(String.Format("\t\t|- Mining Difficulty:\t {0}", difficulty));
            Logging.info(String.Format("\t\t|- Signing Difficulty:\t {0}", signerBits));
            Logging.info(String.Format("\t\t|- Transaction Count:\t {0}", transactions.Count));
            Logging.info(String.Format("\t\t|- Total Fees:\t {0}", totalFee.ToString()));
        }

        /// <summary>
        ///  Test if the block is the genesis block.
        /// </summary>
        public bool isGenesis { get { return this.blockNum == 0 && this.lastBlockChecksum == null; } }

        public void setFrozenSignatures(List<BlockSignature> frozen_sigs)
        {
            if (compacted)
            {
                Logging.error("Trying to set frozen signatures on a compacted block {0}", blockNum);
                return;
            }

            lock (signatures)
            {
                frozenSignatures = frozen_sigs;
            }
        }

        public IxiNumber getTotalSignerDifficulty()
        {
            if (compacted)
            {
                return totalSignerDifficulty;
            }

            IxiNumber totalDiff = 0;
            List<BlockSignature> sigs;
            lock (signatures)
            {
                if (frozenSignatures != null)
                {
                    sigs = new List<BlockSignature>(frozenSignatures);
                }
                else
                {
                    sigs = new List<BlockSignature>(signatures);
                }
            }
            foreach (BlockSignature sig in sigs)
            {
                if (sig.powSolution == null)
                {
                    totalDiff += 1;
                }
                else
                {
                    totalDiff += sig.powSolution.difficulty;
                }
            }
            return totalDiff;
        }

        public ulong getTransactionsCount()
        {
            return (transactions != null && transactions.Count > 0) ? (ulong)transactions.Count : txCount;
        }

        public byte[] getSignaturesBytes(bool frozenSigsOnly, bool asBlockHeader)
        {
            using (MemoryStream m = new MemoryStream(640000))
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    lock (signatures)
                    {
                        if (version < BlockVer.v10)
                        {
                            asBlockHeader = false;
                        }
                        List<BlockSignature> tmp_signatures = signatures;
                        if (frozenSigsOnly && frozenSignatures != null)
                        {
                            tmp_signatures = frozenSignatures;
                        }

                        if (tmp_signatures == null || tmp_signatures.Count == 0)
                        {
                            writer.WriteIxiVarInt(0);
                            writer.WriteIxiVarInt(signatureCount);
                            writer.WriteIxiVarInt(SignerPowSolution.difficultyToBits(totalSignerDifficulty));
                        }
                        else
                        {
                            // Write the number of signatures
                            int num_signatures = tmp_signatures.Count;

                            if (num_signatures > ConsensusConfig.maximumBlockSigners * 2)
                            {
                                num_signatures = ConsensusConfig.maximumBlockSigners * 2;
                            }

                            writer.WriteIxiVarInt(num_signatures);

                            // Write each signature
                            for (int i = 0; i < num_signatures; i++)
                            {
                                BlockSignature signature = tmp_signatures[i];

                                byte[] sigBytes = signature.getBytesForBlock(true, asBlockHeader);
                                writer.WriteIxiVarInt(sigBytes.Length);
                                writer.Write(sigBytes);
                            }
                        }
                    }
                }
                return m.ToArray();
            }
        }

        public void setSignaturesFromBytes(byte[] sigBytes)
        {
            using (MemoryStream m = new MemoryStream(sigBytes))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    int num_signatures = (int)reader.ReadIxiVarUInt();

                    if (num_signatures == 0)
                    {
                        signatureCount = (int)reader.ReadIxiVarUInt();
                        ulong tmpSignerDiff = reader.ReadIxiVarUInt();
                        if (version >= BlockVer.v10)
                        {
                            totalSignerDifficulty = SignerPowSolution.bitsToDifficulty(tmpSignerDiff);
                        }
                    }
                    else
                    {
                        if (num_signatures > ConsensusConfig.maximumBlockSigners * 2)
                        {
                            throw new Exception("Block #" + blockNum + " has more than " + (ConsensusConfig.maximumBlockSigners * 2) + " signatures");
                        }

                        for (int i = 0; i < num_signatures; i++)
                        {
                            int sigLen = (int)reader.ReadIxiVarUInt();
                            BlockSignature sig = new BlockSignature(reader.ReadBytes(sigLen), false);

                            if (!containsSignature(sig.recipientPubKeyOrAddress))
                            {
                                signatures.Add(sig);
                            }
                        }
                    }
                }
            }
        }

        public byte[] getTransactionIDsBytes()
        {
            using (MemoryStream m = new MemoryStream(640000))
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    foreach (byte[] txid in transactions)
                    {
                        writer.WriteIxiVarInt(txid.Length);
                        writer.Write(txid);
                    }
                }
                return m.ToArray();
            }
        }

        public void setTransactionIDsFromBytes(byte[] txIDBytes)
        {
            using (MemoryStream m = new MemoryStream(txIDBytes))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    if (txCount > 0)
                    {
                        // Get the transaction ids
                        for (ulong i = 0; i < txCount; i++)
                        {
                            int txid_len = (int)reader.ReadIxiVarUInt();
                            if (txid_len > 128)
                            {
                                throw new Exception("Block #" + blockNum + " txid len " + txid_len + "B is bigger than 128B.");
                            }
                            byte[] txid = reader.ReadBytes(txid_len);
                            if (transactions.Contains(txid))
                            {
                                // Block contains duplicate txid
                                throw new Exception("Block #" + blockNum + " contains duplicate txid");
                            }
                            transactions.Add(txid);
                            if (version < BlockVer.v8)
                            {
                                transactionPIT.add(UTF8Encoding.UTF8.GetBytes(Transaction.getTxIdString(txid)));
                            }
                            else
                            {
                                transactionPIT.add(txid);
                            }

                        }

                        if (receivedPitChecksum != null
                            && version >= BlockVer.v6
                            && !pitChecksum.SequenceEqual(receivedPitChecksum))
                        {
                            throw new Exception("Invalid PIT Checksum.");
                        }
                    }
                }
            }
        }
    }
}
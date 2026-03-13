// Copyright (C) 2017-2025 Ixian
// This file is part of Ixian DLT - www.github.com/ixian-platform/Ixian-DLT
//
// Ixian DLT is free software: you can redistribute it and/or modify
// it under the terms of the MIT License as published
// by the Open Source Initiative.
//
// Ixian DLT is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// MIT License for more details.

using IXICore;
using IXICore.Meta;
using IXICore.Utils;
using Org.BouncyCastle.Bcpg;
using RocksDbSharp;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace IXICore
{
    namespace Storage
    {
        class RocksDBInternal
        {
            public string dbPath { get; private set; }
            private RocksDb? database = null;
            // global column families
            private ColumnFamilyHandle? rocksCFBlocks = null;
            private ColumnFamilyHandle? rocksCFTransactions = null;
            private ColumnFamilyHandle? rocksCFMeta = null;
            // index column families
            // block
            private StorageIndex? idxBlocksChecksum = null;
            // transaction
            private StorageIndex? idxTXAppliedType = null;
            private StorageIndex? idxAddressTXs = null;
            private readonly object rockLock = new object();

            private readonly byte[] BLOCKS_KEY_HEADER = new byte[] { 0 };
            private readonly byte[] BLOCKS_KEY_TXS = new byte[] { 1 };
            private readonly byte[] BLOCKS_KEY_SIGNERS = new byte[] { 2 };
            private readonly byte[] BLOCKS_KEY_SIGNERS_COMPACT = new byte[] { 3 };

            private readonly byte[] BLOCKS_KEY_PRIMARY_INDEX = new byte[] { 0 };

            private readonly byte[] META_KEY_DB_VERSION = Encoding.UTF8.GetBytes("db_version");
            private readonly byte[] META_KEY_MIN_BLOCK = Encoding.UTF8.GetBytes("min_block");
            private readonly byte[] META_KEY_MAX_BLOCK = Encoding.UTF8.GetBytes("max_block");
            private readonly byte[] META_KEY_COMPACTION_TYPE = Encoding.UTF8.GetBytes("compaction_type");

            private readonly byte[] COMPACTION_TYPE_NONE = new byte[] { 0 };
            private readonly byte[] COMPACTION_TYPE_SIGS = new byte[] { 1 };
            private readonly byte[] COMPACTION_TYPE_FULL = new byte[] { 2 };

            public ulong minBlockNumber { get; private set; }
            public ulong maxBlockNumber { get; private set; }
            public int dbVersion { get; private set; }
            public byte[] compactionType { get; private set; }
            public bool isOpen
            {
                get
                {
                    return database != null;
                }
            }
            public DateTime lastUsedTime { get; private set; }
            // Caches (shared with other rocksDb
            private Cache blockCache;

            public RocksDBInternal(string dbPath, Cache blockCache)
            {
                minBlockNumber = 0;
                maxBlockNumber = 0;
                dbVersion = 0;
                compactionType = COMPACTION_TYPE_NONE;

                this.dbPath = dbPath;
                this.blockCache = blockCache;
            }

            public void openDatabase()
            {
                if (database != null)
                {
                    throw new Exception(String.Format("Rocks Database '{0}' is already open.", dbPath));
                }
                lock (rockLock)
                {
                    var rocksOptions = new DbOptions()
                        .SetCreateIfMissing(true)
                        .SetCreateMissingColumnFamilies(true)
                        .SetKeepLogFileNum(2)
                        .SetMaxLogFileSize(1 * 1024 * 1024)
                        .SetRecycleLogFileNum(10)
                        .IncreaseParallelism(Environment.ProcessorCount)
                        .SetMaxBackgroundCompactions(Environment.ProcessorCount)
                        .SetMaxBackgroundFlushes(Math.Max(1, Math.Min(4, Environment.ProcessorCount / 2)))
                        .SetAllowMmapReads(false)
                        .SetAllowMmapWrites(false)
                        .SetTargetFileSizeBase(256 * 1024 * 1024)
                        .SetTargetFileSizeMultiplier(2)
                        .SetCompression(Compression.Zstd)
                        .SetLevelCompactionDynamicLevelBytes(true)
                        .SetCompactionReadaheadSize(4 * 1024 * 1024);

                    // blocks
                    var blocksBbto = new BlockBasedTableOptions();
                    blocksBbto.SetBlockCache(blockCache.Handle);
                    blocksBbto.SetBlockSize(128 * 1024);
                    blocksBbto.SetCacheIndexAndFilterBlocks(true);
                    blocksBbto.SetPinL0FilterAndIndexBlocksInCache(true);
                    blocksBbto.SetFilterPolicy(BloomFilterPolicy.Create(16, true));
                    blocksBbto.SetWholeKeyFiltering(true);
                    blocksBbto.SetFormatVersion(6);

                    // transactions
                    var txBbto = new BlockBasedTableOptions();
                    txBbto.SetBlockCache(blockCache.Handle);
                    txBbto.SetBlockSize(64 * 1024);
                    txBbto.SetCacheIndexAndFilterBlocks(true);
                    txBbto.SetPinL0FilterAndIndexBlocksInCache(true);
                    txBbto.SetFilterPolicy(BloomFilterPolicy.Create(16, true));
                    txBbto.SetWholeKeyFiltering(true);
                    txBbto.SetFormatVersion(6);

                    // meta
                    var metaBbto = new BlockBasedTableOptions();
                    metaBbto.SetBlockCache(blockCache.Handle);
                    metaBbto.SetBlockSize(4 * 1024);
                    metaBbto.SetCacheIndexAndFilterBlocks(true);
                    metaBbto.SetPinL0FilterAndIndexBlocksInCache(true);
                    metaBbto.SetFilterPolicy(BloomFilterPolicy.Create(14, true));
                    metaBbto.SetWholeKeyFiltering(true);
                    metaBbto.SetFormatVersion(6);

                    // index CFs
                    var blocksIndexBbto = new BlockBasedTableOptions();
                    blocksIndexBbto.SetBlockCache(blockCache.Handle);
                    blocksIndexBbto.SetBlockSize(16 * 1024);
                    blocksIndexBbto.SetCacheIndexAndFilterBlocks(true);
                    blocksIndexBbto.SetPinL0FilterAndIndexBlocksInCache(true);
                    blocksIndexBbto.SetFilterPolicy(BloomFilterPolicy.Create(14, true));
                    blocksIndexBbto.SetWholeKeyFiltering(true);
                    blocksIndexBbto.SetFormatVersion(6);

                    var txIndexBbto = new BlockBasedTableOptions();
                    txIndexBbto.SetBlockCache(blockCache.Handle);
                    txIndexBbto.SetBlockSize(32 * 1024);
                    txIndexBbto.SetCacheIndexAndFilterBlocks(true);
                    txIndexBbto.SetPinL0FilterAndIndexBlocksInCache(true);
                    txIndexBbto.SetFilterPolicy(BloomFilterPolicy.Create(16, true));
                    txIndexBbto.SetWholeKeyFiltering(false);
                    txIndexBbto.SetFormatVersion(6);

                    var columnFamilies = new ColumnFamilies
                    {
                        { "blocks", new ColumnFamilyOptions()
                            .SetBlockBasedTableFactory(blocksBbto)
                            .SetWriteBufferSize(32UL << 20)
                            .SetMaxWriteBufferNumber(2)
                            .SetMinWriteBufferNumberToMerge(1)
                            .SetPrefixExtractor(SliceTransform.CreateFixedPrefix(32))
                        },
                        { "transactions", new ColumnFamilyOptions()
                            .SetBlockBasedTableFactory(txBbto)
                            .SetWriteBufferSize(128UL << 20)
                            .SetMaxWriteBufferNumber(4)
                            .SetMinWriteBufferNumberToMerge(2)
                            .SetPrefixExtractor(SliceTransform.CreateFixedPrefix(16))
                        },
                        { "meta", new ColumnFamilyOptions()
                            .SetBlockBasedTableFactory(metaBbto)
                            .OptimizeForPointLookup(128)
                            .SetWriteBufferSize(64UL << 10)
                            .SetMaxWriteBufferNumber(1)
                        },
                        { "index_blocks_checksum_meta", new ColumnFamilyOptions()
                            .SetBlockBasedTableFactory(blocksIndexBbto)
                            .SetWriteBufferSize(2UL << 20)
                            .SetMaxWriteBufferNumber(2)
                            .SetMinWriteBufferNumberToMerge(1)
                            .SetPrefixExtractor(SliceTransform.CreateFixedPrefix(8))
                        },
                        { "index_tx_applied_type", new ColumnFamilyOptions()
                            .SetBlockBasedTableFactory(txIndexBbto)
                            .SetWriteBufferSize(8UL << 20)
                            .SetMaxWriteBufferNumber(4)
                            .SetMinWriteBufferNumberToMerge(2)
                            .SetPrefixExtractor(SliceTransform.CreateFixedPrefix(8))
                        },
                        { "index_address_txs", new ColumnFamilyOptions()
                            .SetBlockBasedTableFactory(txIndexBbto)
                            .SetWriteBufferSize(16UL << 20)
                            .SetMaxWriteBufferNumber(6)
                            .SetMinWriteBufferNumberToMerge(3)
                            .SetPrefixExtractor(SliceTransform.CreateFixedPrefix(16))
                        }
                    };

                    database = RocksDb.Open(rocksOptions, dbPath, columnFamilies);

                    // initialize column family handles
                    rocksCFBlocks = database.GetColumnFamily("blocks");
                    rocksCFTransactions = database.GetColumnFamily("transactions");
                    rocksCFMeta = database.GetColumnFamily("meta");

                    // initialize indexes
                    idxBlocksChecksum = new StorageIndex("index_blocks_checksum_meta", database);
                    idxTXAppliedType = new StorageIndex("index_tx_applied_type", database);
                    idxAddressTXs = new StorageIndex("index_address_txs", database);

                    // read initial meta values
                    byte[] versionBytes = database.Get(META_KEY_DB_VERSION, rocksCFMeta);
                    if (versionBytes == null)
                    {
                        database.Put(META_KEY_DB_VERSION, dbVersion.GetBytesBE(), rocksCFMeta);
                        database.Put(META_KEY_MIN_BLOCK, minBlockNumber.GetBytesBE(), rocksCFMeta);
                        database.Put(META_KEY_MAX_BLOCK, maxBlockNumber.GetBytesBE(), rocksCFMeta);
                        database.Put(META_KEY_COMPACTION_TYPE, compactionType, rocksCFMeta);
                    }
                    else
                    {
                        try
                        {
                            dbVersion = BinaryPrimitives.ReadInt32BigEndian(versionBytes);

                            byte[] minBlockBytes = database.Get(META_KEY_MIN_BLOCK, rocksCFMeta);
                            minBlockNumber = BinaryPrimitives.ReadUInt64BigEndian(minBlockBytes);

                            byte[] maxBlockBytes = database.Get(META_KEY_MAX_BLOCK, rocksCFMeta);
                            maxBlockNumber = BinaryPrimitives.ReadUInt64BigEndian(maxBlockBytes);

                            byte[] compactionTypeBytes = database.Get(META_KEY_COMPACTION_TYPE, rocksCFMeta);
                            compactionType = compactionTypeBytes;
                        }
                        catch
                        {
                            throw new Exception(string.Format("Unable to read database metadata. Database {0} could be corrupt or invalid.", dbPath));
                        }
                    }

                    Logging.info("RocksDB: Opened Database {0}: Blocks {1} - {2}, version {3}, compaction type {4}", dbPath, minBlockNumber, maxBlockNumber, dbVersion, Crypto.hashToString(compactionType));
                    Logging.trace("RocksDB: Stats: {0}", database.GetProperty("rocksdb.stats"));
                    lastUsedTime = DateTime.Now;
                }
            }

            public void logStats()
            {
                if (database != null)
                {
                    if (blockCache != null)
                    {
                        Logging.info("RocksDB: Common Cache Bytes Used: {0}", blockCache.GetUsage());
                    }

                    Logging.info("RocksDB: Stats [rocksdb.block-cache-usage] '{0}': {1}", dbPath, database.GetProperty("rocksdb.block-cache-usage"));
                    Logging.info("RocksDB: Stats for '{0}': {1}", dbPath, database.GetProperty("rocksdb.dbstats"));
                }
            }

            public void closeDatabase()
            {
                lock (rockLock)
                {
                    if (database == null)
                    {
                        return;
                    }

                    // free all blocks column families
                    rocksCFBlocks = null;
                    rocksCFMeta = null;
                    rocksCFTransactions = null;

                    // free all indexes
                    idxBlocksChecksum = null;
                    idxTXAppliedType = null;
                    idxAddressTXs = null;

                    database.Dispose();
                    database = null;
                }
            }

            private byte[] getBlockMetaBytes(int sigCount, IxiNumber totalSignerDifficulty, byte[] powField)
            {
                byte[] sigCountBytes = sigCount.GetIxiVarIntBytes();
                byte[] tsdBytes = totalSignerDifficulty.getBytes().GetIxiBytes();
                byte[] powFieldBytes = powField.GetIxiBytes();
                byte[] blockMetaBytes = new byte[sigCountBytes.Length + tsdBytes.Length + powFieldBytes.Length];
                Buffer.BlockCopy(sigCountBytes, 0, blockMetaBytes, 0, sigCountBytes.Length);
                Buffer.BlockCopy(tsdBytes, 0, blockMetaBytes, sigCountBytes.Length, tsdBytes.Length);
                Buffer.BlockCopy(powFieldBytes, 0, blockMetaBytes, sigCountBytes.Length + tsdBytes.Length, powFieldBytes.Length);

                return blockMetaBytes;
            }

            private (int sigCount, IxiNumber totalSignerDifficulty, byte[] powField) parseBlockMetaBytes(byte[] bytes)
            {
                int offset = 0;
                var iwo = bytes.GetIxiVarUInt(offset);
                int sigCount = (int)iwo.num;
                offset += iwo.bytesRead;

                var bwo = bytes.ReadIxiBytes(offset);
                IxiNumber totalSignerDifficulty = new IxiNumber(bwo.bytes);
                offset += bwo.bytesRead;

                bwo = bytes.ReadIxiBytes(offset);
                byte[] powField = bwo.bytes;
                offset += bwo.bytesRead;

                return (sigCount, totalSignerDifficulty, powField);
            }

            private void updateBlockIndexes(WriteBatch writeBatch, Block sb)
            {
                writeBatch.Put(StorageIndex.combineKeys(sb.blockChecksum, BLOCKS_KEY_TXS), sb.getTransactionIDsBytes(), rocksCFBlocks);
                if (sb.version >= BlockVer.v10)
                {
                    writeBatch.Put(StorageIndex.combineKeys(sb.blockChecksum, BLOCKS_KEY_SIGNERS), sb.getSignaturesBytes(true, false), rocksCFBlocks);
                    writeBatch.Put(StorageIndex.combineKeys(sb.blockChecksum, BLOCKS_KEY_SIGNERS_COMPACT), sb.getSignaturesBytes(true, true), rocksCFBlocks);
                }
                else
                {
                    writeBatch.Put(StorageIndex.combineKeys(sb.blockChecksum, BLOCKS_KEY_SIGNERS_COMPACT), sb.getSignaturesBytes(true, false), rocksCFBlocks);
                }

                var blockNumBytes = sb.blockNum.GetBytesBE();

                byte[] blockMetaBytes = getBlockMetaBytes(sb.getFrozenSignatureCount(), sb.getTotalSignerDifficulty(), sb.powField);
                idxBlocksChecksum!.addIndexEntry(blockNumBytes, sb.blockChecksum, blockMetaBytes, writeBatch);

                idxBlocksChecksum.addIndexEntry(blockNumBytes, BLOCKS_KEY_PRIMARY_INDEX, sb.blockChecksum, writeBatch);
            }

            private static byte[] typeAndTxIDToBytes(byte type, ReadOnlySpan<byte> txid)
            {
                byte[] buffer = GC.AllocateUninitializedArray<byte>(1 + txid.Length);
                buffer[0] = type;
                txid.CopyTo(buffer.AsSpan(1));

                return buffer;
            }

            private static byte[] blockHeightAndTxIDToBytes(ulong blockHeight, ReadOnlySpan<byte> txid)
            {
                byte[] buffer = GC.AllocateUninitializedArray<byte>(8 + txid.Length);
                BinaryPrimitives.WriteUInt64BigEndian(buffer.AsSpan(0, 8), blockHeight);
                txid.CopyTo(buffer.AsSpan(8));

                return buffer;
            }

            private void updateTXIndexes(WriteBatch writeBatch, Transaction st)
            {
                var txIdBytesShort = st.id.AsSpan(0, 16);

                foreach (var from in st.fromList)
                {
                    idxAddressTXs!.addIndexEntry(new Address(st.pubKey.addressNoChecksum, from.Key).addressNoChecksum.AsSpan(0, 16), blockHeightAndTxIDToBytes(st.applied, txIdBytesShort), Array.Empty<byte>(), writeBatch);
                }

                foreach (var to in st.toList)
                {
                    idxAddressTXs!.addIndexEntry(to.Key.addressNoChecksum.AsSpan(0, 16), blockHeightAndTxIDToBytes(st.applied, txIdBytesShort), Array.Empty<byte>(), writeBatch);
                }

                idxTXAppliedType!.addIndexEntry(st.applied.GetBytesBE(), typeAndTxIDToBytes((byte)st.type, txIdBytesShort), Array.Empty<byte>(), writeBatch);
            }

            private void updateMinMax(WriteBatch writeBatch, ulong blockNum)
            {
                if (minBlockNumber == 0 || blockNum < minBlockNumber)
                {
                    minBlockNumber = blockNum;
                    writeBatch.Put(META_KEY_MIN_BLOCK, minBlockNumber.GetBytesBE(), rocksCFMeta);
                }
                if (maxBlockNumber == 0 || blockNum > maxBlockNumber)
                {
                    maxBlockNumber = blockNum;
                    writeBatch.Put(META_KEY_MAX_BLOCK, maxBlockNumber.GetBytesBE(), rocksCFMeta);
                }
            }

            public bool insertBlock(Block block)
            {
                lock (rockLock)
                {
                    if (database == null)
                    {
                        throw new Exception($"Database {dbPath} is not open.");
                    }
                    lastUsedTime = DateTime.Now;
                    using (WriteBatch writeBatch = new WriteBatch())
                    {
                        writeBatch.Put(StorageIndex.combineKeys(block.blockChecksum, BLOCKS_KEY_HEADER), block.getBytes(true, true, true, true, true, false), rocksCFBlocks);
                        updateBlockIndexes(writeBatch, block);
                        updateMinMax(writeBatch, block.blockNum);
                        database.Write(writeBatch);
                    }
                }
                return true;
            }

            public bool insertTransaction(Transaction transaction)
            {
                lock (rockLock)
                {
                    if (database == null)
                    {
                        throw new Exception($"Database {dbPath} is not open.");
                    }
                    lastUsedTime = DateTime.Now;
                    using (WriteBatch writeBatch = new WriteBatch())
                    {
                        writeBatch.Put(transaction.id, transaction.getBytes(true, true), rocksCFTransactions);
                        updateTXIndexes(writeBatch, transaction);
                        database.Write(writeBatch);
                    }
                }
                return true;
            }

            public Block? getBlock(ulong blockNum)
            {
                lock (rockLock)
                {
                    if (database == null)
                    {
                        throw new Exception($"Database {dbPath} is not open.");
                    }
                    if (blockNum < minBlockNumber || blockNum > maxBlockNumber)
                    {
                        return null;
                    }

                    lastUsedTime = DateTime.Now;

                    var blockNumBytes = blockNum.GetBytesBE();

                    var blockChecksum = idxBlocksChecksum!.getEntry(blockNumBytes, BLOCKS_KEY_PRIMARY_INDEX);
                    if (blockChecksum == null)
                    {
                        return null;
                    }

                    return getBlockByHash(blockChecksum, null);
                }
            }

            public byte[]? getBlockBytes(ulong blockNum, bool compactedSignatures, bool includeTransactions)
            {
                lock (rockLock)
                {
                    if (database == null)
                    {
                        throw new Exception($"Database {dbPath} is not open.");
                    }
                    if (blockNum < minBlockNumber || blockNum > maxBlockNumber)
                    {
                        return null;
                    }

                    lastUsedTime = DateTime.Now;

                    var blockHash = idxBlocksChecksum!.getEntry(blockNum.GetBytesBE(), BLOCKS_KEY_PRIMARY_INDEX);
                    if (blockHash == null)
                    {
                        return null;
                    }

                    byte[] blockBytes = database.Get(StorageIndex.combineKeys(blockHash, BLOCKS_KEY_HEADER), rocksCFBlocks);
                    if (blockBytes != null)
                    {
                        byte[]? sigBytes = null;
                        if (!compactedSignatures)
                        {
                            sigBytes = database.Get(StorageIndex.combineKeys(blockHash, BLOCKS_KEY_SIGNERS), rocksCFBlocks);
                        }
                        if (sigBytes == null)
                        {
                            sigBytes = database.Get(StorageIndex.combineKeys(blockHash, BLOCKS_KEY_SIGNERS_COMPACT), rocksCFBlocks);
                        }
                        if (sigBytes == null)
                        {
                            using(var ms = new MemoryStream())
                            using (var writer = new BinaryWriter(ms))
                            {
                                var blockMeta = parseBlockMetaBytes(idxBlocksChecksum!.getEntry(blockNum.GetBytesBE(), blockHash));
                                writer.WriteIxiVarInt(0);
                                writer.WriteIxiVarInt(blockMeta.sigCount);
                                writer.WriteIxiBytes(blockMeta.totalSignerDifficulty.getBytes());
                                sigBytes = ms.ToArray();
                            }
                        }
                        byte[] mergedBytes = new byte[blockBytes.Length + sigBytes.Length];
                        Buffer.BlockCopy(blockBytes, 0, mergedBytes, 0, blockBytes.Length);
                        Buffer.BlockCopy(sigBytes, 0, mergedBytes, blockBytes.Length, sigBytes.Length);
                        blockBytes = mergedBytes;

                        if (includeTransactions)
                        {
                            byte[] txIDBytes = database.Get(StorageIndex.combineKeys(blockHash, BLOCKS_KEY_TXS), rocksCFBlocks);
                            if (txIDBytes == null)
                            {
                                txIDBytes = Array.Empty<byte>();
                            }
                            mergedBytes = new byte[blockBytes.Length + txIDBytes.Length];
                            Buffer.BlockCopy(blockBytes, 0, mergedBytes, 0, blockBytes.Length);
                            Buffer.BlockCopy(txIDBytes, 0, mergedBytes, blockBytes.Length, txIDBytes.Length);
                            blockBytes = mergedBytes;
                        }

                        return blockBytes;
                    }
                    return null;
                }
            }

            public Block? getBlockByHash(ReadOnlySpan<byte> blockHash)
            {
                if (database == null)
                {
                    throw new Exception($"Database {dbPath} is not open.");
                }

                lastUsedTime = DateTime.Now;
                return getBlockByHash(blockHash, null);
            }

            private Block? getBlockByHash(ReadOnlySpan<byte> blockHash, ReadOnlySpan<byte> blockMetaBytes)
            {
                lock (rockLock)
                {
                    byte[] blockBytes = database!.Get(StorageIndex.combineKeys(blockHash, BLOCKS_KEY_HEADER), rocksCFBlocks);
                    if (blockBytes != null)
                    {
                        byte[] txIDsBytes = database.Get(StorageIndex.combineKeys(blockHash, BLOCKS_KEY_TXS), rocksCFBlocks);
                        Block b = new Block(blockHash.ToArray(), blockBytes, txIDsBytes);
                        (int sigCount, IxiNumber totalSignerDifficulty, byte[] powField) blockMeta;
                        if (blockMetaBytes.Length > 0)
                        {
                            blockMeta = parseBlockMetaBytes(blockMetaBytes.ToArray());
                        }
                        else
                        {
                            blockMeta = parseBlockMetaBytes(idxBlocksChecksum!.getEntry(b.blockNum.GetBytesBE(), b.blockChecksum));
                        }

                        b.totalSignerDifficulty = blockMeta.totalSignerDifficulty;
                        b.powField = blockMeta.powField;
                        b.signatureCount = blockMeta.sigCount;

                        byte[] sigBytes = database.Get(StorageIndex.combineKeys(b.blockChecksum, BLOCKS_KEY_SIGNERS), rocksCFBlocks);
                        if (sigBytes == null)
                        {
                            sigBytes = database.Get(StorageIndex.combineKeys(b.blockChecksum, BLOCKS_KEY_SIGNERS_COMPACT), rocksCFBlocks);
                        }
                        b.setSignaturesFromBytes(sigBytes, false);
                        b.fromLocalStorage = true;
                        return b;
                    }
                    return null;
                }
            }


            private Transaction? getTransactionInternal(ReadOnlySpan<byte> txid)
            {
                var txBytes = getTransactionBytesInternal(txid);
                if (txBytes != null)
                {
                    Transaction t = new Transaction(txid.ToArray(), txBytes);
                    t.fromLocalStorage = true;
                    return t;
                }
                return null;
            }

            private IEnumerable<(ReadOnlyMemory<byte> index, Transaction value)> getTransactionsByPrefixInternal(ReadOnlyMemory<byte> txid)
            {
                var txs = getTransactionsBytesByPrefixInternal(txid);

                foreach (var tx in txs)
                {
                    Transaction t = new Transaction(tx.index.ToArray(), tx.value.ToArray());
                    t.fromLocalStorage = true;
                    yield return (tx.index, t);
                }
            }

            private byte[] getTransactionBytesInternal(ReadOnlySpan<byte> txid)
            {
                lastUsedTime = DateTime.Now;
                return database!.Get(txid, rocksCFTransactions);
            }


            private IEnumerable<(ReadOnlyMemory<byte> index, ReadOnlyMemory<byte> value)> getTransactionsBytesByPrefixInternal(ReadOnlyMemory<byte> txid)
            {
                lastUsedTime = DateTime.Now;

                var ro = new ReadOptions().SetPrefixSameAsStart(true);
                var iter = database!.NewIterator(rocksCFTransactions, ro);

                try
                {
                    for (iter.Seek(txid.Span); iter.Valid(); iter.Next())
                    {
                        var k = iter.Key();
                        if (!k.AsSpan(0, txid.Length).SequenceEqual(txid.Span))
                            yield break;

                        var v = iter.Value();
                        var indexSpan = k.AsMemory();
                        var valueMem = v.AsMemory();

                        yield return (indexSpan, valueMem);
                    }
                }
                finally
                {
                    iter.Dispose();
                }
            }

            public Transaction? getTransaction(byte[] txid)
            {
                lock (rockLock)
                {
                    if (database == null)
                    {
                        throw new Exception($"Database {dbPath} is not open.");
                    }
                    return getTransactionInternal(txid);
                }
            }

            public byte[]? getTransactionBytes(byte[] txid)
            {
                lock (rockLock)
                {
                    if (database == null)
                    {
                        throw new Exception($"Database {dbPath} is not open.");
                    }
                    return getTransactionBytesInternal(txid);
                }
            }

            public IEnumerable<Transaction> getTransactionsByAddress(byte[] addr, ulong blockNum = 0)
            {
                lock (rockLock)
                {
                    List<Transaction> txs = new List<Transaction>();
                    if (database == null)
                    {
                        throw new Exception($"Database {dbPath} is not open.");
                    }
                    lastUsedTime = DateTime.Now;
                    IEnumerable<(ReadOnlyMemory<byte> index, ReadOnlyMemory<byte> value)> entries;
                    if (blockNum == 0)
                    {
                        entries = idxAddressTXs!.getEntriesForKey(addr.AsMemory(0, 16));
                    }
                    else
                    {
                        entries = idxAddressTXs!.getEntriesForKey(addr.AsMemory(0, 16), blockNum.GetBytesBE());
                    }
                    foreach (var i in entries)
                    {
                        var tmpTxs = getTransactionsByPrefixInternal(i.index.Slice(8));
                        foreach (var tx in tmpTxs)
                        {
                            txs.Add(tx.value);
                        }
                    }
                    return txs;
                }
            }

            public IEnumerable<Transaction> getTransactionsInBlock(ulong blockNum, short txType = -1)
            {
                lock (rockLock)
                {
                    List<Transaction> txs = new List<Transaction>();
                    if (database == null)
                    {
                        throw new Exception($"Database {dbPath} is not open.");
                    }
                    lastUsedTime = DateTime.Now;
                    IEnumerable<(ReadOnlyMemory<byte> index, ReadOnlyMemory<byte> value)> entries;
                    if (txType == -1)
                    {
                        entries = idxTXAppliedType!.getEntriesForKey(blockNum.GetBytesBE());
                    }
                    else
                    {
                        entries = idxTXAppliedType!.getEntriesForKey(blockNum.GetBytesBE(), new byte[] { (byte)txType });
                    }

                    foreach (var txid in entries)
                    {
                        var tmpTxs = getTransactionsByPrefixInternal(txid.index.Slice(1));
                        foreach (var tx in tmpTxs)
                        {
                            txs.Add(tx.value);
                        }
                    }
                    return txs;
                }
            }

            public IEnumerable<byte[]> getTransactionsBytesInBlock(ulong blockNum, short txType = -1)
            {
                lock (rockLock)
                {
                    List<byte[]> txs = new List<byte[]>();
                    if (database == null)
                    {
                        throw new Exception($"Database {dbPath} is not open.");
                    }
                    lastUsedTime = DateTime.Now;
                    IEnumerable<(ReadOnlyMemory<byte> index, ReadOnlyMemory<byte> value)> entries;
                    if (txType == -1)
                    {
                        entries = idxTXAppliedType!.getEntriesForKey(blockNum.GetBytesBE());
                    }
                    else
                    {
                        entries = idxTXAppliedType!.getEntriesForKey(blockNum.GetBytesBE(), new byte[] { (byte)txType });
                    }

                    foreach (var txid in entries)
                    {
                        var tmpTxs = getTransactionsBytesByPrefixInternal(txid.index.Slice(1));
                        foreach (var tx in tmpTxs)
                        {
                            txs.Add(tx.value.ToArray());
                        }
                    }
                    return txs;
                }
            }

            public bool removeBlock(ulong blockNum)
            {
                lock (rockLock)
                {
                    Block? block = getBlock(blockNum);
                    if (block != null)
                    {
                        lastUsedTime = DateTime.Now;
                        var blockChecksum = block.blockChecksum;
                        var blockNumBytes = blockNum.GetBytesBE();

                        // Delete all transactions applied on this block height
                        foreach (var txIdBytes in block.transactions)
                        {
                            removeTransactionInternal(txIdBytes);
                        }

                        using (WriteBatch writeBatch = new WriteBatch())
                        {
                            writeBatch.Delete(StorageIndex.combineKeys(blockChecksum, BLOCKS_KEY_HEADER), rocksCFBlocks);
                            writeBatch.Delete(StorageIndex.combineKeys(blockChecksum, BLOCKS_KEY_SIGNERS), rocksCFBlocks);
                            writeBatch.Delete(StorageIndex.combineKeys(blockChecksum, BLOCKS_KEY_SIGNERS_COMPACT), rocksCFBlocks);
                            writeBatch.Delete(StorageIndex.combineKeys(blockChecksum, BLOCKS_KEY_TXS), rocksCFBlocks);

                            idxBlocksChecksum!.delIndexEntry(blockNumBytes, blockChecksum, writeBatch);

                            idxBlocksChecksum.delIndexEntry(blockNumBytes, BLOCKS_KEY_PRIMARY_INDEX, writeBatch);

                            database!.Write(writeBatch);

                            if (blockNum == maxBlockNumber)
                            {
                                if (blockNum == minBlockNumber)
                                {
                                    minBlockNumber = 0;
                                    writeBatch.Put(META_KEY_MIN_BLOCK, minBlockNumber.GetBytesBE(), rocksCFMeta);

                                    maxBlockNumber = 0;
                                    writeBatch.Put(META_KEY_MAX_BLOCK, maxBlockNumber.GetBytesBE(), rocksCFMeta);
                                }
                                else
                                {
                                    maxBlockNumber = blockNum - 1;
                                    writeBatch.Put(META_KEY_MAX_BLOCK, maxBlockNumber.GetBytesBE(), rocksCFMeta);
                                }
                            }
                            else if (blockNum == minBlockNumber)
                            {
                                minBlockNumber = blockNum + 1;
                                writeBatch.Put(META_KEY_MIN_BLOCK, minBlockNumber.GetBytesBE(), rocksCFMeta);
                            }
                        }

                        return true;
                    }
                    return false;
                }
            }

            private bool removeTransactionInternal(ReadOnlySpan<byte> txid)
            {
                Transaction? tx = getTransactionInternal(txid);
                if (tx != null)
                {
                    using (WriteBatch writeBatch = new WriteBatch())
                    {
                        writeBatch.Delete(txid, rocksCFTransactions);
                        var txIdBytesShort = txid.Slice(0, 16);
                        removeTransactionIndexes(tx, txIdBytesShort, writeBatch);
                        database!.Write(writeBatch);
                    }
                    return true;
                }
                return false;
            }

            private void removeTransactionIndexes(Transaction tx, ReadOnlySpan<byte> txIdBytesShort, WriteBatch writeBatch)
            {
                // remove it from indexes
                foreach (var f in tx.fromList.Keys)
                {
                    idxAddressTXs!.delIndexEntry(new Address(tx.pubKey.addressNoChecksum, f).addressNoChecksum.AsSpan(0, 16), blockHeightAndTxIDToBytes(tx.applied, txIdBytesShort), writeBatch);
                }
                foreach (var t in tx.toList.Keys)
                {
                    idxAddressTXs!.delIndexEntry(t.addressNoChecksum.AsSpan(0, 16), blockHeightAndTxIDToBytes(tx.applied, txIdBytesShort), writeBatch);
                }
                idxTXAppliedType!.delIndexEntry(tx.applied.GetBytesBE(), typeAndTxIDToBytes((byte)tx.type, txIdBytesShort), writeBatch);
            }

            public bool removeTransaction(byte[] txid)
            {
                lock (rockLock)
                {
                    lastUsedTime = DateTime.Now;
                    return removeTransactionInternal(txid);
                }
            }

            public (byte[]? blockHash, IxiNumber? totalSignerDifficulty) getBlockTotalSignerDifficulty(ulong blockNum)
            {
                lock (rockLock)
                {
                    if (database == null)
                    {
                        throw new Exception($"Database {dbPath} is not open.");
                    }
                    lastUsedTime = DateTime.Now;

                    var blockNumBytes = blockNum.GetBytesBE();

                    var blockHash = idxBlocksChecksum!.getEntry(blockNumBytes, BLOCKS_KEY_PRIMARY_INDEX);
                    if (blockHash == null)
                    {
                        return (null, null);
                    }
                    var blockMeta = idxBlocksChecksum!.getEntry(blockNumBytes, blockHash);
                    if (blockMeta == null)
                    {
                        return (null, null);
                    }
                    return (blockHash, parseBlockMetaBytes(blockMeta).totalSignerDifficulty);
                }
            }

            public void compact()
            {
                if (database != null)
                {
                    try
                    {
                        Logging.info("RocksDB: Performing compaction on database '{0}'.", dbPath);
                        lock (rockLock)
                        {
                            database.CompactRange(null, null, rocksCFBlocks);
                            database.CompactRange(null, null, rocksCFTransactions);
                            database.CompactRange(null, null, rocksCFMeta);
                            database.CompactRange(null, null, idxBlocksChecksum!.rocksIndexHandle);
                            database.CompactRange(null, null, idxAddressTXs!.rocksIndexHandle);
                            database.CompactRange(null, null, idxTXAppliedType!.rocksIndexHandle);
                        }
                    }
                    catch (Exception e)
                    {
                        Logging.error("RocksDB: Error while performing regular maintenance on '{0}': {1}", dbPath, e.Message);
                    }
                }
            }

            public void deleteDatabase()
            {
                closeDatabase();
                Directory.Delete(dbPath, true);
            }
        }

        public class RocksDBStorage : IStorage
        {
            private readonly Dictionary<ulong, RocksDBInternal> openDatabases = new Dictionary<ulong, RocksDBInternal>();
            public uint closeAfterSeconds = 60;

            private int maxOpenDatabases = 50;
            private long minDiskSpace = 1L * 1024L * 1024L * 1024L;

            // Runtime stuff
            private Cache? commonBlockCache = null;
            private Queue<RocksDBInternal> reopenCleanupList = new Queue<RocksDBInternal>();
            private DateTime lastReopenOptimize = DateTime.Now;


            private ulong highestBlockNum = 0;
            private ulong lowestBlockNum = 0;
            private ulong maxDatabaseCache;
            private int lastBlockVersion = BlockVer.v0;

            private ulong maxBlocksPerDatabase;

            private bool closeRedactedWindow;

            public RocksDBStorage(string dataFolderBlocks, ulong maxDatabaseCache, ulong maxBlocksPerDatabase, int maxOpenDatabases) : base(dataFolderBlocks)
            {
                this.maxOpenDatabases = maxOpenDatabases;
                this.maxDatabaseCache = maxDatabaseCache;
                this.maxBlocksPerDatabase = maxBlocksPerDatabase;
                closeRedactedWindow = false;
                if (ConsensusConfig.getRedactedWindowSize(lastBlockVersion) >= maxBlocksPerDatabase * (ulong)maxOpenDatabases)
                {
                    closeRedactedWindow = true;
                }
            }

            private RocksDBInternal? getDatabase(ulong blockNum, bool onlyExisting = false)
            {
                if (ctsLoop == null)
                {
                    throw new Exception("Error while getting database, RocksDB is shutting down.");
                }
                // Open or create the db which should contain blockNum
                ulong baseBlockNum = blockNum / maxBlocksPerDatabase;
                RocksDBInternal? db = null;
                lock (openDatabases)
                {
                    if (openDatabases.ContainsKey(baseBlockNum))
                    {
                        db = openDatabases[baseBlockNum];
                        if (!db.isOpen)
                        {
                            Logging.info("RocksDB: Database {0} is not opened - opening.", baseBlockNum);
                            db.openDatabase();
                        }
                    }
                    else
                    {
                        if (!hasSufficientDiskSpace())
                        {
                            throw new InvalidOperationException("RocksDB: Error opening database, free disk space is below 1GB.");
                        }

                        string db_path = Path.Combine(pathBase, "0000", baseBlockNum.ToString());
                        if (onlyExisting)
                        {
                            if (!Directory.Exists(db_path))
                            {
                                return null;
                            }
                        }

                        Logging.info("RocksDB: Opening a database for blocks {0} - {1}.", baseBlockNum * maxBlocksPerDatabase, (baseBlockNum * maxBlocksPerDatabase) + maxBlocksPerDatabase - 1);
                        db = new RocksDBInternal(db_path, commonBlockCache!);
                        db.openDatabase();
                        openDatabases.Add(baseBlockNum, db);

                        if (openDatabases.Count > maxOpenDatabases)
                        {
                            closeOldestDatabase(db);
                        }
                    }
                }
                return db;
            }

            public static bool hasRocksDBData(string pathBase)
            {
                if (Directory.Exists(Path.Combine(pathBase, "0000", "0")))
                {
                    return true;
                }
                return false;
            }

            protected override bool prepareStorageInternal(bool optimize)
            {
                // Files structured like:
                //  'pathBase\<startOffset>', where <startOffset> is the nominal lowest block number in that database
                //  the actual lowest block in that database may be higher than <startOffset>
                // <startOffset> is aligned to `maxBlocksPerDB` blocks

                // check that the base path exists, or create it
                try
                {
                    if (!Directory.Exists(pathBase))
                    {
                        Directory.CreateDirectory(pathBase);
                    }

                    if (!Directory.Exists(Path.Combine(pathBase, "0000")))
                    {
                        Directory.CreateDirectory(Path.Combine(pathBase, "0000"));
                    }
                }
                catch (Exception e)
                {
                    Logging.error("Unable to prepare block database path '{0}': {1}", pathBase, e.Message);
                    return false;
                }

                // Prepare cache
                commonBlockCache = Cache.CreateLru(maxDatabaseCache);
                // DB optimization
                if (optimize)
                {
                    Logging.info("RocksDB: Performing pre-start DB compaction and optimization.");
                    foreach (string db in Directory.GetDirectories(Path.Combine(pathBase, "0000")))
                    {
                        Logging.info("RocksDB: Optimizing [{0}].", db);
                        RocksDBInternal temp_db = new RocksDBInternal(db, commonBlockCache);
                        try
                        {
                            temp_db.openDatabase();
                            temp_db.compact();
                            temp_db.closeDatabase();
                        }
                        catch (Exception e)
                        {
                            Logging.warn("RocksDB: Error while opening database {0}: {1}", db, e.Message);
                        }
                    }
                    Logging.info("RocksDB: Pre-start optimization complete.");
                }

                Logging.info("Last storage block number is: #{0}", getHighestBlockInStorage());

                return true;
            }

            private bool hasSufficientDiskSpace()
            {
                var availSpace = Platform.getAvailableDiskSpace(pathBase);
                if (availSpace == -1)
                {
                    Logging.warn("Could not read available disk space.");
                    return true;
                }
                return availSpace > minDiskSpace;
            }

            protected override void cleanupCache()
            {
                lock (openDatabases)
                {
                    Logging.info("RocksDB Registered database list:");
                    List<ulong> toDrop = new List<ulong>();
                    foreach (var db in openDatabases)
                    {
                        Logging.info("RocksDB: [{0}]: open: {1}, last used: {2}",
                            db.Value.dbPath,
                            db.Value.isOpen,
                            db.Value.lastUsedTime
                            );

                        if (db.Value.isOpen
                            && (DateTime.Now - db.Value.lastUsedTime).TotalSeconds >= closeAfterSeconds)
                        {
                            if (db.Value.maxBlockNumber == 0)
                            {
                                continue;
                            }
                            if (db.Value.maxBlockNumber + ConsensusConfig.getRedactedWindowSize(lastBlockVersion) >= highestBlockNum)
                            {
                                // never close the databases within redacted window
                                continue;
                            }
                            Logging.info("RocksDB: Closing '{0}' due to inactivity.", db.Value.dbPath);
                            db.Value.closeDatabase();
                            toDrop.Add(db.Key);
                            reopenCleanupList.Enqueue(db.Value);
                        }
                    }

                    foreach (ulong dbnum in toDrop)
                    {
                        openDatabases.Remove(dbnum);
                    }

                    if ((DateTime.Now - lastReopenOptimize).TotalSeconds > 60.0)
                    {
                        compact();
                    }

                    // check disk status and close databases if we're running low
                    bool sufficientDiskSpace = hasSufficientDiskSpace();
                    if (!sufficientDiskSpace && openDatabases.Where(x => x.Value.isOpen).Count() > 0)
                    {
                        Logging.error("RocksDB: Disk free space is low, closing all databases, to prevent data corruption.");
                        closeDatabases();
                    }
                }
            }

            private void compact()
            {
                int reopenListCount = reopenCleanupList.Count;
                for (int i = 0; i < reopenListCount; i++)
                {
                    var db = reopenCleanupList.Dequeue();
                    if (openDatabases.Values.Any(x => x.dbPath == db.dbPath))
                    {
                        Logging.info("RocksDB: Database [{0}] was still in use, skipping until it is closed.", db.dbPath);
                        continue;
                    }

                    if (closeRedactedWindow
                        || db.maxBlockNumber + ConsensusConfig.getRedactedWindowSize(lastBlockVersion) < highestBlockNum)
                    {
                        Logging.info("RocksDB: Compacting closed database [{0}].", db.dbPath);
                        try
                        {
                            db.openDatabase();
                        }
                        catch (Exception)
                        {
                            // these were attempted too quickly and RocksDB internal still has some pointers open
                            reopenCleanupList.Enqueue(db);
                            Logging.info("RocksDB: Database [{0}] was locked by another process, will try again later.", db.dbPath);
                        }
                        if (db.isOpen)
                        {
                            db.compact();
                            db.closeDatabase();
                            Logging.info("RocksDB: Compacting succeeded");
                        }
                    }
                }
                lastReopenOptimize = DateTime.Now;
            }

            private void closeOldestDatabase(RocksDBInternal excludeDb)
            {
                var oldestDb = openDatabases.OrderBy(x => x.Value.lastUsedTime).Where(x => x.Value.isOpen && x.Value.maxBlockNumber > 0 && (closeRedactedWindow || x.Value.maxBlockNumber + ConsensusConfig.getRedactedWindowSize(lastBlockVersion) < highestBlockNum)).FirstOrDefault();
                if (oldestDb.Value != null
                    && oldestDb.Value != excludeDb)
                {
                    oldestDb.Value.closeDatabase();
                    openDatabases.Remove(oldestDb.Key);
                    reopenCleanupList.Enqueue(oldestDb.Value);
                }
            }

            public override void deleteData()
            {
                if (Directory.Exists(pathBase))
                {
                    Directory.Delete(pathBase, true);
                }
            }

            private void closeDatabases(bool addToCleanup = true)
            {
                var toClose = openDatabases.Keys.ToList();
                foreach (var key in toClose)
                {
                    var db = openDatabases[key];
                    Logging.info("RocksDB: Closing '{0}'", db.dbPath);
                    db.closeDatabase();
                    openDatabases.Remove(key);
                    if (addToCleanup)
                    {
                        reopenCleanupList.Enqueue(db);
                    }
                }
            }

            protected override void shutdown()
            {
                lock (openDatabases)
                {
                    closeDatabases();
                    compact();
                }
            }

            public override ulong getHighestBlockInStorage()
            {
                if (highestBlockNum > 0)
                {
                    return highestBlockNum;
                }

                // find our absolute highest block db
                long latest_db = -1;
                foreach (var d in Directory.EnumerateDirectories(Path.Combine(pathBase, "0000")))
                {
                    string[] dir_parts = d.Split(Path.DirectorySeparatorChar);
                    string final_dir = dir_parts[dir_parts.Length - 1];
                    if (long.TryParse(final_dir, out long db_base))
                    {
                        if (db_base > latest_db)
                        {
                            latest_db = db_base;
                        }
                    }
                }
                lock (openDatabases)
                {
                    for (long i = latest_db; i >= 0; i--)
                    {
                        var db = getDatabase((ulong)i * maxBlocksPerDatabase, true);
                        if (db != null && db.maxBlockNumber > 0)
                        {
                            highestBlockNum = db.maxBlockNumber;
                            return highestBlockNum;
                        }
                    }
                    return 0;
                }
            }

            public override ulong getLowestBlockInStorage()
            {
                if (lowestBlockNum > 0)
                {
                    return lowestBlockNum;
                }

                // find our absolute lowest block db
                ulong oldest_db = ulong.MaxValue;
                foreach (var d in Directory.EnumerateDirectories(Path.Combine(pathBase, "0000")))
                {
                    string[] dir_parts = d.Split(Path.DirectorySeparatorChar);
                    string final_dir = dir_parts[dir_parts.Length - 1];
                    if (ulong.TryParse(final_dir, out ulong db_base))
                    {
                        if (db_base < oldest_db)
                        {
                            oldest_db = db_base;
                        }
                    }
                }
                if (oldest_db == ulong.MaxValue)
                {
                    return 0; // empty db
                }
                lock (openDatabases)
                {
                    var db = getDatabase(oldest_db * maxBlocksPerDatabase, true);
                    lowestBlockNum = db!.minBlockNumber;
                    return lowestBlockNum;
                }
            }

            protected override bool insertBlockInternal(Block block)
            {
                lock (openDatabases)
                {
                    var db = getDatabase(block.blockNum);
                    if (db == null)
                    {
                        throw new Exception(string.Format("Cannot access database for block {0}", block.blockNum));
                    }
                    if (db.insertBlock(block))
                    {
                        if (block.blockNum > getHighestBlockInStorage())
                        {
                            highestBlockNum = block.blockNum;
                            lastBlockVersion = block.version;
                        }
                        return true;
                    }
                    return false;
                }
            }

            protected override bool insertTransactionInternal(Transaction transaction)
            {
                lock (openDatabases)
                {
                    if (transaction.applied == 0)
                    {
                        throw new Exception(string.Format("Cannot insert transaction {0}, applied is 0.", transaction.getTxIdString()));
                    }
                    var db = getDatabase(transaction.applied);
                    if (db == null)
                    {
                        throw new Exception(string.Format("Cannot access database for block {0}", transaction.applied));
                    }
                    return db.insertTransaction(transaction);
                }
            }

            public override Block? getBlock(ulong blockNum)
            {
                lock (openDatabases)
                {
                    ulong highestBlockNum = getHighestBlockInStorage();
                    if (blockNum > highestBlockNum)
                    {
                        Logging.warn("Tried to get block {0} but the highest block in storage is {1}", blockNum, highestBlockNum);
                        return null;
                    }
                    var db = getDatabase(blockNum, true);
                    return db?.getBlock(blockNum);
                }
            }

            public override byte[]? getBlockBytes(ulong blockNum, bool compactedSignatures, bool includeTransactions)
            {
                lock (openDatabases)
                {
                    ulong highestBlockNum = getHighestBlockInStorage();
                    if (blockNum > highestBlockNum)
                    {
                        Logging.warn("Tried to get block {0} but the highest block in storage is {1}", blockNum, highestBlockNum);
                        return null;
                    }
                    var db = getDatabase(blockNum, true);
                    return db?.getBlockBytes(blockNum, compactedSignatures, includeTransactions);
                }
            }

            public override Transaction? getTransaction(byte[] txid, ulong blockNum = 0)
            {
                lock (openDatabases)
                {
                    ulong highestBlockNum = getHighestBlockInStorage();

                    if (blockNum != 0)
                    {
                        if (blockNum > highestBlockNum)
                        {
                            Logging.warn("Tried to get transaction in block {0} but the highest block in storage is {1}", blockNum, highestBlockNum);
                            return null;
                        }

                        var db = getDatabase(blockNum, true);

                        if (db == null)
                        {
                            throw new Exception(string.Format("Cannot access database for block {0}", blockNum));
                        }

                        return db.getTransaction(txid);
                    }
                    else
                    {
                        bool found = false;
                        ulong tx_blocknum = IxiVarInt.GetIxiVarUInt(txid, 1).num;
                        ulong db_blocknum = tx_blocknum / maxBlocksPerDatabase;

                        if (tx_blocknum == 0)
                        {
                            Logging.error("Invalid txid {0} - generated at block height 0.", Transaction.getTxIdString(txid));
                            return null;
                        }

                        if (tx_blocknum > highestBlockNum)
                        {
                            Logging.warn("Tried to get transaction generated on block {0} but the highest block in storage is {1}", tx_blocknum, highestBlockNum);
                            return null;
                        }

                        // TODO Improve getRedactedWindowSize(0) with block height helpers to determine block version and correct window size
                        if (highestBlockNum > tx_blocknum + ConsensusConfig.getRedactedWindowSize(0))
                        {
                            highestBlockNum = tx_blocknum + ConsensusConfig.getRedactedWindowSize(0);
                        }

                        while (!found)
                        {
                            var db = getDatabase(db_blocknum, true);
                            if (db == null)
                            {
                                throw new Exception(string.Format("Cannot access database for block {0}", db_blocknum));
                            }

                            Transaction? tx = db.getTransaction(txid);
                            if (tx != null)
                            {
                                return tx;
                            }
                            else
                            {
                                if (db_blocknum + maxBlocksPerDatabase <= highestBlockNum)
                                {
                                    db_blocknum += maxBlocksPerDatabase;
                                }
                                else
                                {
                                    // Transaction not found in any database
                                    return null;
                                }
                            }
                        }
                    }
                    return null;
                }
            }

            public override byte[]? getTransactionBytes(byte[] txid, ulong blockNum = 0)
            {
                lock (openDatabases)
                {
                    ulong highestBlockNum = getHighestBlockInStorage();

                    if (blockNum != 0)
                    {
                        if (blockNum > highestBlockNum)
                        {
                            Logging.warn("Tried to get transaction in block {0} but the highest block in storage is {1}", blockNum, highestBlockNum);
                            return null;
                        }

                        var db = getDatabase(blockNum, true);
                        if (db == null)
                        {
                            throw new Exception(string.Format("Cannot access database for block {0}", blockNum));
                        }

                        return db.getTransactionBytes(txid);
                    }
                    else
                    {
                        bool found = false;
                        ulong tx_blocknum = IxiVarInt.GetIxiVarUInt(txid, 1).num;
                        ulong db_blocknum = tx_blocknum / maxBlocksPerDatabase;

                        if (tx_blocknum == 0)
                        {
                            Logging.error("Invalid txid {0} - generated at block height 0.", Transaction.getTxIdString(txid));
                            return null;
                        }

                        if (tx_blocknum > highestBlockNum)
                        {
                            Logging.warn("Tried to get transaction generated on block {0} but the highest block in storage is {1}", tx_blocknum, highestBlockNum);
                            return null;
                        }

                        // TODO Improve getRedactedWindowSize(0) with block height helpers to determine block version and correct window size
                        if (highestBlockNum > tx_blocknum + ConsensusConfig.getRedactedWindowSize(0))
                        {
                            highestBlockNum = tx_blocknum + ConsensusConfig.getRedactedWindowSize(0);
                        }

                        while (!found)
                        {
                            var db = getDatabase(tx_blocknum, true);
                            if (db == null)
                            {
                                throw new Exception(string.Format("Cannot access database for block {0}", db_blocknum));
                            }

                            byte[]? tx = db.getTransactionBytes(txid);
                            if (tx != null)
                            {
                                return tx;
                            }
                            else
                            {
                                if (db_blocknum + maxBlocksPerDatabase <= highestBlockNum)
                                {
                                    db_blocknum += maxBlocksPerDatabase;
                                }
                                else
                                {
                                    // Transaction not found in any database
                                    return null;
                                }
                            }
                        }
                    }
                    return null;
                }
            }

            public IEnumerable<Transaction>? getTransactionsByAddress(byte[] addr, ulong superBlockNum, ulong blockNum = 0)
            {
                lock (openDatabases)
                {
                    ulong highestBlockNum = getHighestBlockInStorage();
                    if (blockNum > highestBlockNum)
                    {
                        Logging.warn("Tried to get block {0} but the highest block in storage is {1}", blockNum, highestBlockNum);
                        return null;
                    }
                    var db = getDatabase(superBlockNum, true);
                    if (db == null)
                    {
                        throw new Exception(string.Format("Cannot access database for block {0}", superBlockNum));
                    }
                    return db.getTransactionsByAddress(addr, blockNum);
                }
            }

            public override IEnumerable<Transaction>? getTransactionsInBlock(ulong blockNum, short tx_type = -1)
            {
                lock (openDatabases)
                {
                    ulong highestBlockNum = getHighestBlockInStorage();
                    if (blockNum > highestBlockNum)
                    {
                        Logging.warn("Tried to get block {0} but the highest block in storage is {1}", blockNum, highestBlockNum);
                        return null;
                    }
                    var db = getDatabase(blockNum, true);
                    if (db == null)
                    {
                        throw new Exception(string.Format("Cannot access database for block {0}", blockNum));
                    }
                    return db.getTransactionsInBlock(blockNum, tx_type);
                }
            }

            public override IEnumerable<byte[]>? getTransactionsBytesInBlock(ulong blockNum, short tx_type = -1)
            {
                lock (openDatabases)
                {
                    ulong highestBlockNum = getHighestBlockInStorage();
                    if (blockNum > highestBlockNum)
                    {
                        Logging.warn("Tried to get block {0} but the highest block in storage is {1}", blockNum, highestBlockNum);
                        return null;
                    }
                    var db = getDatabase(blockNum, true);
                    if (db == null)
                    {
                        throw new Exception(string.Format("Cannot access database for block {0}", blockNum));
                    }
                    return db.getTransactionsBytesInBlock(blockNum, tx_type);
                }
            }

            public override bool removeBlock(ulong blockNum)
            {
                lock (openDatabases)
                {
                    ulong highestBlockNum = getHighestBlockInStorage();
                    if (blockNum > highestBlockNum)
                    {
                        Logging.warn("Tried to get block {0} but the highest block in storage is {1}", blockNum, highestBlockNum);
                        return false;
                    }
                    var db = getDatabase(blockNum, true);
                    if (db == null)
                    {
                        throw new Exception(string.Format("Cannot access database for block {0}", blockNum));
                    }
                    if (db.removeBlock(blockNum))
                    {
                        if (blockNum == highestBlockNum)
                        {
                            highestBlockNum = blockNum - 1;
                        }
                        if (blockNum == lowestBlockNum)
                        {
                            lowestBlockNum = blockNum + 1;
                        }
                        return true;
                    }
                    return false;
                }
            }

            public override bool removeTransaction(byte[] txid, ulong blockNum)
            {
                lock (openDatabases)
                {
                    ulong highestBlockNum = getHighestBlockInStorage();
                    if (blockNum > highestBlockNum)
                    {
                        Logging.warn("Tried to get block {0} but the highest block in storage is {1}", blockNum, highestBlockNum);
                        return false;
                    }
                    var db = getDatabase(blockNum, true);
                    if (db == null)
                    {
                        throw new Exception(string.Format("Cannot access database for block {0}", blockNum));
                    }
                    return db.removeTransaction(txid);
                }
            }

            public override (byte[]? blockHash, IxiNumber? totalSignerDifficulty) getBlockTotalSignerDifficulty(ulong blockNum)
            {
                lock (openDatabases)
                {
                    ulong highestBlockNum = getHighestBlockInStorage();
                    if (blockNum > highestBlockNum)
                    {
                        Logging.warn("Tried to get block {0} but the highest block in storage is {1}", blockNum, highestBlockNum);
                        return (null, null);
                    }
                    var db = getDatabase(blockNum, true);
                    if (db == null)
                    {
                        return (null, null);
                    }
                    return db.getBlockTotalSignerDifficulty(blockNum);
                }
            }

            public override void redactBlockStorage(ulong removeBlocksBelow)
            {
                ulong lowestBlock = getLowestBlockInStorage();
                lock (openDatabases)
                {
                    closeDatabases(false);
                    ulong dbBlockNum = (ulong)(removeBlocksBelow / CoreConfig.maxBlockHeadersPerDatabase);

                    bool first = false;

                    while (!first)
                    {
                        string dbPath = Path.Combine(pathBase, "0000", dbBlockNum.ToString());

                        if (!Directory.Exists(dbPath))
                        {
                            break;
                        }

                        Directory.Delete(dbPath, true);

                        if (dbBlockNum > 0)
                        {
                            dbBlockNum--;
                        }
                        else if (dbBlockNum == 0)
                        {
                            first = true;
                        }
                    }
                }
            }
        }
    }
}

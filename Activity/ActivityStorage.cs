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
using IXICore.Storage;
using IXICore.Utils;
using RocksDbSharp;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace IXICore.Activity
{
    class RocksDBInternal
    {
        public string dbPath { get; private set; }
        private RocksDb? database = null;
        // global column families
        private ColumnFamilyHandle? metaCF;
        private ColumnFamilyHandle? activityCF;
        private ColumnFamilyHandle? rawTxCF;

        private StorageIndex? idxActivityId;
        private StorageIndex? idxBlockHeightActivityId;
        private StorageIndex? idxStatusActivityId;
        private StorageIndex? idxAddressActivityId;

        private readonly object rockLock = new object();

        private readonly byte[] META_KEY_DB_VERSION = Encoding.UTF8.GetBytes("db_version");
        private readonly byte[] META_KEY_MIN_BLOCK = Encoding.UTF8.GetBytes("min_block");
        private readonly byte[] META_KEY_MAX_BLOCK = Encoding.UTF8.GetBytes("max_block");

        // Reuse a single 0xFF byte to avoid tiny allocations in the hot path
        private static readonly byte[] oneByteFF = new byte[] { 0xFF };

        private readonly byte[] ACTIVITY_KEY_PAYLOAD = new byte[] { 0 };
        private readonly byte[] ACTIVITY_KEY_META = new byte[] { 1 };

        public ulong minBlockNumber { get; private set; }
        public ulong maxBlockNumber { get; private set; }
        public int dbVersion { get; private set; } = 1;
        public bool isOpen
        {
            get
            {
                lock (rockLock)
                {
                    return database != null;
                }
            }
        }
        public DateTime lastUsedTime { get; private set; }
        // Caches (shared with other rocksDb
        private Cache blockCache;

        private RocksDBOptimizations optimizationType;

        public RocksDBInternal(string dbPath, Cache blockCache, RocksDBOptimizations optimizationType)
        {
            minBlockNumber = 0;
            maxBlockNumber = 0;

            this.dbPath = dbPath;
            this.blockCache = blockCache;
            this.optimizationType = optimizationType;
        }


        public (DbOptions dbOptions, ColumnFamilies columnFamilies) getDefaultOptions()
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
                .SetCompression(RocksDbSharp.Compression.Zstd)
                .SetLevelCompactionDynamicLevelBytes(true)
                .SetCompactionReadaheadSize(4 * 1024 * 1024);

            // activity
            var activityBbto = new BlockBasedTableOptions();
            activityBbto.SetBlockCache(blockCache.Handle);
            activityBbto.SetBlockSize(32 * 1024);
            activityBbto.SetCacheIndexAndFilterBlocks(true);
            activityBbto.SetPinL0FilterAndIndexBlocksInCache(true);
            activityBbto.SetFilterPolicy(BloomFilterPolicy.Create(16, true));
            activityBbto.SetWholeKeyFiltering(true);
            activityBbto.SetFormatVersion(6);

            // meta
            var metaBbto = new BlockBasedTableOptions();
            metaBbto.SetBlockCache(blockCache.Handle);
            metaBbto.SetBlockSize(4 * 1024);
            metaBbto.SetCacheIndexAndFilterBlocks(true);
            metaBbto.SetPinL0FilterAndIndexBlocksInCache(true);
            metaBbto.SetFilterPolicy(BloomFilterPolicy.Create(10, false));
            metaBbto.SetWholeKeyFiltering(true);
            metaBbto.SetFormatVersion(6);

            var columnFamilies = new ColumnFamilies
                {
                    { "activity", new ColumnFamilyOptions()
                        .SetBlockBasedTableFactory(activityBbto)
                        .SetWriteBufferSize(8UL << 20)
                        .SetMaxWriteBufferNumber(2)
                        .SetMinWriteBufferNumberToMerge(1)
                        .SetPrefixExtractor(SliceTransform.CreateFixedPrefix(16))
                    },
                    { "meta", new ColumnFamilyOptions()
                        .SetBlockBasedTableFactory(metaBbto)
                        .OptimizeForPointLookup(64)
                        .SetWriteBufferSize(128UL << 10)
                        .SetMaxWriteBufferNumber(1)
                    },
                    { "raw_tx", new ColumnFamilyOptions()
                        .SetBlockBasedTableFactory(activityBbto)
                        .SetWriteBufferSize(16UL << 20)
                        .SetMaxWriteBufferNumber(2)
                        .SetMinWriteBufferNumberToMerge(1)
                    },
                    { "index_block_height_activity_id", new ColumnFamilyOptions()
                        .SetBlockBasedTableFactory(activityBbto)
                        .SetWriteBufferSize(1UL << 20)
                        .SetMaxWriteBufferNumber(2)
                        .SetMinWriteBufferNumberToMerge(1)
                        .SetPrefixExtractor(SliceTransform.CreateFixedPrefix(8))
                    },
                    { "index_activity_id", new ColumnFamilyOptions()
                        .SetBlockBasedTableFactory(activityBbto)
                        .SetWriteBufferSize(1UL << 20)
                        .SetMaxWriteBufferNumber(2)
                        .SetMinWriteBufferNumberToMerge(1)
                        .SetPrefixExtractor(SliceTransform.CreateFixedPrefix(16))
                    },
                    { "index_status_activity_id", new ColumnFamilyOptions()
                        .SetBlockBasedTableFactory(activityBbto)
                        .SetWriteBufferSize(1UL << 20)
                        .SetMaxWriteBufferNumber(2)
                        .SetMinWriteBufferNumberToMerge(1)
                        .SetPrefixExtractor(SliceTransform.CreateFixedPrefix(2))
                    },
                    { "index_address_activity_id", new ColumnFamilyOptions()
                        .SetBlockBasedTableFactory(activityBbto)
                        .SetWriteBufferSize(1UL << 20)
                        .SetMaxWriteBufferNumber(2)
                        .SetMinWriteBufferNumberToMerge(1)
                        .SetPrefixExtractor(SliceTransform.CreateFixedPrefix(16))
                    }
                };

            return (rocksOptions, columnFamilies);
        }

        private (DbOptions dbOptions, ColumnFamilies columnFamilies) getMobilesOptions()
        {
            var opts = getDefaultOptions();

            var dbOptions = opts.dbOptions;
            dbOptions.SetCompression(RocksDbSharp.Compression.Lz4)
                     .SetMaxBackgroundCompactions(1)
                     .SetMaxBackgroundFlushes(1)
                     .IncreaseParallelism(1)
                     .SetTargetFileSizeBase(8UL << 20)
                     .SetTargetFileSizeMultiplier(2)
                     .SetLevelCompactionDynamicLevelBytes(false)

                     .SetUseDirectReads(false)
                     .SetUseDirectIoForFlushAndCompaction(false)
                     .SetCompactionReadaheadSize(2UL << 20)
                     .SetBytesPerSync(1UL << 20)

                     .SetUseFsync(0)
                     .SetWALTtlSeconds(0)
                     .SetWALSizeLimitMB(64)
                     .SetMaxTotalWalSize(64UL << 20)

                     .SetMaxOpenFiles(30)

                     .SetKeepLogFileNum(2)
                     .SetMaxLogFileSize(512 << 10)

                     .SetWriteBufferSize(1UL << 20)
                     .SetMaxWriteBufferNumber(2);

            var columnFamilies = opts.columnFamilies;

            var activityBbto = new BlockBasedTableOptions()
                    .SetBlockCache(blockCache.Handle)
                    .SetBlockSize(32 * 1024)
                    .SetCacheIndexAndFilterBlocks(true)
                    .SetPinL0FilterAndIndexBlocksInCache(true)
                    .SetFilterPolicy(BloomFilterPolicy.Create(10, false))
                    .SetWholeKeyFiltering(true)
                    .SetFormatVersion(6);

            var activityCfOpts = columnFamilies.ToList().Find(x => x.Name == "activity");
            activityCfOpts.Options.SetBlockBasedTableFactory(activityBbto)
                                  .SetWriteBufferSize(2UL << 20)
                                  .SetMaxWriteBufferNumber(2)
                                  .SetMinWriteBufferNumberToMerge(1);

            var rawTxCfOpts = columnFamilies.ToList().Find(x => x.Name == "raw_tx");
            rawTxCfOpts.Options.SetBlockBasedTableFactory(activityBbto)
                               .SetWriteBufferSize(4UL << 20)
                               .SetMaxWriteBufferNumber(2)
                               .SetMinWriteBufferNumberToMerge(1);

            var indexTable = new BlockBasedTableOptions()
                    .SetBlockCache(blockCache.Handle)
                    .SetBlockSize(8 * 1024)
                    .SetCacheIndexAndFilterBlocks(true)
                    .SetFilterPolicy(BloomFilterPolicy.Create(8, false))
                    .SetWholeKeyFiltering(true)
                    .SetFormatVersion(6);

            foreach (var cf in columnFamilies.Where(x => x.Name.StartsWith("index_")))
            {
                cf.Options
                    .SetBlockBasedTableFactory(indexTable)
                    .SetWriteBufferSize(512UL << 10)
                    .SetMaxWriteBufferNumber(2)
                    .SetMinWriteBufferNumberToMerge(1);
            }

            return (dbOptions, columnFamilies);
        }

        public void openDatabase()
        {
            if (database != null)
            {
                throw new Exception(String.Format("Rocks Database '{0}' is already open.", dbPath));
            }
            lock (rockLock)
            {
                var options = getDefaultOptions();
                if (optimizationType == RocksDBOptimizations.Mobiles)
                {
                    options = getMobilesOptions();
                }
                database = RocksDb.Open(options.dbOptions, dbPath, options.columnFamilies);

                // initialize column family handles
                activityCF = database.GetColumnFamily("activity");
                metaCF = database.GetColumnFamily("meta");
                rawTxCF = database.GetColumnFamily("raw_tx");

                idxBlockHeightActivityId = new StorageIndex("index_block_height_activity_id", database);
                idxActivityId = new StorageIndex("index_activity_id", database);
                idxStatusActivityId = new StorageIndex("index_status_activity_id", database);
                idxAddressActivityId = new StorageIndex("index_address_activity_id", database);

                // read initial meta values
                byte[] versionBytes = database.Get(META_KEY_DB_VERSION, metaCF);
                if (versionBytes == null)
                {
                    database.Put(META_KEY_DB_VERSION, dbVersion.GetBytesBE(), metaCF);
                    database.Put(META_KEY_MIN_BLOCK, minBlockNumber.GetBytesBE(), metaCF);
                    database.Put(META_KEY_MAX_BLOCK, maxBlockNumber.GetBytesBE(), metaCF);
                }
                else
                {
                    try
                    {
                        int tmpDbVersion = BinaryPrimitives.ReadInt32BigEndian(versionBytes);

                        if (tmpDbVersion < dbVersion)
                        {
                            Logging.warn("Activity Database '{0}' version '{1}' is too old, recreating.", dbPath, tmpDbVersion);

                            database.DropColumnFamily("activity");
                            database.DropColumnFamily("meta");
                            database.DropColumnFamily("raw_tx");
                            database.DropColumnFamily("index_block_height_activity_id");
                            database.DropColumnFamily("index_activity_id");
                            database.DropColumnFamily("index_status_activity_id");
                            database.DropColumnFamily("index_address_activity_id");

                            closeDatabase();
                            openDatabase();
                        }
                        else
                        {
                            byte[] minBlockBytes = database.Get(META_KEY_MIN_BLOCK, metaCF);
                            minBlockNumber = BinaryPrimitives.ReadUInt64BigEndian(minBlockBytes);

                            byte[] maxBlockBytes = database.Get(META_KEY_MAX_BLOCK, metaCF);
                            maxBlockNumber = BinaryPrimitives.ReadUInt64BigEndian(maxBlockBytes);
                        }
                    }
                    catch
                    {
                        throw new Exception(string.Format("Unable to read database metadata. Database {0} could be corrupt or invalid.", dbPath));
                    }
                }

                Logging.info("Activity: Opened Database {0}: Blocks {1} - {2}, version {3}", dbPath, minBlockNumber, maxBlockNumber, dbVersion);
                Logging.trace("Activity: Stats: {0}", database.GetProperty("rocksdb.stats"));
                lastUsedTime = DateTime.Now;
            }
        }

        public void logStats()
        {
            if (database != null)
            {
                if (blockCache != null)
                {
                    Logging.info("Activity: Common Cache Bytes Used: {0}", blockCache.GetUsage());
                }

                Logging.info("Activity: Stats [rocksdb.block-cache-usage] '{0}': {1}", dbPath, database.GetProperty("rocksdb.block-cache-usage"));
                Logging.info("Activity: Stats for '{0}': {1}", dbPath, database.GetProperty("rocksdb.dbstats"));
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

                // free all column families
                activityCF = null;
                metaCF = null;
                rawTxCF = null;
                idxBlockHeightActivityId = null;
                idxActivityId = null;
                idxStatusActivityId = null;
                idxAddressActivityId = null;

                database.Dispose();
                database = null;
            }
        }

        public void compact()
        {
            if (database != null)
            {
                try
                {
                    Logging.info("Activity: Performing compaction on database '{0}'.", dbPath);
                    lock (rockLock)
                    {
                        database.CompactRange(null, null, activityCF);
                        database.CompactRange(null, null, metaCF);
                        database.CompactRange(null, null, rawTxCF);
                        database.CompactRange(null, null, idxBlockHeightActivityId!.rocksIndexHandle);
                        database.CompactRange(null, null, idxActivityId!.rocksIndexHandle);
                        database.CompactRange(null, null, idxStatusActivityId!.rocksIndexHandle);
                    }
                }
                catch (Exception e)
                {
                    Logging.error("Activity: Error while performing regular maintenance on '{0}': {1}", dbPath, e.Message);
                }
            }
        }

        private void insertAddressIndexes(ActivityObject activity, byte[] timestampTypeIdKey, WriteBatch writeBatch)
        {
            if (activity.fromAddressList != null && activity.fromAddressList.Count > 0)
            {
                foreach (var addressEntry in activity.fromAddressList)
                {
                    idxAddressActivityId!.addIndexEntry(addressEntry.Key.addressNoChecksum.AsSpan(0, 16), timestampTypeIdKey, Array.Empty<byte>(), writeBatch);
                }
            }

            if (activity.toAddressList != null && activity.toAddressList.Count > 0)
            {
                foreach (var addressEntry in activity.toAddressList)
                {
                    idxAddressActivityId!.addIndexEntry(addressEntry.Key.addressNoChecksum.AsSpan(0, 16), timestampTypeIdKey, Array.Empty<byte>(), writeBatch);
                }
            }
        }

        public bool insertActivity(ActivityObject activity)
        {
            lock (rockLock)
            {
                if (database == null)
                {
                    return false;
                }
                byte[] seedHash = activity.seedHash;
                Span<byte> seed16 = seedHash.Length >= 16 ? seedHash.AsSpan(0, 16) : seedHash;
                byte[]? timestampTypeIdKey = idxActivityId!.getEntry(activity.id, seed16);
                if (timestampTypeIdKey != null && timestampTypeIdKey.Length > 0)
                {
                    return false;
                }

                lastUsedTime = DateTime.Now;
                using (WriteBatch writeBatch = new WriteBatch())
                {
                    timestampTypeIdKey = StorageIndex.combineKeys(Clock.getTimestampMillis().GetBytesBE(), StorageIndex.combineKeys(((short)activity.type).GetBytesBE(), activity.id));
                    byte[] key = StorageIndex.combineKeys(seed16, timestampTypeIdKey);
                    writeBatch.Put(StorageIndex.combineKeys(ACTIVITY_KEY_PAYLOAD, key), activity.GetBytes(), activityCF);
                    writeBatch.Put(StorageIndex.combineKeys(ACTIVITY_KEY_META, activity.id), activity.GetMetaBytes(), activityCF);
                    idxActivityId.addIndexEntry(activity.id, seed16, timestampTypeIdKey, writeBatch);

                    insertAddressIndexes(activity, timestampTypeIdKey, writeBatch);

                    if (activity.transaction != null
                        && !database.HasKey(activity.id, rawTxCF))
                    {
                        writeBatch.Put(activity.id, activity.transaction.getBytes(false, true), rawTxCF);
                    }
                    if (activity.status == ActivityStatus.Final)
                    {
                        if (activity.appliedBlockHeight == 0)
                        {
                            throw new Exception("Cannot set status to final with applied block height 0.");
                        }
                        idxBlockHeightActivityId!.addIndexEntry(activity.appliedBlockHeight.GetBytesBE(), activity.id, Array.Empty<byte>(), writeBatch);
                    }
                    else
                    {
                        idxStatusActivityId!.addIndexEntry(((short)activity.status).GetBytesBE(), activity.id, Array.Empty<byte>(), writeBatch);
                    }
                    updateMinMax(writeBatch, activity.appliedBlockHeight);
                    database.Write(writeBatch);
                }
            }
            return true;
        }

        public ActivityObject? getActivityById(byte[] id, byte[]? seedHash = null, bool includeTransaction = false)
        {
            lock (rockLock)
            {
                if (database == null)
                {
                    return null;
                }
                byte[]? seed16 = seedHash?.Length >= 16 ? seedHash.AsSpan(0, 16).ToArray() : seedHash;
                foreach (var (indexMem, valueMem) in idxActivityId!.getEntriesForKey(id, seed16))
                {
                    if (seedHash == null || seedHash.Length == 0 || indexMem.Span.SequenceEqual(seed16))
                    {
                        short typeShort = BinaryPrimitives.ReadInt16BigEndian(valueMem.Span.Slice(8, 2));

                        byte[] payloadKey = StorageIndex.combineKeys(ACTIVITY_KEY_PAYLOAD, StorageIndex.combineKeys(indexMem.Span, valueMem.Span));
                        byte[] payload = database.Get(payloadKey, activityCF);

                        byte[] metaKey = StorageIndex.combineKeys(ACTIVITY_KEY_META, id);
                        byte[] meta = database.Get(metaKey, activityCF);

                        byte[] txBytes = database.Get(id, rawTxCF);

                        return new ActivityObject(payload, indexMem.ToArray(), (ActivityType)typeShort, id, meta, txBytes);
                    }
                }
            }
            return null;
        }

        private void updateMinMax(WriteBatch writeBatch, ulong blockNum)
        {
            if (blockNum == 0)
            {
                return;
            }

            if (minBlockNumber == 0 || blockNum < minBlockNumber)
            {
                minBlockNumber = blockNum;
                writeBatch.Put(META_KEY_MIN_BLOCK, minBlockNumber.GetBytesBE(), metaCF);
            }
            if (maxBlockNumber == 0 || blockNum > maxBlockNumber)
            {
                maxBlockNumber = blockNum;
                writeBatch.Put(META_KEY_MAX_BLOCK, maxBlockNumber.GetBytesBE(), metaCF);
            }
        }

        public List<ActivityObject> getActivitiesBySeedHashAndType(byte[] seedHash, ActivityType? typeFilter, byte[]? fromActivityId = null, int count = 0, bool descending = false)
        {
            lock (rockLock)
            {
                var result = new List<ActivityObject>(count > 0 ? count : 64);

                if (database == null || seedHash == null || seedHash.Length == 0)
                    return result;

                if (count <= 0) count = 50;
                lastUsedTime = DateTime.Now;

                byte[] seed16 = seedHash.Length >= 16 ? seedHash.AsSpan(0, 16).ToArray() : seedHash;

                byte[] payloadSeedPrefix = StorageIndex.combineKeys(ACTIVITY_KEY_PAYLOAD, seed16);

                // Compute an exclusive upper bound for our range: [0x00|seed16] .. [0x00|seed16|0xFF] (exclusive)
                byte[] upperBound = StorageIndex.combineKeys(payloadSeedPrefix, oneByteFF);

                // Resolve fromActivityId via secondary index
                byte[]? exactFromPayloadKey = null;
                if (fromActivityId != null && fromActivityId.Length > 0)
                {
                    var tsTypeIdKey = idxActivityId!.getEntry(fromActivityId, seed16);
                    if (tsTypeIdKey != null && tsTypeIdKey.Length > 0)
                        exactFromPayloadKey = StorageIndex.combineKeys(payloadSeedPrefix, tsTypeIdKey);
                }

                // Use total order and explicit bound.
                var ro = new ReadOptions().SetTotalOrderSeek(true);
                if (!descending)
                {
                    // iterate_upper_bound is only used for forward scans
                    ro.SetIterateUpperBound(upperBound);
                }

                using var it = database.NewIterator(activityCF, ro);

                ReadOnlySpan<byte> mustPrefix = payloadSeedPrefix;

                if (!descending)
                {
                    if (exactFromPayloadKey != null)
                    {
                        it.Seek(exactFromPayloadKey);
                        if (it.Valid() && it.Key().AsSpan().SequenceEqual(exactFromPayloadKey))
                            it.Next(); // exclusive

                        while (it.Valid() && !hasPrefix(it.Key(), mustPrefix))
                            it.Next();
                    }
                    else
                    {
                        it.Seek(payloadSeedPrefix);
                        while (it.Valid() && !hasPrefix(it.Key(), mustPrefix))
                            it.Next();
                    }

                    for (; it.Valid(); it.Next())
                    {
                        var k = it.Key().AsSpan();
                        if (!hasPrefix(k, mustPrefix)) break;

                        var suffix = k.Slice(1 + 16);
                        if (suffix.Length < 10) continue;

                        short typeShort = BinaryPrimitives.ReadInt16BigEndian(suffix.Slice(8, 2));
                        if (typeFilter != null && typeShort != (short)typeFilter.Value) continue;

                        var payload = it.Value();
                        if (payload == null || payload.Length == 0) continue;

                        byte[] realId = suffix.Slice(10).ToArray();

                        byte[] metaKey = StorageIndex.combineKeys(ACTIVITY_KEY_META, realId);
                        byte[] meta = database.Get(metaKey, activityCF);

                        result.Add(new ActivityObject(payload, seed16, (ActivityType)typeShort, realId, meta, null));
                        if (result.Count >= count) break;
                    }
                }
                else
                {
                    if (exactFromPayloadKey != null)
                    {
                        it.Seek(exactFromPayloadKey);
                        if (it.Valid() && it.Key().AsSpan().SequenceEqual(exactFromPayloadKey))
                            it.Prev(); // exclusive
                        else if (!it.Valid())
                            it.SeekToLast();
                    }
                    else
                    {
                        it.Seek(upperBound);
                        if (!it.Valid()) it.SeekToLast();
                    }

                    while (it.Valid() && !hasPrefix(it.Key(), mustPrefix))
                        it.Prev();

                    for (; it.Valid(); it.Prev())
                    {
                        var k = it.Key().AsSpan();
                        if (!hasPrefix(k, mustPrefix)) break;

                        var suffix = k.Slice(1 + 16);
                        if (suffix.Length < 10) continue;

                        short typeShort = BinaryPrimitives.ReadInt16BigEndian(suffix.Slice(8, 2));
                        if (typeFilter != null && typeShort != (short)typeFilter.Value) continue;

                        var payload = it.Value();
                        if (payload == null || payload.Length == 0) continue;

                        byte[] realId = suffix.Slice(10).ToArray();

                        byte[] metaKey = StorageIndex.combineKeys(ACTIVITY_KEY_META, realId);
                        byte[] meta = database.Get(metaKey, activityCF);

                        result.Add(new ActivityObject(payload, seed16, (ActivityType)typeShort, realId, meta, null));
                        if (result.Count >= count) break;
                    }
                }

                return result;
            }
        }

        static bool hasPrefix(ReadOnlySpan<byte> key, ReadOnlySpan<byte> prefix)
            => key.Length >= prefix.Length && key.Slice(0, prefix.Length).SequenceEqual(prefix);

        public List<byte[]> revertTransactionsByBlockHeight(ulong blockHeight)
        {
            lock (rockLock)
            {
                List<byte[]> reverted = new();
                if (database == null)
                    return reverted;

                lastUsedTime = DateTime.Now;

                using (var wb = new WriteBatch())
                {
                    foreach (var (indexMem, valueMem) in idxBlockHeightActivityId!.getEntriesForKey(blockHeight.GetBytesBE()))
                    {
                        var id = indexMem.ToArray();
                        updateStatus(id, ActivityStatus.Reverted, blockHeight);
                        reverted.Add(id);
                    }
                    database.Write(wb);
                }
                return reverted;
            }
        }

        public bool updateStatus(byte[] id, ActivityStatus status, ulong blockHeight, long timestamp = 0)
        {
            lock (rockLock)
            {
                if (database == null)
                    return false;

                lastUsedTime = DateTime.Now;

                using (var wb = new WriteBatch())
                {
                    var metaKey = StorageIndex.combineKeys(ACTIVITY_KEY_META, id);

                    // Remove existing indexes
                    var existingMetaEntry = database.Get(metaKey, activityCF);
                    if (existingMetaEntry == null || existingMetaEntry.Length == 0)
                    {
                        return false;
                    }
                    var parsedMeta = ActivityObject.ParseMetaBytes(existingMetaEntry);
                    long ts = timestamp;
                    if (timestamp == 0)
                    {
                        ts = parsedMeta.timestamp;
                    }

                    if (parsedMeta.status == ActivityStatus.Final)
                    {
                        idxBlockHeightActivityId!.delIndexEntry(parsedMeta.appliedBlockHeight.GetBytesBE(), id, wb);
                    }
                    else
                    {
                        idxStatusActivityId!.delIndexEntry(((short)parsedMeta.status).GetBytesBE(), id, wb);
                    }

                    // Update meta and add new indexes
                    byte[] metaBytes = ActivityObject.GetMetaBytes(status, blockHeight, ts);
                    wb.Put(metaKey, metaBytes, activityCF);

                    if (status == ActivityStatus.Final)
                    {
                        if (blockHeight == 0)
                        {
                            throw new Exception("Cannot set status to final with applied block height 0.");
                        }
                        idxBlockHeightActivityId!.addIndexEntry(blockHeight.GetBytesBE(), id, Array.Empty<byte>(), wb);
                    }
                    else
                    {
                        idxStatusActivityId!.addIndexEntry(((short)status).GetBytesBE(), id, Array.Empty<byte>(), wb);
                    }

                    updateMinMax(wb, blockHeight);
                    database.Write(wb);
                }

                return true;
            }
        }

        public bool updateValue(byte[] id, IxiNumber value)
        {
            lock (rockLock)
            {
                if (database == null)
                    return false;

                lastUsedTime = DateTime.Now;

                bool anyUpdated = false;
                using (var wb = new WriteBatch())
                {
                    foreach (var (indexMem, valueMem) in idxActivityId!.getEntriesForKey(id))
                    {
                        var seedHash = indexMem.ToArray();
                        var tsTypeId = valueMem.ToArray();

                        var payloadKey = StorageIndex.combineKeys(ACTIVITY_KEY_PAYLOAD, StorageIndex.combineKeys(seedHash, tsTypeId));

                        byte[] payload = database.Get(payloadKey, activityCF);

                        short typeShort = BinaryPrimitives.ReadInt16BigEndian(tsTypeId.AsSpan(8, 2));
                        byte[] realId = tsTypeId.AsSpan(10).ToArray();

                        var ao = new ActivityObject(payload, seedHash, (ActivityType)typeShort, realId, null, null)
                        {
                            value = value
                        };

                        wb.Put(payloadKey, ao.GetBytes(), activityCF);
                        anyUpdated = true;
                    }

                    if (anyUpdated)
                        database.Write(wb);
                }

                return anyUpdated;
            }
        }

        public List<ActivityObject> getActivitiesByStatus(ActivityStatus status, bool includeTransaction)
        {
            if (status == ActivityStatus.Final)
            {
                throw new Exception("Cannot query by final status, as it is expected to be the most common status and is indexed by block height. Please query by block height range instead.");
            }
            lock (rockLock)
            {
                List<ActivityObject> activities = new List<ActivityObject>();
                if (database == null)
                {
                    return activities;
                }
                foreach (var (indexMem, valueMem) in idxStatusActivityId!.getEntriesForKey(((short)status).GetBytesBE()))
                {
                    var activity = getActivityById(indexMem.ToArray(), null, includeTransaction);
                    if (activity == null)
                    {
                        throw new Exception(string.Format("Inconsistent index: activity with id {0} not found for status {1}. Database may be corrupt.", Convert.ToHexString(indexMem.ToArray()), status));
                    }
                    activities.Add(activity);
                }
                return activities;
            }
        }

        public List<ActivityObject> getActivitiesByAddress(
            Address address,
            ActivityType? typeFilter,
            byte[]? fromActivityId = null,
            int count = 50,
            bool descending = false)
        {
            lock (rockLock)
            {
                var result = new List<ActivityObject>(count);

                if (database == null)
                    return result;

                Span<byte> address16 = address.addressNoChecksum.Length >= 16 ? address.addressNoChecksum.AsSpan(0, 16) : address.addressNoChecksum;

                lastUsedTime = DateTime.Now;

                byte[] upperBound = StorageIndex.combineKeys(address16, oneByteFF);

                // Resolve fromActivityId via secondary index
                byte[]? exactFromKey = null;

                if (fromActivityId != null && fromActivityId.Length > 0)
                {
                    foreach (var (_, valueMem) in idxActivityId!.getEntriesForKey(fromActivityId))
                    {
                        var candidateKey = StorageIndex.combineKeys(address16, valueMem.Span);

                        // verify it actually exists in address index
                        var existing = database.Get(candidateKey, idxAddressActivityId!.rocksIndexHandle);
                        if (existing != null)
                        {
                            exactFromKey = candidateKey;
                            break;
                        }
                    }
                }

                var ro = new ReadOptions().SetTotalOrderSeek(true);
                if (!descending)
                    ro.SetIterateUpperBound(upperBound);

                using var it = database.NewIterator(idxAddressActivityId!.rocksIndexHandle, ro);

                if (!descending)
                {
                    if (exactFromKey != null)
                    {
                        it.Seek(exactFromKey);

                        if (it.Valid() && it.Key().AsSpan().SequenceEqual(exactFromKey))
                            it.Next(); // exclusive

                        while (it.Valid() && !hasPrefix(it.Key(), address16))
                            it.Next();
                    }
                    else
                    {
                        it.Seek(address16);
                        while (it.Valid() && !hasPrefix(it.Key(), address16))
                            it.Next();
                    }

                    for (; it.Valid(); it.Next())
                    {
                        var k = it.Key().AsSpan();
                        if (!hasPrefix(k, address16)) break;

                        var suffix = k.Slice(address16.Length);
                        if (suffix.Length < 10) continue;

                        short typeShort = BinaryPrimitives.ReadInt16BigEndian(suffix.Slice(8, 2));
                        if (typeFilter != null && typeShort != (short)typeFilter.Value) continue;

                        byte[] realId = suffix.Slice(10).ToArray();

                        var ao = getActivityById(realId);
                        if (ao != null)
                            result.Add(ao);

                        if (result.Count >= count) break;
                    }
                }
                else
                {
                    if (exactFromKey != null)
                    {
                        it.Seek(exactFromKey);

                        if (it.Valid() && it.Key().AsSpan().SequenceEqual(exactFromKey))
                            it.Prev(); // exclusive
                        else if (!it.Valid())
                            it.SeekToLast();
                    }
                    else
                    {
                        it.Seek(upperBound);
                        if (!it.Valid()) it.SeekToLast();
                    }

                    while (it.Valid() && !hasPrefix(it.Key(), address16))
                        it.Prev();

                    for (; it.Valid(); it.Prev())
                    {
                        var k = it.Key().AsSpan();
                        if (!hasPrefix(k, address16)) break;

                        var suffix = k.Slice(address16.Length);
                        if (suffix.Length < 10) continue;

                        short typeShort = BinaryPrimitives.ReadInt16BigEndian(suffix.Slice(8, 2));
                        if (typeFilter != null && typeShort != (short)typeFilter.Value) continue;

                        byte[] realId = suffix.Slice(10).ToArray();

                        var ao = getActivityById(realId);
                        if (ao != null)
                            result.Add(ao);

                        if (result.Count >= count) break;
                    }
                }

                return result;
            }
        }

        public void flush()
        {
            if (database == null)
            {
                throw new Exception($"Database {dbPath} is not open.");
            }

            Logging.info("RocksDB: Flushing database '{0}'.", dbPath);
            lock (rockLock)
            {
                database.Flush(new FlushOptions().SetWaitForFlush(true));
            }
        }
    }

    public class ActivityStorage : IActivityStorage
    {
        protected string pathBase;

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

        private bool running = false;

        private ulong maxBlocksPerDatabase = 0;

        private RocksDBOptimizations optimizationType;

        public ActivityStorage(string path, ulong maxDatabaseCache, ulong maxBlocksPerDatabase, RocksDBOptimizations optimizationType, long minDiskSpace)
        {
            this.pathBase = path;
            this.maxDatabaseCache = maxDatabaseCache;
            this.maxBlocksPerDatabase = maxBlocksPerDatabase;

            this.optimizationType = optimizationType;
            this.minDiskSpace = minDiskSpace;
        }

        private RocksDBInternal? getDatabase(ulong blockNum, bool onlyExisting = false)
        {
            if (running == false)
            {
                throw new Exception("Error while getting database, RocksDB is shutting down.");
            }
            // Open or create the db which should contain blockNum
            ulong baseBlockNum = maxBlocksPerDatabase > 0 ? blockNum / maxBlocksPerDatabase : 0;
            RocksDBInternal db;
            lock (openDatabases)
            {
                if (openDatabases.ContainsKey(baseBlockNum))
                {
                    db = openDatabases[baseBlockNum];
                    if (!db.isOpen)
                    {
                        Logging.info("Activity: Database {0} is not opened - opening.", baseBlockNum);
                        db.openDatabase();
                    }
                }
                else
                {
                    if (!hasSufficientDiskSpace())
                    {
                        throw new IOException($"Activity: Error opening database, free disk space is below {minDiskSpace}B.");
                    }

                    string db_path = Path.Combine(pathBase, baseBlockNum.ToString());
                    if (onlyExisting)
                    {
                        if (!Directory.Exists(db_path))
                        {
                            return null;
                        }
                    }

                    Logging.info("Activity: Opening a database for activity {0} - {1}.", baseBlockNum * maxBlocksPerDatabase, (baseBlockNum * maxBlocksPerDatabase) + maxBlocksPerDatabase - 1);
                    db = new RocksDBInternal(db_path, commonBlockCache!, optimizationType);
                    db.openDatabase();
                    openDatabases.Add(baseBlockNum, db);

                    if (openDatabases.Count > maxOpenDatabases)
                    {
                        closeOldestDatabase();
                    }
                }
            }
            return db;
        }

        public bool prepareStorage(bool optimize)
        {
            if (running == true)
            {
                return false;
            }

            // check that the base path exists, or create it
            if (!Directory.Exists(pathBase))
            {
                try
                {
                    Directory.CreateDirectory(pathBase);
                }
                catch (Exception e)
                {
                    Logging.error("Unable to prepare block database path '{0}': {1}", pathBase, e.Message);
                    return false;
                }
            }
            // Prepare cache
            commonBlockCache = Cache.CreateLru(maxDatabaseCache);
            // DB optimization
            if (optimize)
            {
                Logging.info("Activity: Performing pre-start DB compaction and optimization.");
                foreach (string db in Directory.GetDirectories(pathBase))
                {
                    Logging.info("Activity: Optimizing [{0}].", db);
                    RocksDBInternal temp_db = new RocksDBInternal(db, commonBlockCache, optimizationType);
                    try
                    {
                        temp_db.openDatabase();
                        temp_db.compact();
                        temp_db.closeDatabase();
                    }
                    catch (Exception e)
                    {
                        Logging.warn("Activity: Error while opening database {0}: {1}", db, e.Message);
                    }
                }
                Logging.info("Activity: Pre-start optimization complete.");
            }

            running = true;

            Logging.info("Last activity block number is: #{0}", getHighestBlockInStorage());
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
            Logging.info($"Free space: {availSpace}B > {minDiskSpace}B");
            return availSpace >= minDiskSpace;
        }

        public void cleanupCache()
        {
            lock (openDatabases)
            {
                Logging.info("Activity Registered database list:");
                List<ulong> toDrop = new List<ulong>();
                foreach (var db in openDatabases)
                {
                    Logging.info("Activity: [{0}]: open: {1}, last used: {2}",
                        db.Value.dbPath,
                        db.Value.isOpen,
                        db.Value.lastUsedTime
                        );

                    if ((DateTime.Now - db.Value.lastUsedTime).TotalSeconds >= closeAfterSeconds)
                    {
                        if (db.Value.maxBlockNumber == 0)
                        {
                            continue;
                        }
                        if (db.Value.maxBlockNumber >= highestBlockNum)
                        {
                            // never close the databases within redacted window
                            continue;
                        }
                        Logging.info("Activity: Closing '{0}' due to inactivity.", db.Value.dbPath);
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
                    Logging.error("Activity: Disk free space is low, closing all databases, to prevent data corruption.");
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
                    Logging.info("Activity: Database [{0}] was still in use, skipping until it is closed.", db.dbPath);
                    continue;
                }

                Logging.info("Activity: Compacting closed database [{0}].", db.dbPath);
                try
                {
                    db.openDatabase();
                }
                catch (Exception)
                {
                    // these were attempted too quickly and RocksDB internal still has some pointers open
                    reopenCleanupList.Enqueue(db);
                    Logging.info("Activity: Database [{0}] was locked by another process, will try again later.", db.dbPath);
                }
                if (db.isOpen)
                {
                    db.compact();
                    db.closeDatabase();
                    Logging.info("Activity: Compacting succeeded");
                }
            }
            lastReopenOptimize = DateTime.Now;
        }

        private void closeOldestDatabase()
        {
            var oldestDb = openDatabases.OrderBy(x => x.Value.lastUsedTime).Where(x => x.Value.isOpen && x.Value.maxBlockNumber > 0 && x.Value.maxBlockNumber < highestBlockNum).FirstOrDefault();
            if (oldestDb.Value != null)
            {
                oldestDb.Value.closeDatabase();
                openDatabases.Remove(oldestDb.Key);
                reopenCleanupList.Enqueue(oldestDb.Value);
            }
        }

        public void deleteData()
        {
            if (Directory.Exists(pathBase))
            {
                Directory.Delete(pathBase, true);
            }
        }

        private void closeDatabases()
        {
            var toClose = openDatabases.Keys.ToList();
            foreach (var key in toClose)
            {
                var db = openDatabases[key];
                Logging.info("Activity: Shutdown, closing '{0}'", db.dbPath);
                db.closeDatabase();
                openDatabases.Remove(key);
                reopenCleanupList.Enqueue(db);
            }
        }

        public void stopStorage()
        {
            lock (openDatabases)
            {
                if (running == false)
                {
                    return;
                }
                closeDatabases();
                compact();
                running = false;
            }
        }


        public ulong getHighestBlockInStorage()
        {
            if (highestBlockNum > 0)
            {
                return highestBlockNum;
            }

            // find our absolute highest block db
            long latest_db = -1;
            foreach (var d in Directory.EnumerateDirectories(pathBase))
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

        public ulong getLowestBlockInStorage()
        {
            if (lowestBlockNum > 0)
            {
                return lowestBlockNum;
            }

            // find our absolute lowest block db
            ulong oldest_db = ulong.MaxValue;
            foreach (var d in Directory.EnumerateDirectories(pathBase))
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

        public List<ActivityObject> getActivitiesBySeedHashAndType(byte[] seedHash, ActivityType? type, byte[]? fromActivityId = null, int count = 0, bool descending = false)
        {
            lock (openDatabases)
            {
                var db = getDatabase(0, true);

                if (db == null)
                {
                    return new();
                }

                return db.getActivitiesBySeedHashAndType(seedHash.AsSpan(0, 16).ToArray(), type, fromActivityId, count, descending);
            }
        }

        public bool insertActivity(ActivityObject activity)
        {
            lock (openDatabases)
            {
                var db = getDatabase(0);
                if (db!.insertActivity(activity))
                {
                    if (activity.appliedBlockHeight > getHighestBlockInStorage())
                    {
                        highestBlockNum = activity.appliedBlockHeight;
                    }
                    return true;
                }
                return false;
            }
        }

        public ActivityObject? getActivityById(byte[] id, byte[]? seedHash = null, bool includeTransaction = false)
        {
            lock (openDatabases)
            {
                var db = getDatabase(0);
                if (db == null)
                {
                    return null;
                }
                return db.getActivityById(id, seedHash, includeTransaction);
            }
        }

        public List<byte[]> revertTransactionsByBlockHeight(ulong blockHeight)
        {
            lock (openDatabases)
            {
                var db = getDatabase(0);
                return db!.revertTransactionsByBlockHeight(blockHeight);
            }
        }

        public bool updateStatus(byte[] id, ActivityStatus status, ulong blockHeight, long timestamp = 0)
        {
            lock (openDatabases)
            {
                var db = getDatabase(0);
                if (db!.updateStatus(id, status, blockHeight, timestamp))
                {
                    if (blockHeight > getHighestBlockInStorage())
                    {
                        highestBlockNum = blockHeight;
                    }
                    return true;
                }
                return false;
            }
        }

        public bool updateValue(byte[] id, IxiNumber value)
        {
            lock (openDatabases)
            {
                var db = getDatabase(0);
                return db!.updateValue(id, value);
            }
        }

        public List<ActivityObject> getActivitiesByStatus(ActivityStatus status, bool includeTransaction)
        {
            lock (openDatabases)
            {
                var db = getDatabase(0);
                return db!.getActivitiesByStatus(status, includeTransaction);
            }
        }

        public List<ActivityObject> getActivitiesByAddress(Address address, ActivityType? type, byte[]? fromActivityId = null, int count = 50, bool descending = false)
        {
            lock (openDatabases)
            {
                var db = getDatabase(0, true);
                if (db == null)
                    return new();

                return db.getActivitiesByAddress(address, type, fromActivityId, count, descending);
            }
        }

        public void sleep()
        {
            lock (openDatabases)
            {
                var toClose = openDatabases.Keys.ToList();
                foreach (var key in toClose)
                {
                    var db = openDatabases[key];
                    Logging.info("RocksDB: Closing '{0}'", db.dbPath);
                    db.closeDatabase();
                }
            }
        }
    }
}

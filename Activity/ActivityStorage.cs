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

#if __ROCKS_DB_SHARP__

using IXICore.Meta;
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
        private RocksDb database = null;
        // global column families
        private ColumnFamilyHandle metaCF;
        private ColumnFamilyHandle activityCF;

        private StorageIndex idxActivityId;

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
        public int dbVersion { get; private set; }
        public bool isOpen
        {
            get
            {
                return database != null;
            }
        }
        public DateTime lastUsedTime { get; private set; }
        // Caches (shared with other rocksDb
        private Cache blockCache = null;

        public RocksDBInternal(string dbPath, Cache blockCache)
        {
            minBlockNumber = 0;
            maxBlockNumber = 0;
            dbVersion = 0;

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
                metaBbto.SetFilterPolicy(BloomFilterPolicy.Create(14, true));
                metaBbto.SetWholeKeyFiltering(true);
                metaBbto.SetFormatVersion(6);

                var columnFamilies = new ColumnFamilies
                {
                    { "activity", new ColumnFamilyOptions()
                        .SetBlockBasedTableFactory(activityBbto)
                        .SetWriteBufferSize(16UL << 20)
                        .SetMaxWriteBufferNumber(2)
                        .SetMinWriteBufferNumberToMerge(1)
                        .SetPrefixExtractor(SliceTransform.CreateFixedPrefix(16))
                    },
                    { "meta", new ColumnFamilyOptions()
                        .SetBlockBasedTableFactory(metaBbto)
                        .OptimizeForPointLookup(128)
                        .SetWriteBufferSize(64UL << 10)
                        .SetMaxWriteBufferNumber(1)
                    },
                    { "index_activity_id", new ColumnFamilyOptions()
                        .SetBlockBasedTableFactory(activityBbto)
                        .SetWriteBufferSize(16UL << 20)
                        .SetMaxWriteBufferNumber(2)
                        .SetMinWriteBufferNumberToMerge(1)
                        .SetPrefixExtractor(SliceTransform.CreateFixedPrefix(16))
                    }
                };

                database = RocksDb.Open(rocksOptions, dbPath, columnFamilies);

                // initialize column family handles
                activityCF = database.GetColumnFamily("activity");
                metaCF = database.GetColumnFamily("meta");

                idxActivityId = new StorageIndex("index_activity_id", database);

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
                        dbVersion = BinaryPrimitives.ReadInt32BigEndian(versionBytes);

                        byte[] minBlockBytes = database.Get(META_KEY_MIN_BLOCK, metaCF);
                        minBlockNumber = BinaryPrimitives.ReadUInt64BigEndian(minBlockBytes);

                        byte[] maxBlockBytes = database.Get(META_KEY_MAX_BLOCK, metaCF);
                        maxBlockNumber = BinaryPrimitives.ReadUInt64BigEndian(maxBlockBytes);
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
                idxActivityId = null;

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
                        database.CompactRange(null, null, idxActivityId.rocksIndexHandle);
                    }
                }
                catch (Exception e)
                {
                    Logging.error("Activity: Error while performing regular maintenance on '{0}': {1}", dbPath, e.Message);
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
                lastUsedTime = DateTime.Now;
                using (WriteBatch writeBatch = new WriteBatch())
                {
                    byte[] timestampTypeIdKey = StorageIndex.combineKeys(Clock.getTimestampMillis().GetBytesBE(), StorageIndex.combineKeys(((short)activity.type).GetBytesBE(), activity.id));
                    byte[] key = StorageIndex.combineKeys(activity.seedHash, timestampTypeIdKey);
                    writeBatch.Put(StorageIndex.combineKeys(ACTIVITY_KEY_PAYLOAD, key), activity.GetBytes(), activityCF);
                    writeBatch.Put(StorageIndex.combineKeys(ACTIVITY_KEY_META, key), activity.GetMetaBytes(), activityCF);
                    idxActivityId.addIndexEntry(activity.id, activity.seedHash, timestampTypeIdKey);
                    updateMinMax(writeBatch, activity.blockHeight);
                    database.Write(writeBatch);
                }
            }
            return true;
        }

        private void updateMinMax(WriteBatch writeBatch, ulong blockNum)
        {
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

        public List<ActivityObject> getActivitiesBySeedHashAndType(byte[] seedHash, ActivityType? typeFilter, byte[] fromActivityId = null, int count = 0, bool descending = false)
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
                byte[] exactFromPayloadKey = null;
                if (fromActivityId != null && fromActivityId.Length > 0)
                {
                    var tsTypeIdKey = idxActivityId.getEntry(fromActivityId, seed16);
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

                        byte[] metaKey = StorageIndex.combineKeys(ACTIVITY_KEY_META, StorageIndex.combineKeys(seed16, suffix.ToArray()));
                        byte[] meta = database.Get(metaKey, activityCF);

                        byte[] realId = suffix.Slice(10).ToArray();

                        result.Add(new ActivityObject(payload, seed16, (ActivityType)typeShort, realId, meta));
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

                        byte[] metaKey = StorageIndex.combineKeys(ACTIVITY_KEY_META, StorageIndex.combineKeys(seed16, suffix.ToArray()));
                        byte[] meta = database.Get(metaKey, activityCF);

                        byte[] realId = suffix.Slice(10).ToArray();

                        result.Add(new ActivityObject(payload, seed16, (ActivityType)typeShort, realId, meta));
                        if (result.Count >= count) break;
                    }
                }

                return result;
            }
        }

        static bool hasPrefix(ReadOnlySpan<byte> key, ReadOnlySpan<byte> prefix)
            => key.Length >= prefix.Length && key.Slice(0, prefix.Length).SequenceEqual(prefix);

        public bool updateStatus(byte[] id, ActivityStatus status, ulong blockHeight, long timestamp = 0)
        {
            lock (rockLock)
            {
                if (database == null)
                    return false;

                lastUsedTime = DateTime.Now;

                bool anyUpdated = false;
                using (var wb = new WriteBatch())
                {
                    // Iterate all entries for this id (in case of multiple seed hashes)
                    foreach (var (indexMem, valueMem) in idxActivityId.getEntriesForKey(id))
                    {
                        var seedHash = indexMem.ToArray();
                        var tsTypeId = valueMem.ToArray();

                        var metaKey = StorageIndex.combineKeys(ACTIVITY_KEY_META, StorageIndex.combineKeys(seedHash, tsTypeId));

                        long ts;
                        if (timestamp > 0)
                        {
                            ts = timestamp;
                        }
                        else
                        {
                            var existingMetaEntry = database.Get(metaKey, activityCF);
                            var parsedMeta = ActivityObject.ParseMetaBytes(existingMetaEntry);
                            ts = parsedMeta.timestamp;
                        }

                        byte[] metaBytes = ActivityObject.GetMetaBytes(status, blockHeight, ts);
                        wb.Put(metaKey, metaBytes, activityCF);

                        updateMinMax(wb, blockHeight);
                        anyUpdated = true;
                    }

                    if (anyUpdated)
                        database.Write(wb);
                }

                return anyUpdated;
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
                    foreach (var (indexMem, valueMem) in idxActivityId.getEntriesForKey(id))
                    {
                        var seedHash = indexMem.ToArray();
                        var tsTypeId = valueMem.ToArray();

                        var payloadKey = StorageIndex.combineKeys(ACTIVITY_KEY_PAYLOAD, StorageIndex.combineKeys(seedHash, tsTypeId));

                        byte[] payload = database.Get(payloadKey, activityCF);

                        short typeShort = BinaryPrimitives.ReadInt16BigEndian(tsTypeId.AsSpan(8, 2));
                        byte[] realId = tsTypeId.AsSpan(10).ToArray();

                        var ao = new ActivityObject(payload, seedHash, (ActivityType)typeShort, realId, null)
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
    }

    public class ActivityStorage : IActivityStorage
    {
        protected string pathBase;

        private readonly Dictionary<ulong, RocksDBInternal> openDatabases = new Dictionary<ulong, RocksDBInternal>();
        public uint closeAfterSeconds = 60;

        private int maxOpenDatabases = 50;
        private long minDiskSpace = 1L * 1024L * 1024L * 1024L;

        // Runtime stuff
        private Cache commonBlockCache = null;
        private Queue<RocksDBInternal> reopenCleanupList = new Queue<RocksDBInternal>();
        private DateTime lastReopenOptimize = DateTime.Now;

        private ulong highestBlockNum = 0;
        private ulong lowestBlockNum = 0;

        private ulong maxDatabaseCache;

        private bool running = false;

        private ulong maxBlocksPerDatabase = 0;

        public ActivityStorage(string path, ulong maxDatabaseCache, ulong maxBlocksPerDatabase)
        {
            this.pathBase = path;
            this.maxDatabaseCache = maxDatabaseCache;
            this.maxBlocksPerDatabase = maxBlocksPerDatabase;
        }

        private RocksDBInternal getDatabase(ulong blockNum, bool onlyExisting = false)
        {
            if (running == false)
            {
                throw new Exception("Error while getting database, RocksDB is shutting down.");
            }
            // Open or create the db which should contain blockNum
            ulong baseBlockNum = maxBlocksPerDatabase > 0 ? blockNum / maxBlocksPerDatabase : 0;
            RocksDBInternal db = null;
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
                        throw new InvalidOperationException("Activity: Error opening database, free disk space is below 1GB.");
                    }

                    string db_path = Path.Combine(pathBase, baseBlockNum.ToString());
                    if (onlyExisting)
                    {
                        if (!Directory.Exists(db_path))
                        {
                            Logging.info("Activity: Open of '{0} requested with onlyExisting = true, but it does not exist.", db_path);
                            return null;
                        }
                    }

                    Logging.info("Activity: Opening a database for activity {0} - {1}.", baseBlockNum * maxBlocksPerDatabase, (baseBlockNum * maxBlocksPerDatabase) + maxBlocksPerDatabase - 1);
                    db = new RocksDBInternal(db_path, commonBlockCache);
                    openDatabases.Add(baseBlockNum, db);
                    db.openDatabase();

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
                    RocksDBInternal temp_db = new RocksDBInternal(db, commonBlockCache);
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

                    if (db.Value.isOpen
                        && (DateTime.Now - db.Value.lastUsedTime).TotalSeconds >= closeAfterSeconds)
                    {
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
            var oldestDb = openDatabases.OrderBy(x => x.Value.lastUsedTime).Where(x => x.Value.isOpen && x.Value.maxBlockNumber < highestBlockNum).FirstOrDefault();
            if (oldestDb.Value != null)
            {
                oldestDb.Value.closeDatabase();
                openDatabases.Remove(oldestDb.Key);
                reopenCleanupList.Enqueue(oldestDb.Value);
            }
        }

        public void deleteData()
        {
            Directory.Delete(pathBase, true);
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
                var db = getDatabase(oldest_db, true);
                lowestBlockNum = db.minBlockNumber;
                return lowestBlockNum;
            }
        }

        public List<ActivityObject> getActivitiesBySeedHashAndType(byte[] seedHash, ActivityType? type, byte[] fromActivityId = null, int count = 0, bool descending = false)
        {
            lock (openDatabases)
            {
                var db = getDatabase(0, true);

                if (db == null)
                {
                    throw new Exception(string.Format("Cannot access activity database."));
                }

                return db.getActivitiesBySeedHashAndType(seedHash.AsSpan(0, 16).ToArray(), type, fromActivityId, count, descending);
            }
        }

        public bool insertActivity(ActivityObject activity)
        {
            lock (openDatabases)
            {
                var db = getDatabase(0);
                if (db.insertActivity(activity))
                {
                    if (activity.blockHeight > getHighestBlockInStorage())
                    {
                        highestBlockNum = activity.blockHeight;
                    }
                    return true;
                }
                return false;
            }
        }

        public bool updateStatus(byte[] id, ActivityStatus status, ulong blockHeight, long timestamp = 0)
        {
            lock (openDatabases)
            {
                var db = getDatabase(0);
                if (db.updateStatus(id, status, blockHeight, timestamp))
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
                return db.updateValue(id, value);
            }
        }
    }
}

#endif

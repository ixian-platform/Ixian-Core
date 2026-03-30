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

using RocksDbSharp;

namespace IXICore.Storage
{
    class StorageIndex
    {
        public ColumnFamilyHandle rocksIndexHandle;
        private RocksDb db;
        public StorageIndex(string cf_name, RocksDb db)
        {
            this.db = db;
            rocksIndexHandle = db.GetColumnFamily(cf_name);
        }

        public static byte[] combineKeys(ReadOnlySpan<byte> key1, ReadOnlySpan<byte> key2)
        {
            int size = key1.Length + key2.Length;

            var combined = GC.AllocateUninitializedArray<byte>(size);
            key1.CopyTo(combined.AsSpan());
            key2.CopyTo(combined.AsSpan(key1.Length));

            return combined;
        }

        public void addIndexEntry(ReadOnlySpan<byte> key, ReadOnlySpan<byte> index, ReadOnlySpan<byte> data, WriteBatch? writeBatch = null)
        {
            byte[] keyWithSuffix = combineKeys(key, index);
            if (writeBatch != null)
            {
                writeBatch.Put(keyWithSuffix, data, rocksIndexHandle);
            }
            else
            {
                db.Put(keyWithSuffix, data, rocksIndexHandle);
            }
        }

        public void delIndexEntry(ReadOnlySpan<byte> key, ReadOnlySpan<byte> index, WriteBatch? writeBatch = null)
        {
            byte[] keyWithSuffix = combineKeys(key, index);
            if (writeBatch != null)
            {
                writeBatch.Delete(keyWithSuffix, rocksIndexHandle);
            }
            else
            {
                db.Remove(keyWithSuffix, rocksIndexHandle);
            }
        }

        public byte[] getEntry(ReadOnlySpan<byte> key, ReadOnlySpan<byte> index)
        {
            var keyWithSuffix = combineKeys(key, index);
            return db.Get(keyWithSuffix, rocksIndexHandle);
        }

        public bool hasKey(ReadOnlySpan<byte> key, ReadOnlySpan<byte> index)
        {
            var keyWithSuffix = combineKeys(key, index);
            return db.HasKey(keyWithSuffix, rocksIndexHandle);
        }

        public IEnumerable<(ReadOnlyMemory<byte> index, ReadOnlyMemory<byte> value)> getEntriesForKey(ReadOnlyMemory<byte> key,
                                                                                                      ReadOnlyMemory<byte> index = default)
        {
            var combinedKeys = combineKeys(key.Span, index.Span);

            var ro = new ReadOptions().SetPrefixSameAsStart(true);
            var iter = db.NewIterator(rocksIndexHandle, ro);

            try
            {
                for (iter.Seek(combinedKeys); iter.Valid(); iter.Next())
                {
                    var k = iter.Key();
                    if (!k.AsSpan(0, combinedKeys.Length).SequenceEqual(combinedKeys))
                        yield break;

                    var v = iter.Value();
                    var indexSpan = k.AsMemory().Slice(key.Length);
                    var valueMem = v.AsMemory();

                    yield return (indexSpan, valueMem);
                }
            }
            finally
            {
                iter.Dispose();
            }
        }
    }
}

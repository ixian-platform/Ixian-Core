// Copyright (C) 2017-2025 Ixian OU
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
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;

namespace IXICore.Inventory
{
    // Immutable key wrapper for byte[] with cached hashcode for fast lookups.
    struct ByteArrayKey : IEquatable<ByteArrayKey>
    {
        private readonly byte[] bytes;
        private readonly int hash;

        public ByteArrayKey(byte[] bytes)
        {
            if (bytes == null)
                throw new ArgumentNullException(nameof(bytes));

            this.bytes = bytes;

            // FNV-1a 32-bit hash
            unchecked
            {
                uint h = 2166136261u; // offset basis
                for (int i = 0; i < bytes.Length; i++)
                    h = (h ^ bytes[i]) * 16777619u;
                hash = (int)h; // final cast to signed int for GetHashCode compatibility
            }
        }

        public byte[] Bytes => bytes;

        public bool Equals(ByteArrayKey other)
        {
            var a = bytes;
            var b = other.bytes;
            if (ReferenceEquals(a, b)) return true;
            if (a == null || b == null || a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++)
                if (a[i] != b[i]) return false;
            return true;
        }

        public override bool Equals(object obj) => obj is ByteArrayKey other && Equals(other);
        public override int GetHashCode() => hash;
    }

    class PendingInventoryItem
    {
        public InventoryItem item;
        public volatile bool processed;
        public long lastRequested;
        public int retryCount;
        private readonly ConcurrentDictionary<RemoteEndpoint, byte> endpoints = new ConcurrentDictionary<RemoteEndpoint, byte>();

        public PendingInventoryItem(InventoryItem item)
        {
            this.item = item;
            processed = false;
            retryCount = 0;
            lastRequested = 0;
        }

        public void AddEndpoint(RemoteEndpoint ep)
        {
            if (ep != null)
                endpoints.TryAdd(ep, 0);
        }

        public void RemoveEndpoint(RemoteEndpoint ep)
        {
            if (ep != null)
                endpoints.TryRemove(ep, out _);
        }

        public RemoteEndpoint GetRandomConnectedEndpoint(Random rnd)
        {
            var keys = endpoints.Keys;
            if (keys.Count == 0) return null;
            int start = rnd.Next(0, Math.Max(1, keys.Count));
            int idx = 0;
            foreach (var ep in keys)
            {
                if (idx++ < start) continue;
                if (ep != null && ep.isConnected() && ep.helloReceived)
                    return ep;
            }
            foreach (var ep in keys)
            {
                if (ep != null && ep.isConnected() && ep.helloReceived)
                    return ep;
            }
            return null;
        }
    }

    class InventoryTypeOptions
    {
        public int maxRetries = 5;
        public int timeout = 200;
        public int maxItems = 2000;
    }

    abstract class InventoryCache
    {
        public static InventoryCache Instance { get; private set; }

        // Two sets per type
        protected readonly ConcurrentDictionary<InventoryItemTypes, ConcurrentDictionary<ByteArrayKey, PendingInventoryItem>> pendingInventory;
        protected readonly ConcurrentDictionary<InventoryItemTypes, ConcurrentDictionary<ByteArrayKey, bool>> processedInventory;

        // Queues for eviction
        protected readonly ConcurrentDictionary<InventoryItemTypes, ConcurrentQueue<ByteArrayKey>> pendingQueues;
        protected readonly ConcurrentDictionary<InventoryItemTypes, ConcurrentQueue<ByteArrayKey>> processedQueues;

        protected readonly Dictionary<InventoryItemTypes, InventoryTypeOptions> typeOptions;
        private static readonly ThreadLocal<Random> threadRandom = new ThreadLocal<Random>(() =>
            new Random(unchecked(Environment.TickCount * 31 + Thread.CurrentThread.ManagedThreadId)));

        protected InventoryCache()
        {
            pendingInventory = new ConcurrentDictionary<InventoryItemTypes, ConcurrentDictionary<ByteArrayKey, PendingInventoryItem>>();
            processedInventory = new ConcurrentDictionary<InventoryItemTypes, ConcurrentDictionary<ByteArrayKey, bool>>();
            pendingQueues = new ConcurrentDictionary<InventoryItemTypes, ConcurrentQueue<ByteArrayKey>>();
            processedQueues = new ConcurrentDictionary<InventoryItemTypes, ConcurrentQueue<ByteArrayKey>>();

            foreach (InventoryItemTypes t in Enum.GetValues(typeof(InventoryItemTypes)))
            {
                pendingInventory[t] = new ConcurrentDictionary<ByteArrayKey, PendingInventoryItem>();
                processedInventory[t] = new ConcurrentDictionary<ByteArrayKey, bool>();
                pendingQueues[t] = new ConcurrentQueue<ByteArrayKey>();
                processedQueues[t] = new ConcurrentQueue<ByteArrayKey>();
            }

            typeOptions = new Dictionary<InventoryItemTypes, InventoryTypeOptions>
            {
                { InventoryItemTypes.block, new InventoryTypeOptions() { maxRetries = 10, timeout = 15, maxItems = 10 } },
                { InventoryItemTypes.blockSignature, new InventoryTypeOptions() { maxRetries = 15, timeout = 10, maxItems = 2000 } },
                { InventoryItemTypes.keepAlive, new InventoryTypeOptions() { maxRetries = 2, timeout = 30, maxItems = 10000 } },
                { InventoryItemTypes.transaction, new InventoryTypeOptions() { maxRetries = 5, timeout = 200, maxItems = 10000 } }
            };
        }

        public static void init(InventoryCache instance) => Instance = instance;

        private PendingInventoryItem get(InventoryItemTypes type, byte[] hash)
        {
            if (hash == null) return null;
            var key = new ByteArrayKey(hash);
            pendingInventory[type].TryGetValue(key, out var pii);
            return pii;
        }

        public PendingInventoryItem add(InventoryItem item, RemoteEndpoint endpoint, bool forceAddToPending)
        {
            if (item?.hash == null)
            {
                Logging.error("Error adding inventory item, hash is null.");
                return null;
            }
            var type = item.type;
            var key = new ByteArrayKey(item.hash);

            // skip if disabled
            if (!typeOptions.ContainsKey(type)
                || typeOptions[type].maxItems == 0)
            {
                Logging.error("Error adding inventory item, type disabled.");
                return null;
            }

            // skip if recently processed
            if (processedInventory[type].ContainsKey(key))
            {
                if (forceAddToPending)
                {
                    processedInventory[type].TryRemove(key, out _);
                }
                else
                {
                    return new PendingInventoryItem(item) { processed = true };
                }
            }

            var dict = pendingInventory[type];
            var queue = pendingQueues[type];

            var pii = dict.GetOrAdd(key, _ =>
            {
                var newPii = new PendingInventoryItem(item);
                if (endpoint != null) newPii.AddEndpoint(endpoint);
                queue.Enqueue(key);
                truncateQueueIfNeeded(type, pendingInventory, pendingQueues);
                return newPii;
            });

            if (!ReferenceEquals(pii.item, item))
                pii.item = item;
            if (endpoint != null)
                pii.AddEndpoint(endpoint);

            return pii;
        }

        public bool processInventoryItem(InventoryItemTypes type, byte[] hash)
        {
            return processInventoryItem(get(type, hash));
        }

        public bool processInventoryItem(PendingInventoryItem pii)
        {
            if (pii == null)
            {
                Logging.error("Cannot process pendingInventoryItem, PendingInventoryItem is null.");
                return false;
            }

            try
            {
                var rnd = threadRandom.Value;
                var endpoint = pii.GetRandomConnectedEndpoint(rnd);

                if (sendInventoryRequest(pii.item, endpoint))
                {
                    pii.lastRequested = Clock.getTimestamp();
                    if (Interlocked.Increment(ref pii.retryCount) > typeOptions[pii.item.type].maxRetries)
                        setProcessedFlag(pii.item.type, pii.item.hash);
                    return true;
                }
                else
                {
                    // All good, we already have this item.
                    setProcessedFlag(pii.item.type, pii.item.hash);
                }
            }
            catch (Exception e)
            {
                Logging.error("Exception in processInventoryItem: {0}", e);
                setProcessedFlag(pii.item.type, pii.item.hash);
            }
            return false;
        }

        public void processCache()
        {
            long now = Clock.getTimestamp();
            foreach (var type in pendingInventory.Keys)
            {
                if (!typeOptions.TryGetValue(type, out var opts))
                    opts = new InventoryTypeOptions();
                long expiration_time = now - opts.timeout;

                foreach (var kv in pendingInventory[type])
                {
                    var pii = kv.Value;
                    if (pii.lastRequested > expiration_time) continue;
                    processInventoryItem(pii);
                }
            }
        }

        public virtual void setProcessedFlag(InventoryItemTypes type, byte[] hash)
        {
            if (hash == null) return;
            var key = new ByteArrayKey(hash);

            // move from pending to processed
            pendingInventory[type].TryRemove(key, out _);
            processedInventory[type][key] = true;
            processedQueues[type].Enqueue(key);
            truncateQueueIfNeeded(type, processedInventory, processedQueues);
        }

        public long getItemCount()
        {
            long count = 0;
            foreach (var kv in pendingInventory) count += kv.Value.Count;
            foreach (var kv in processedInventory) count += kv.Value.Count;
            return count;
        }

        public long getProcessedItemCount()
        {
            long count = 0;
            foreach (var kv in processedInventory) count += kv.Value.Count;
            return count;
        }

        protected void truncateQueueIfNeeded<T>(
            InventoryItemTypes type,
            ConcurrentDictionary<InventoryItemTypes, ConcurrentDictionary<ByteArrayKey, T>> dictMap,
            ConcurrentDictionary<InventoryItemTypes, ConcurrentQueue<ByteArrayKey>> queueMap)
        {
            if (!typeOptions.TryGetValue(type, out var opts))
                opts = new InventoryTypeOptions();
            var dict = dictMap[type];
            var queue = queueMap[type];

            while (dict.Count > opts.maxItems && queue.TryDequeue(out var oldKey))
            {
                dict.TryRemove(oldKey, out _);
            }
        }

        public static InventoryItem decodeInventoryItem(byte[] bytes)
        {
            InventoryItemTypes type = (InventoryItemTypes)bytes.GetIxiVarInt(0).num;
            switch (type)
            {
                case InventoryItemTypes.block: return new InventoryItemBlock(bytes);
                case InventoryItemTypes.transaction: return new InventoryItem(bytes);
                case InventoryItemTypes.keepAlive: return new InventoryItemKeepAlive(bytes);
                case InventoryItemTypes.blockSignature: return new InventoryItemSignature(bytes);
                default: return null;
            }
        }

        abstract protected bool sendInventoryRequest(InventoryItem item, RemoteEndpoint endpoint);
    }
}

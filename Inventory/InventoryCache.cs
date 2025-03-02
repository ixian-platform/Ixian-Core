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
using System.Linq;

namespace IXICore.Inventory
{
    class PendingInventoryItem
    {
        public InventoryItem item;
        public bool processed;
        public long lastRequested;
        public int retryCount;
        public List<RemoteEndpoint> endpoints;

        public PendingInventoryItem(InventoryItem item)
        {
            this.item = item;
            processed = false;
            retryCount = 0;
            lastRequested = 0;
            endpoints = new List<RemoteEndpoint>();
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
        protected Dictionary<InventoryItemTypes, Dictionary<byte[], PendingInventoryItem>> inventory = null;
        protected Dictionary<InventoryItemTypes, InventoryTypeOptions> typeOptions = null;

        Random rnd = new Random();

        public InventoryCache()
        {
            inventory = new Dictionary<InventoryItemTypes, Dictionary<byte[], PendingInventoryItem>>();
            inventory.Add(InventoryItemTypes.block, new Dictionary<byte[], PendingInventoryItem>(new ByteArrayComparer()));
            inventory.Add(InventoryItemTypes.blockSignature, new Dictionary<byte[], PendingInventoryItem>(new ByteArrayComparer()));
            inventory.Add(InventoryItemTypes.keepAlive, new Dictionary<byte[], PendingInventoryItem>(new ByteArrayComparer()));
            inventory.Add(InventoryItemTypes.transaction, new Dictionary<byte[], PendingInventoryItem>(new ByteArrayComparer()));

            typeOptions = new Dictionary<InventoryItemTypes, InventoryTypeOptions>();
            typeOptions.Add(InventoryItemTypes.block, new InventoryTypeOptions() { maxRetries = 10, timeout = 15, maxItems = 100 });
            typeOptions.Add(InventoryItemTypes.blockSignature, new InventoryTypeOptions() { maxRetries = 15, timeout = 10, maxItems = 2000 });
            typeOptions.Add(InventoryItemTypes.keepAlive, new InventoryTypeOptions() { maxRetries = 2, timeout = 30, maxItems = 10000 });
            typeOptions.Add(InventoryItemTypes.transaction, new InventoryTypeOptions() { maxRetries = 5, timeout = 200, maxItems = 10000 });
        }

        public PendingInventoryItem get(InventoryItemTypes type, byte[] hash)
        {
            lock (inventory)
            {
                var inventory_types = inventory[type];
                if (!inventory_types.ContainsKey(hash))
                {
                    return null;
                }
                return inventory_types[hash];
            }
        }

        public PendingInventoryItem add(InventoryItem item, RemoteEndpoint endpoint)
        {
            lock (inventory)
            {
                var inventory_list = inventory[item.type];
                if(item.hash == null)
                {
                    Logging.error("Error adding inventory item, hash is null.");
                    return null;
                }

                if (!inventory_list.ContainsKey(item.hash))
                {
                    PendingInventoryItem pii = new PendingInventoryItem(item);
                    if(endpoint != null)
                    {
                        pii.endpoints.Add(endpoint);
                    }
                    inventory_list.Add(item.hash, pii);
                    truncateInventory(item.type);
                    return pii;
                }
                else
                {
                    PendingInventoryItem pii = inventory_list[item.hash];
                    pii.item = item;
                    if (endpoint != null)
                    {
                        if (!pii.endpoints.Contains(endpoint))
                        {
                            pii.endpoints.Add(endpoint);
                        }
                    }
                    return pii;
                }
            }
        }

        private bool remove(InventoryItemTypes type, byte[] hash)
        {
            lock (inventory)
            {
                return inventory[type].Remove(hash);
            }
        }

        public static InventoryItem decodeInventoryItem(byte[] bytes)
        {
            InventoryItemTypes type = (InventoryItemTypes)bytes.GetIxiVarInt(0).num;
            InventoryItem item = null;
            switch (type)
            {
                case InventoryItemTypes.block:
                    item = new InventoryItemBlock(bytes);
                    break;
                case InventoryItemTypes.transaction:
                    item = new InventoryItem(bytes);
                    break;
                case InventoryItemTypes.keepAlive:
                    item = new InventoryItemKeepAlive(bytes);
                    break;
                case InventoryItemTypes.blockSignature:
                    item = new InventoryItemSignature(bytes);
                    break;
            }
            return item;
        }

        public bool processInventoryItem(InventoryItemTypes type, byte[] hash)
        {
            var pii = get(type, hash);
            return processInventoryItem(pii);
        }

        public bool processInventoryItem(PendingInventoryItem pii)
        {
            if(pii == null)
            {
                Logging.error("Cannot process pendingInventoryItem, PendingInventoryItem is null.");
                return false;
            }
            if(pii.processed)
            {
                return false;
            }
            try
            {
                var endpoints = pii.endpoints.OrderBy(x => rnd.Next());
                RemoteEndpoint endpoint = null;
                if(endpoints.Count() > 0)
                {
                    foreach (var ep in endpoints)
                    {
                        if (ep.isConnected() && ep.helloReceived)
                        {
                            endpoint = ep;
                            break;
                        }
                        else
                        {
                            pii.endpoints.Remove(ep);
                        }
                    }
                }
                if (sendInventoryRequest(pii.item, endpoint))
                {
                    pii.lastRequested = Clock.getTimestamp();
                    if (pii.retryCount > typeOptions[pii.item.type].maxRetries)
                    {
                        pii.processed = true;
                    }
                    pii.retryCount++;
                    return true;
                }
                else
                {
                    pii.processed = true;
                }
                return false;
            }
            catch (Exception e)
            {
                Logging.error("Exception occurred in processInventoryItem: {0}", e);
                pii.processed = true;
            }

            return false;
        }

        public void processCache()
        {
            List<PendingInventoryItem> items_to_process = new List<PendingInventoryItem>();
            lock(inventory)
            {
                foreach(var types in inventory)
                {
                    long expiration_time = Clock.getTimestamp() - typeOptions[types.Key].timeout;
                    foreach (var item in types.Value)
                    {
                        if (item.Value.processed)
                        {
                            continue;
                        }
                        if (item.Value.lastRequested > expiration_time)
                        {
                            continue;
                        }
                        Logging.trace("Processing inventory cache " + types.Key + ": " + item.Value.lastRequested);
                        items_to_process.Add(item.Value);
                    }
                }
            }
            foreach(var item in items_to_process)
            {
                processInventoryItem(item);
            }
        }

        virtual public bool setProcessedFlag(InventoryItemTypes type, byte[] hash, bool processed)
        {
            lock(inventory)
            {
                if (!inventory[type].ContainsKey(hash))
                {
                    if(processed)
                    {
                        var inventory_list = inventory[type];
                        inventory_list.Add(hash, new PendingInventoryItem(new InventoryItem(type, hash)) { processed = processed });
                        truncateInventory(type);
                    }
                }
                else
                {
                    inventory[type][hash].processed = processed;
                    return true;
                }
            }
            return false;
        }

        abstract protected bool sendInventoryRequest(InventoryItem item, RemoteEndpoint endpoint);

        public long getItemCount()
        {
            lock(inventory)
            {
                long count = 0;
                foreach (var type in inventory)
                {
                    count += type.Value.Count();
                }
                return count;
            }
        }

        public long getProcessedItemCount()
        {
            lock (inventory)
            {
                long count = 0;
                foreach (var type in inventory)
                {
                    count += type.Value.Where(x => x.Value.processed == true).Count();
                }
                return count;
            }
        }

        protected void truncateInventory(InventoryItemTypes type)
        {
            var inventory_list = inventory[type];
            int max_items = 2000;
            InventoryTypeOptions options;
            if(typeOptions.TryGetValue(type, out options))
            {
                max_items = options.maxItems;
            }
            if (inventory_list.Count() > max_items)
            {
                inventory_list.Remove(inventory_list.Keys.First());
            }
        }
    }
}
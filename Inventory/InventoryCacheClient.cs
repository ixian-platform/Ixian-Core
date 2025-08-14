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
using IXICore.Network;
using IXICore.Utils;
using System;
using System.Linq;

namespace IXICore.Inventory
{
    class InventoryCacheClient : InventoryCache
    {
        TransactionInclusion tiv;
        public InventoryCacheClient(TransactionInclusion tiv) : base()
        {
            this.tiv = tiv;
            typeOptions[InventoryItemTypes.blockSignature].maxItems = 0;
        }

        override protected bool sendInventoryRequest(InventoryItem item, RemoteEndpoint endpoint)
        {
            switch (item.type)
            {
                case InventoryItemTypes.block:
                    return handleBlock(item, endpoint);
                case InventoryItemTypes.keepAlive:
                    return handleKeepAlive(item, endpoint);
                case InventoryItemTypes.transaction:
                    return CoreProtocolMessage.broadcastGetTransaction(item.hash, 0, endpoint);
                default:
                    Logging.error("Unknown inventory item type {0}", item.type);
                    break;
            }
            return false;
        }

        private bool handleBlock(InventoryItem item, RemoteEndpoint endpoint)
        {
            InventoryItemBlock iib = (InventoryItemBlock)item;
            ulong last_block_height = IxianHandler.getLastBlockHeight();
            if (iib.blockNum == last_block_height + 1)
            {
                tiv.requestNewBlockHeaders(iib.blockNum, endpoint);
                return true;
            }
            else if (iib.blockNum > last_block_height + 1)
            {
                // Future block
                return true;
            }
            return false;
        }

        private bool handleKeepAlive(InventoryItem item, RemoteEndpoint endpoint)
        {
            if (endpoint == null)
            {
                return false;
            }
            InventoryItemKeepAlive iika = (InventoryItemKeepAlive)item;
            byte[] address = iika.address.addressNoChecksum;
            Presence p = PresenceList.getPresenceByAddress(iika.address);
            if (p == null)
            {
                CoreProtocolMessage.broadcastGetPresence(address, endpoint);
                return true;
            }
            else
            {
                var pa = p.addresses.Find(x => x.device.SequenceEqual(iika.deviceId));
                if (pa == null || iika.lastSeen > pa.lastSeenTime)
                {
                    byte[] address_len_bytes = ((ulong)address.Length).GetIxiVarIntBytes();
                    byte[] device_len_bytes = ((ulong)iika.deviceId.Length).GetIxiVarIntBytes();
                    byte[] data = new byte[1 + address_len_bytes.Length + address.Length + device_len_bytes.Length + iika.deviceId.Length];
                    data[0] = 1;
                    Array.Copy(address_len_bytes, 0, data, 1, address_len_bytes.Length);
                    Array.Copy(address, 0, data, 1 + address_len_bytes.Length, address.Length);
                    Array.Copy(device_len_bytes, 0, data, 1 + address_len_bytes.Length + address.Length, device_len_bytes.Length);
                    Array.Copy(iika.deviceId, 0, data, 1 + address_len_bytes.Length + address.Length + device_len_bytes.Length, iika.deviceId.Length);
                    endpoint.sendData(ProtocolMessageCode.getKeepAlives, data, null);
                    return true;
                }
            }
            return false;
        }
    }
}

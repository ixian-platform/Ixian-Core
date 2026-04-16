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

using IXICore.Utils;
using System;
using System.IO;

namespace IXICore.Inventory
{
    [Obsolete("Use InventoryItemKeepAlive2 instead")]
    public class InventoryItemKeepAlive : InventoryItem
    {
        public long lastSeen;
        public Address address;
        public byte[] deviceId;

        public InventoryItemKeepAlive(byte[] hash, long lastSeen, Address address, byte[] deviceId)
        {
            type = InventoryItemTypes.keepAlive;
            this.hash = hash;
            this.lastSeen = lastSeen;
            this.address = address;
            this.deviceId = deviceId;
        }

        public InventoryItemKeepAlive(byte[] bytes)
        {
            using (MemoryStream m = new MemoryStream(bytes))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    type = (InventoryItemTypes)reader.ReadIxiVarInt();

                    int hash_len = (int)reader.ReadIxiVarUInt();
                    hash = reader.ReadBytes(hash_len);

                    lastSeen = reader.ReadIxiVarInt();

                    int address_len = (int)reader.ReadIxiVarUInt();
                    address = new Address(reader.ReadBytes(address_len));

                    int device_id_len = (int)reader.ReadIxiVarUInt();
                    deviceId = reader.ReadBytes(device_id_len);
                }
            }
        }

        override public byte[] getBytes()
        {
            using (MemoryStream m = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.WriteIxiVarInt((int)type);

                    writer.WriteIxiVarInt(hash.Length);
                    writer.Write(hash);

                    writer.WriteIxiVarInt(lastSeen);

                    writer.WriteIxiVarInt(address.addressNoChecksum.Length);
                    writer.Write(address.addressNoChecksum);

                    writer.WriteIxiVarInt(deviceId.Length);
                    writer.Write(deviceId);
                }
                return m.ToArray();
            }
        }
    }


    public class InventoryItemKeepAlive2 : InventoryItem
    {
        public long lastSeen;
        public Address address;
        public byte[] deviceId;

        public InventoryItemKeepAlive2(long lastSeen, Address address, byte[] deviceId)
        {
            type = InventoryItemTypes.keepAlive2;
            this.lastSeen = lastSeen;
            this.address = address;
            this.deviceId = deviceId;

            hash = getHash(lastSeen, address, deviceId);
        }

        public InventoryItemKeepAlive2(byte[] bytes)
        {
            using (MemoryStream m = new MemoryStream(bytes))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    type = (InventoryItemTypes)reader.ReadIxiVarInt();

                    lastSeen = reader.ReadIxiVarInt();

                    address = new Address(reader.ReadIxiBytes()!);
                    deviceId = reader.ReadIxiBytes()!;

                    hash = getHash(lastSeen, address, deviceId);
                }
            }
        }

        override public byte[] getBytes()
        {
            using (MemoryStream m = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.WriteIxiVarInt((int)type);

                    writer.WriteIxiVarInt(lastSeen);

                    writer.WriteIxiBytes(address.addressNoChecksum);

                    writer.WriteIxiBytes(deviceId);
                }
                return m.ToArray();
            }
        }

        static public byte[] getHash(long lastSeen, Address address, byte[] deviceId)
        {
            byte[] lastSeenBytes = lastSeen.GetBytesBE();
            byte[] iiHash = new byte[lastSeenBytes.Length + address.addressNoChecksum.Length + deviceId.Length];
            Buffer.BlockCopy(lastSeenBytes, 0, iiHash, 0, lastSeenBytes.Length);
            Buffer.BlockCopy(address.addressNoChecksum, 0, iiHash, lastSeenBytes.Length, address.addressNoChecksum.Length);
            Buffer.BlockCopy(deviceId, 0, iiHash, lastSeenBytes.Length + address.addressNoChecksum.Length, deviceId.Length);
            return iiHash;
        }
    }
}

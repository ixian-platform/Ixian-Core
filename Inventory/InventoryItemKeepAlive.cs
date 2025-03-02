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


using IXICore.Utils;
using System.IO;

namespace IXICore.Inventory
{
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
}

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

using IXICore.Utils;
using System;
using System.IO;

namespace IXICore.Inventory
{
    public enum InventoryItemTypes
    {
        transaction = 0,
        block = 1,
        [Obsolete("Use blockSignature2 instead")]
        blockSignature = 2,
        keepAlive = 3,
        blockSignature2 = 4
    }

    public class InventoryItem
    {
        public InventoryItemTypes type;
        public byte[] hash;

        public InventoryItem()
        {

        }

        public InventoryItem(InventoryItemTypes type, byte[] hash)
        {
            this.type = type;
            this.hash = hash;
        }

        public InventoryItem(byte[] bytes)
        {
            using (MemoryStream m = new MemoryStream(bytes))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    type = (InventoryItemTypes)reader.ReadIxiVarInt();

                    int hash_len = (int)reader.ReadIxiVarUInt();
                    hash = reader.ReadBytes(hash_len);
                }
            }
        }

        virtual public byte[] getBytes()
        {
            using (MemoryStream m = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.WriteIxiVarInt((int)type);

                    writer.WriteIxiVarInt(hash.Length);
                    writer.Write(hash);
                }
                return m.ToArray();
            }
        }
    }
}
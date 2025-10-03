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
    public class InventoryItemSignature : InventoryItem
    {
        public ulong blockNum;
        public byte[] blockHash;
        public byte[] solution;


        [Obsolete("Use InventoryItemSignature(byte[] solution...) instead")]
        public InventoryItemSignature(Address address, ulong blockNum, byte[] blockHash) : this(InventoryItemTypes.blockSignature, address.addressNoChecksum, blockNum, blockHash)
        {
        }

        public InventoryItemSignature(byte[] solution, ulong blockNum, byte[] blockHash) : this(InventoryItemTypes.blockSignature2, solution, blockNum, blockHash)
        {
        }


        private InventoryItemSignature(InventoryItemTypes type, byte[] solution, ulong blockNum, byte[] blockHash)
        {
            this.type = type;
            this.blockNum = blockNum;
            this.blockHash = blockHash;
            this.solution = solution;

            hash = getHash(solution, blockHash);
        }

        public InventoryItemSignature(byte[] bytes)
        {
            using (MemoryStream m = new MemoryStream(bytes))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    type = (InventoryItemTypes)reader.ReadIxiVarInt();

                    int solution_len = (int)reader.ReadIxiVarUInt();
                    solution = reader.ReadBytes(solution_len);

                    blockNum = reader.ReadIxiVarUInt();

                    int block_hash_len = (int)reader.ReadIxiVarUInt();
                    blockHash = reader.ReadBytes(block_hash_len);

                    hash = getHash(solution, blockHash);
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

                    writer.WriteIxiVarInt(solution.Length);
                    writer.Write(solution);

                    writer.WriteIxiVarInt(blockNum);

                    writer.WriteIxiVarInt(blockHash.Length);
                    writer.Write(blockHash);
                }
                return m.ToArray();
            }
        }

        static public byte[] getHash(byte[] solution, byte[] block_hash)
        {
            byte[] solution_block_hash = new byte[solution.Length + block_hash.Length];
            Array.Copy(solution, solution_block_hash, solution.Length);
            Array.Copy(block_hash, 0, solution_block_hash, solution.Length, block_hash.Length);
            return CryptoManager.lib.sha3_512sqTrunc(solution_block_hash);
        }
    }
}

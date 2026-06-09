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

namespace IXICore.Streaming.Models
{
    public class RequestFileDataMessage
    {
        public string Uid { get; set; }
        public ulong PacketNumber { get; set; }

        public RequestFileDataMessage(string uid, ulong packetNumber)
        {
            Uid = uid;
            PacketNumber = packetNumber;
        }

        public RequestFileDataMessage(byte[] data)
        {
            using (MemoryStream m = new MemoryStream(data))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    Uid = reader.ReadString();
                    PacketNumber = reader.ReadUInt64();
                }
            }
        }

        public byte[] getBytes()
        {
            using (MemoryStream m = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    // Write UID
                    writer.Write(Uid);

                    // Write Packet Number
                    writer.Write(PacketNumber);

                    return m.ToArray();
                }
            }
        }
    }
}

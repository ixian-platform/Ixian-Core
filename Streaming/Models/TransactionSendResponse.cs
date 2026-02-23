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

using IXICore.Meta;
using IXICore.Utils;
using System.IO;

namespace IXICore.Streaming.Models
{
    class TransactionSendResponse
    {
        public byte[] RequestId { get; private set; }
        public byte[] Instructions { get; private set; }

        public TransactionSendResponse(byte[] requestId, byte[] instructions)
        {
            RequestId = requestId;
            Instructions = instructions;
        }

        public TransactionSendResponse(byte[] bytes)
        {
            using (MemoryStream m = new MemoryStream(bytes))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    RequestId = reader.ReadIxiBytes()!;
                    Instructions = reader.ReadIxiBytes()!;
                }
            }
        }

        public byte[] getBytes()
        {
            using (MemoryStream m = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.WriteIxiBytes(RequestId);
                    writer.WriteIxiBytes(Instructions);
                }
                return m.ToArray();
            }
        }
    }
}

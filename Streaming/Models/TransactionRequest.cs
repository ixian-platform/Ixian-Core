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
    class TransactionRequest
    {
        public byte[]? RequestId { get; private set; }
        public IxiNumber Amount { get; private set; }
        public byte[]? Message { get; private set; }
        public byte[] Instructions { get; private set; }
        public byte[]? PubKey { get; private set; }

        public TransactionRequest(byte[]? requestId, IxiNumber amount, byte[]? message, byte[] instructions, byte[]? pubKey)
        {
            RequestId = requestId;
            Amount = amount;
            Message = message;
            Instructions = instructions;
            PubKey = pubKey;
        }

        public TransactionRequest(byte[] bytes)
        {
            using (MemoryStream m = new MemoryStream(bytes))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    RequestId = reader.ReadIxiBytes();
                    Amount = reader.ReadIxiNumber();
                    Message = reader.ReadIxiBytes();
                    Instructions = reader.ReadIxiBytes()!;
                    PubKey = reader.ReadIxiBytes();
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
                    writer.WriteIxiNumber(Amount);
                    writer.WriteIxiBytes(Message);
                    writer.WriteIxiBytes(Instructions);
                    writer.WriteIxiBytes(PubKey);
                }
                return m.ToArray();
            }
        }
    }
}

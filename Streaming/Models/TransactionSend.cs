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
    class TransactionSend
    {
        public Transaction Transaction { get; private set; }
        public byte[]? RequestId { get; private set; }
        public byte[]? PubKey { get; private set; }

        public TransactionSend(Transaction tx, byte[]? requestId, byte[]? pubKey)
        {
            Transaction = tx;
            RequestId = requestId;
            PubKey = pubKey;
        }

        public TransactionSend(byte[] bytes)
        {
            using (MemoryStream m = new MemoryStream(bytes))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    Transaction = new Transaction(reader.ReadIxiBytes()!, true, true);
                    RequestId = reader.ReadIxiBytes();
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
                    writer.WriteIxiBytes(Transaction.getBytes(true, true));
                    writer.WriteIxiBytes(RequestId);
                    writer.WriteIxiBytes(PubKey);
                }
                return m.ToArray();
            }
        }
    }
}

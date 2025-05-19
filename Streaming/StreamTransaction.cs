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


using System.IO;

namespace IXICore
{
    class StreamTransaction
    {
        public byte[] messageID;
        public Transaction transaction;

        public StreamTransaction(byte[] message_id, Transaction tx)
        {
            messageID = message_id;
            transaction = tx;
        }

        public StreamTransaction(byte[] bytes)
        {
            using (MemoryStream m = new MemoryStream(bytes))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    int msg_id_len = reader.ReadInt32();
                    messageID = reader.ReadBytes(msg_id_len);

                    int tx_len = reader.ReadInt32();
                    transaction = new Transaction(reader.ReadBytes(tx_len), false, true);
                }
            }
        }

        public byte[] getBytes()
        {
            using (MemoryStream m = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.Write(messageID.Length);
                    writer.Write(messageID);

                    byte[] tx_bytes = transaction.getBytes(true, true);
                    writer.Write(tx_bytes.Length);
                    writer.Write(tx_bytes);
                }
                return m.ToArray();
            }
        }

    }
}

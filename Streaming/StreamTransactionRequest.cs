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
    class StreamTransactionRequest
    {
        public byte[] messageID;
        public IxiNumber cost;

        public StreamTransactionRequest(byte[] message_id, IxiNumber cost)
        {
            messageID = message_id;
            this.cost = cost;
        }

        public StreamTransactionRequest(byte[] bytes)
        {
            using (MemoryStream m = new MemoryStream(bytes))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    int msg_id_len = reader.ReadInt32();
                    messageID = reader.ReadBytes(msg_id_len);

                    cost = new IxiNumber(reader.ReadString());
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

                    writer.Write(cost.ToString());
                }
                return m.ToArray();
            }
        }

    }
}

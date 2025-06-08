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

namespace IXICore.Streaming
{
    public class ReactionData
    {
        public Address sender = null;
        public string data = null;

        public ReactionData(Address sender, string data)
        {
            this.sender = sender;
            this.data = data;
        }

        public ReactionData(byte[] contact_bytes)
        {
            using (MemoryStream m = new MemoryStream(contact_bytes))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    int sender_len = reader.ReadInt32();
                    sender = new Address(reader.ReadBytes(sender_len));
                    data = reader.ReadString();
                    if(data == "")
                    {
                        data = null;
                    }
                }
            }
        }

        public byte[] getBytes()
        {
            using (MemoryStream m = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.Write(sender.addressWithChecksum.Length);
                    writer.Write(sender.addressWithChecksum);
                    if (data != null)
                    {
                        writer.Write(data);
                    }else
                    {
                        writer.Write("");
                    }
                }
                return m.ToArray();
            }
        }
    }
}

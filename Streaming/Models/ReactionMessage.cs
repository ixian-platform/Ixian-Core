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
    public class ReactionMessage
    {
        public byte[] msgId = null;
        public string reaction = null;

        public ReactionMessage(byte[] msg_id, string reaction)
        {
            msgId = msg_id;
            this.reaction = reaction;
        }

        public ReactionMessage(byte[] reaction_bytes)
        {
            using (MemoryStream m = new MemoryStream(reaction_bytes))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    int msg_id_len = reader.ReadInt32();
                    msgId = reader.ReadBytes(msg_id_len);
                    reaction = reader.ReadString();
                }
            }
        }

        public byte[] getBytes()
        {
            using (MemoryStream m = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.Write(msgId.Length);
                    writer.Write(msgId);
                    writer.Write(reaction);
                }
                return m.ToArray();
            }
        }
    }
}

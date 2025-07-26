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
using System.IO;

namespace IXICore.Streaming.Models
{
    public class KeysMessage
    {
        public byte[] aesKey { get; set; }
        public byte[] chachaKey { get; set; }
        public KeysMessage(byte[] aesKey, byte[] chachaKey)
        {
            this.aesKey = aesKey;
            this.chachaKey = chachaKey;
        }

        public KeysMessage(byte[] data)
        {
            int offset = 0;
            var bwo = data.ReadIxiBytes(offset);
            offset += bwo.bytesRead;
            aesKey = bwo.bytes;

            bwo = data.ReadIxiBytes(offset);
            offset += bwo.bytesRead;
            chachaKey = bwo.bytes;
        }

        public byte[] getBytes()
        {
            using (MemoryStream m = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    if (aesKey != null)
                    {
                        writer.Write(aesKey.Length);
                        writer.Write(aesKey);
                    }
                    else
                    {
                        writer.Write(0);
                    }

                    if (chachaKey != null)
                    {
                        writer.Write(chachaKey.Length);
                        writer.Write(chachaKey);
                    }
                    else
                    {
                        writer.Write(0);
                    }
                }
                return m.ToArray();
            }
        }
    }
}

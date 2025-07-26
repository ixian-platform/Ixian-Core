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
using System.Collections.Generic;

namespace IXICore.Streaming.Models
{
    public class AppProtocolsMessage
    {
        public List<byte[]> protocolIds { get; set; } = new();
        public AppProtocolsMessage(List<byte[]> protocolIds)
        {
            this.protocolIds = protocolIds;
        }

        public AppProtocolsMessage(byte[] data)
        {
            int offset = 0;
            var count = data.GetIxiVarUInt(offset);
            offset += count.bytesRead;

            for (int i = 0; i < (int)count.num; i++)
            {
                var bwo = data.ReadIxiBytes(offset);
                offset += bwo.bytesRead;
                protocolIds.Add(bwo.bytes);
            }
        }

        public byte[] getBytes()
        {
            List<byte> bytes = new List<byte>();

            bytes.AddRange(protocolIds.Count.GetIxiVarIntBytes());

            foreach (var protocolId in protocolIds)
            {
                bytes.AddRange(protocolId.GetIxiBytes());
            }

            return bytes.ToArray();
        }
    }
}

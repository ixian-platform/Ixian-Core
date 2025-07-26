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
using System;

namespace IXICore.Streaming.Models
{
    public class RequestAdd2Message
    {
        public int maxProtocolVersion { get; set; }
        public byte[] pubKey { get; set; }

        public RequestAdd2Message(int maxProtocolVersion, byte[] pubKey, byte[] ecdhPubKey, byte[] mlkemPubKey, byte[] aesSalt)
        {
            this.maxProtocolVersion = maxProtocolVersion;
            this.pubKey = pubKey;
        }

        public RequestAdd2Message(byte[] data)
        {
            int offset = 0;
            var version = data.GetIxiVarUInt(offset);
            offset += version.bytesRead;
            maxProtocolVersion = (int)version.num;

            var bwo = data.ReadIxiBytes(offset);
            offset += bwo.bytesRead;
            pubKey = bwo.bytes;
        }

        public byte[] getBytes()
        {
            byte[] pubKeyIxiBytes = pubKey.GetIxiBytes();
            byte[] acceptAddMsg = new byte[1 + pubKeyIxiBytes.Length];
            acceptAddMsg[0] = (byte)maxProtocolVersion;
            Buffer.BlockCopy(pubKeyIxiBytes, 0, acceptAddMsg, 1, pubKeyIxiBytes.Length);

            return acceptAddMsg;
        }
    }
}

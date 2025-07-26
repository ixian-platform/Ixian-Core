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
    public class AcceptAdd2Message
    {
        public int version { get; set; }
        public byte[] rsaPubKey { get; set; }
        public byte[] ecdhPubKey { get; set; }
        public byte[] mlkemPubKey { get; set; }
        public byte[] aesSalt { get; set; }
        public StreamCapabilities capabilities { get; set; }

        public AcceptAdd2Message(int version, byte[] rsaPubKey, byte[] ecdhPubKey, byte[] mlkemPubKey, byte[] aesSalt, StreamCapabilities capabilities)
        {
            this.version = version;
            this.rsaPubKey = rsaPubKey;
            this.ecdhPubKey = ecdhPubKey;
            this.mlkemPubKey = mlkemPubKey;
            this.aesSalt = aesSalt;
            this.capabilities = capabilities;
        }

        public AcceptAdd2Message(byte[] data)
        {
            int offset = 0;
            var version = data.GetIxiVarUInt(offset);
            offset += version.bytesRead;
            this.version = (int)version.num;

            var bwo = data.ReadIxiBytes(offset);
            offset += bwo.bytesRead;
            rsaPubKey = bwo.bytes;

            bwo = data.ReadIxiBytes(offset);
            offset += bwo.bytesRead;
            ecdhPubKey = bwo.bytes;

            bwo = data.ReadIxiBytes(offset);
            offset += bwo.bytesRead;
            mlkemPubKey = bwo.bytes;

            bwo = data.ReadIxiBytes(offset);
            offset += bwo.bytesRead;
            aesSalt = bwo.bytes;

            if (data.Length > offset)
            {
                var ivio = data.GetIxiVarUInt(offset);
                offset += ivio.bytesRead;
                capabilities = (StreamCapabilities)ivio.num;
            } else
            {
                capabilities = StreamCapabilities.Incoming | StreamCapabilities.Outgoing | StreamCapabilities.IPN | StreamCapabilities.Apps;
            }
        }

        public byte[] getBytes()
        {
            byte[] pubKeyIxiBytes = rsaPubKey.GetIxiBytes();
            byte[] ecdhPubkeyIxiBytes = ecdhPubKey.GetIxiBytes();
            byte[] mlkemPubkeyIxiBytes = mlkemPubKey.GetIxiBytes();
            byte[] aesSaltIxiBytes = aesSalt.GetIxiBytes();
            byte[] capabilitiesBytes = ((int)capabilities).GetIxiVarIntBytes();
            byte[] acceptAddMsg = new byte[1 + pubKeyIxiBytes.Length + ecdhPubkeyIxiBytes.Length + mlkemPubkeyIxiBytes.Length + aesSaltIxiBytes.Length + capabilitiesBytes.Length];
            acceptAddMsg[0] = (byte)version;
            Buffer.BlockCopy(pubKeyIxiBytes, 0, acceptAddMsg, 1, pubKeyIxiBytes.Length);
            Buffer.BlockCopy(ecdhPubkeyIxiBytes, 0, acceptAddMsg, 1 + pubKeyIxiBytes.Length, ecdhPubkeyIxiBytes.Length);
            Buffer.BlockCopy(mlkemPubkeyIxiBytes, 0, acceptAddMsg, 1 + pubKeyIxiBytes.Length + ecdhPubkeyIxiBytes.Length, mlkemPubkeyIxiBytes.Length);
            Buffer.BlockCopy(aesSaltIxiBytes, 0, acceptAddMsg, 1 + pubKeyIxiBytes.Length + ecdhPubkeyIxiBytes.Length + mlkemPubkeyIxiBytes.Length, aesSaltIxiBytes.Length);
            Buffer.BlockCopy(capabilitiesBytes, 0, acceptAddMsg, 1 + pubKeyIxiBytes.Length + ecdhPubkeyIxiBytes.Length + mlkemPubkeyIxiBytes.Length + aesSaltIxiBytes.Length, capabilitiesBytes.Length);

            return acceptAddMsg;
        }
    }
}

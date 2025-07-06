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

namespace IXICore.Streaming.Models
{
    public class AcceptAdd2
    {
        public int version { get; set; }
        public byte[] rsaPubKey { get; set; }
        public byte[] ecdhPubKey { get; set; }
        public byte[] mlkemPubKey { get; set; }
        public byte[] aesSalt { get; set; }
        public AcceptAdd2(int version, byte[] rsaPubKey, byte[] ecdhPubKey, byte[] mlkemPubKey, byte[] aesSalt)
        {
            this.version = version;
            this.rsaPubKey = rsaPubKey;
            this.ecdhPubKey = ecdhPubKey;
            this.mlkemPubKey = mlkemPubKey;
            this.aesSalt = aesSalt;
        }

        public AcceptAdd2(byte[] data)
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
        }

        public byte[] getBytes()
        {
            byte[] pubKeyIxiBytes = rsaPubKey.GetIxiBytes();
            byte[] ecdhPubkeyIxiBytes = ecdhPubKey.GetIxiBytes();
            byte[] mlkemPubkeyIxiBytes = mlkemPubKey.GetIxiBytes();
            byte[] aesSaltIxiBytes = aesSalt.GetIxiBytes();
            byte[] acceptAddMsg = new byte[1 + pubKeyIxiBytes.Length + ecdhPubkeyIxiBytes.Length + mlkemPubkeyIxiBytes.Length + aesSaltIxiBytes.Length];
            acceptAddMsg[0] = (byte)version;
            Buffer.BlockCopy(pubKeyIxiBytes, 0, acceptAddMsg, 1, pubKeyIxiBytes.Length);
            Buffer.BlockCopy(ecdhPubkeyIxiBytes, 0, acceptAddMsg, 1 + pubKeyIxiBytes.Length, ecdhPubkeyIxiBytes.Length);
            Buffer.BlockCopy(mlkemPubkeyIxiBytes, 0, acceptAddMsg, 1 + pubKeyIxiBytes.Length + ecdhPubkeyIxiBytes.Length, mlkemPubkeyIxiBytes.Length);
            Buffer.BlockCopy(aesSaltIxiBytes, 0, acceptAddMsg, 1 + pubKeyIxiBytes.Length + ecdhPubkeyIxiBytes.Length + mlkemPubkeyIxiBytes.Length, aesSaltIxiBytes.Length);

            return acceptAddMsg;
        }
    }
}

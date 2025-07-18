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
    public class Keys2
    {
        public byte[] ecdhPubKey { get; set; }
        public byte[] mlkemCiphertext { get; set; }
        public byte[] chaChaSalt { get; set; }
        public Keys2(byte[] ecdhPubKey, byte[] mlkemCiphertext, byte[] chaChaSalt)
        {
            this.ecdhPubKey = ecdhPubKey;
            this.mlkemCiphertext = mlkemCiphertext;
            this.chaChaSalt = chaChaSalt;
        }

        public Keys2(byte[] data)
        {
            int offset = 0;
            var bwo = data.ReadIxiBytes(offset);
            offset += bwo.bytesRead;
            ecdhPubKey = bwo.bytes;

            bwo = data.ReadIxiBytes(offset);
            offset += bwo.bytesRead;
            mlkemCiphertext = bwo.bytes;

            bwo = data.ReadIxiBytes(offset);
            offset += bwo.bytesRead;
            chaChaSalt = bwo.bytes;
        }

        public byte[] getBytes()
        {
            byte[] ecdhPubkeyIxiBytes = ecdhPubKey.GetIxiBytes();
            byte[] mlkemCiphertextIxiBytes = mlkemCiphertext.GetIxiBytes();
            byte[] chachaSaltIxiBytes = chaChaSalt.GetIxiBytes();
            byte[] keys2AddMsg = new byte[ecdhPubkeyIxiBytes.Length + mlkemCiphertextIxiBytes.Length + chachaSaltIxiBytes.Length];
            Buffer.BlockCopy(ecdhPubkeyIxiBytes, 0, keys2AddMsg, 0, ecdhPubkeyIxiBytes.Length);
            Buffer.BlockCopy(mlkemCiphertextIxiBytes, 0, keys2AddMsg, ecdhPubkeyIxiBytes.Length, mlkemCiphertextIxiBytes.Length);
            Buffer.BlockCopy(chachaSaltIxiBytes, 0, keys2AddMsg, ecdhPubkeyIxiBytes.Length + mlkemCiphertextIxiBytes.Length, chachaSaltIxiBytes.Length);

            return keys2AddMsg;
        }
    }
}

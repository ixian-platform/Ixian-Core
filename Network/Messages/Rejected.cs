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

namespace IXICore.Network.Messages
{
    public enum RejectedCode : byte
    {
        TransactionInvalid = 0x20,
        TransactionDust = 0x21,
        TransactionInsufficientFee = 0x22,
        TransactionDuplicate = 0x23
    }

    public class Rejected
    {
        public RejectedCode code { get; private set; }
        public byte[] data { get; private set; }

        public Rejected(byte[] bytes)
        {
            if (bytes.Length > 128)
            {
                throw new Exception("'Rejected' message larger than 128 bytes.");
            }

            code = (RejectedCode)bytes[0];
            data = IxiUtils.ReadIxiBytes(bytes, 1).bytes;
        }

        public Rejected(RejectedCode code, byte[] data)
        {
            this.code = code;
            this.data = data;
        }

        public byte[] getBytes()
        {
            var dataBytes = IxiUtils.GetIxiBytes(data);
            byte[] bytes = new byte[1 + dataBytes.Length];
            bytes[0] = (byte)code;
            Array.Copy(dataBytes, 0, bytes, 1, dataBytes.Length);
            return bytes;
        }
    }
}
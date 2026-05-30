// Copyright (C) 2017-2026 Ixian
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
using System.Text;

namespace IXICore.Streaming.Models
{
    public class ChatStreamMessage
    {
        public byte[] MessageId { get; set;  }
        public string Message { get; set; }
        public int Sequence { get; set; }
        public bool IsStream { get; set; }

        public ChatStreamMessage(byte[] messageId, string message, int sequence, bool isStream)
        {
            MessageId = messageId;
            Message = message;
            Sequence = sequence;
            IsStream = isStream;
        }

        public ChatStreamMessage(byte[] data)
        {
            int offset = 0;

            var messageIdBytes = data.ReadIxiBytes(offset);
            MessageId = messageIdBytes.bytes;
            offset += messageIdBytes.bytesRead;

            var messageBytes = data.ReadIxiBytes(offset);
            Message = Encoding.UTF8.GetString(messageBytes.bytes);
            offset += messageBytes.bytesRead;

            var sequenceBytes = data.GetIxiVarUInt(offset);
            Sequence = (int)sequenceBytes.num;
            offset += sequenceBytes.bytesRead;

            IsStream = data[offset] == 1;
            offset += 1;
        }

        public byte[] getBytes()
        {
            int totalSize = 0;

            var messageIdBytes = MessageId.GetIxiBytes();
            totalSize += messageIdBytes.Length;

            var messageBytes = Encoding.UTF8.GetBytes(Message).GetIxiBytes();
            totalSize += messageBytes.Length;

            var sequenceBytes = Sequence.GetIxiVarIntBytes();
            totalSize += sequenceBytes.Length;

            totalSize += 1; // IsStream

            byte[] result = new byte[totalSize];
            int offset = 0;

            messageIdBytes.CopyTo(result, offset);
            offset += messageIdBytes.Length;

            messageBytes.CopyTo(result, offset);
            offset += messageBytes.Length;

            sequenceBytes.CopyTo(result, offset);
            offset += sequenceBytes.Length;

            result[offset] = IsStream ? (byte)1 : (byte)0;
            offset += 1;

            return result;
        }
    }
}

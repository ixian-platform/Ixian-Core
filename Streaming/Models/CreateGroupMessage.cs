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

using IXICore.Network;
using IXICore.SpixiBot;
using IXICore.Utils;
using System;
using System.Collections.Generic;
using System.Text;

namespace IXICore.Streaming.Models
{
    public class CreateGroupMessage
    {
        public string groupName { get; set; }
        public byte[] randomId { get; set; }
        public OrderedDictionary<Address, string?> participants { get; set; }
        public OrderedDictionary<string, BotChannel> channels { get; set; }
        public bool hideParticipantAddresses { get; set; } = false;

        public CreateGroupMessage(byte[] randomId, string groupName, OrderedDictionary<Address, string?> participants, OrderedDictionary<string, BotChannel> channels, bool hideParticipantAddresses)
        {
            this.randomId = randomId;
            this.groupName = groupName;
            this.participants = participants;
            this.channels = channels;
            this.hideParticipantAddresses = hideParticipantAddresses;
        }

        public CreateGroupMessage(byte[] data)
        {
            participants = new(new AddressComparer());
            channels = new();

            int offset = 0;

            var randomIdBytes = data.ReadIxiBytes(offset);
            randomId = randomIdBytes.bytes;
            offset += randomIdBytes.bytesRead;

            var groupNameBytes = data.ReadIxiBytes(offset);
            groupName = Encoding.UTF8.GetString(groupNameBytes.bytes);
            offset += groupNameBytes.bytesRead;

            hideParticipantAddresses = data[offset] != 0;
            offset += 1;

            var count = data.GetIxiVarUInt(offset);
            if (count.num > 10)
            {
                throw new Exception("Error creating group message from bytes, participant count is higher than 10.");
            }
            offset += count.bytesRead;

            for (int i = 0; i < (int)count.num; i++)
            {
                var addressBytes = data.ReadIxiBytes(offset);
                offset += addressBytes.bytesRead;

                var nameBytes = data.ReadIxiBytes(offset);
                offset += nameBytes.bytesRead;

                string? name = null;
                if (nameBytes.bytes != null)
                {
                    name = Encoding.UTF8.GetString(nameBytes.bytes);
                }

                participants.Add(new Address(addressBytes.bytes), name);
            }

            count = data.GetIxiVarUInt(offset);
            if (count.num > 10)
            {
                throw new Exception("Error creating group message from bytes, channel count is higher than 10.");
            }
            offset += count.bytesRead;

            for (int i = 0; i < (int)count.num; i++)
            {
                var channelNameBytes = data.ReadIxiBytes(offset);
                offset += channelNameBytes.bytesRead;

                var bcBytes = data.ReadIxiBytes(offset);
                offset += bcBytes.bytesRead;

                channels.Add(UTF8Encoding.UTF8.GetString(channelNameBytes.bytes), new BotChannel(bcBytes.bytes));
            }
        }

        public byte[] getBytes()
        {
            int totalSize = 0;

            var randomIdBytes = randomId.GetIxiBytes();
            totalSize += randomIdBytes.Length;

            var nameBytes = Encoding.UTF8.GetBytes(groupName).GetIxiBytes();
            totalSize += nameBytes.Length;

            totalSize += 1; // hideParticipantAddresses

            totalSize += participants.Count.GetIxiVarIntBytes().Length;

            var participantsParts = new List<byte[]>();
            foreach (var p in participants)
            {
                byte[] bytes;
                if (hideParticipantAddresses)
                {
                    bytes = GroupChat.DeriveGroupAddress(p.Key, randomId).addressNoChecksum.GetIxiBytes();
                }
                else
                {
                    bytes = p.Key.getInputBytes().GetIxiBytes();
                }
                participantsParts.Add(bytes);
                totalSize += bytes.Length;

                if (p.Value == null)
                {
                    bytes = new byte[0].GetIxiBytes();
                }
                else
                {
                    bytes = Encoding.UTF8.GetBytes(p.Value).GetIxiBytes();
                }
                participantsParts.Add(bytes);
                totalSize += bytes.Length;
            }

            totalSize += channels.Count.GetIxiVarIntBytes().Length;

            var channelsParts = new List<byte[]>();
            foreach (var c in channels)
            {
                var bytes = UTF8Encoding.UTF8.GetBytes(c.Key).GetIxiBytes();
                channelsParts.Add(bytes);
                totalSize += bytes.Length;

                bytes = c.Value.getBytes();
                channelsParts.Add(bytes);
                totalSize += bytes.Length;
            }

            byte[] result = new byte[totalSize];
            int offset = 0;

            randomIdBytes.CopyTo(result, offset);
            offset += randomIdBytes.Length;

            nameBytes.CopyTo(result, offset);
            offset += nameBytes.Length;

            result[offset] = hideParticipantAddresses ? (byte)1 : (byte)0;
            offset += 1;

            participants.Count.GetIxiVarIntBytes().CopyTo(result, offset);
            offset += 1;

            foreach (var bytes in participantsParts)
            {
                bytes.CopyTo(result, offset);
                offset += bytes.Length;
            }

            channels.Count.GetIxiVarIntBytes().CopyTo(result, offset);
            offset += 1;

            foreach (var bytes in channelsParts)
            {
                bytes.CopyTo(result, offset);
                offset += bytes.Length;
            }

            return result;
        }
    }
}

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

using System;
using System.Collections.Generic;
using System.IO;
using IXICore.Utils;
using Newtonsoft.Json;

namespace IXICore.Activity
{
    /// <summary>
    /// Type of the stored activity item.
    /// </summary>
    public enum ActivityType : short
    {
        None = 0,
        /// <summary>
        /// Transaction was received.
        /// </summary>
        TransactionReceived = 100,
        /// <summary>
        /// Transaction was generated and sent.
        /// </summary>
        TransactionSent = 101,
        /// <summary>
        /// A mining reward transaction was generated and sent.
        /// </summary>
        MiningReward = 200,
        /// <summary>
        /// A staking reward transaction was received.
        /// </summary>
        StakingReward = 201,
        /// <summary>
        /// Contact request was received.
        /// </summary>
        ContactRequest = 300,
        /// <summary>
        /// IXI Name Management transaction.
        /// </summary>
        IxiName = 400
    }

    /// <summary>
    /// State of the activity.
    /// </summary>
    public enum ActivityStatus : byte
    {
        Pending = 1,
        Final = 2,
        Error = 3
    }

    public class AddressConverter : JsonConverter<Address>
    {
        public override void WriteJson(JsonWriter writer, Address value, JsonSerializer serializer)
        {
            if (value == null)
            {
                writer.WriteNull();
                return;
            }

            writer.WriteValue(value.ToString());
        }

        public override Address ReadJson(JsonReader reader, Type objectType, Address existingValue, bool hasExistingValue, JsonSerializer serializer)
        {
            if (reader.TokenType == JsonToken.Null)
                return null;

            var addrStr = serializer.Deserialize<string>(reader);
            if (string.IsNullOrWhiteSpace(addrStr))
                return null;

            return new Address(addrStr);
        }
    }


    public class TXIDConverter : JsonConverter<byte[]>
    {
        public override void WriteJson(JsonWriter writer, byte[] value, JsonSerializer serializer)
        {
            if (value == null)
            {
                writer.WriteNull();
                return;
            }

            writer.WriteValue(Transaction.getTxIdString(value));
        }

        public override byte[] ReadJson(JsonReader reader, Type objectType, byte[] existingValue, bool hasExistingValue, JsonSerializer serializer)
        {
            if (reader.TokenType == JsonToken.Null)
                return null;

            var addrStr = serializer.Deserialize<string>(reader);
            if (string.IsNullOrWhiteSpace(addrStr))
                return null;

            return Transaction.txIdLegacyToV8(addrStr);
        }
    }

    public class AddressIxiNumberDictConverter : JsonConverter<IDictionary<Address, IxiNumber>>
    {
        public override void WriteJson(JsonWriter writer, IDictionary<Address, IxiNumber> value, JsonSerializer serializer)
        {
            writer.WriteStartObject();
            if (value != null)
            {
                foreach (var kv in value)
                {
                    writer.WritePropertyName(kv.Key.ToString());
                    writer.WriteValue(kv.Value?.ToString());
                }
            }
            writer.WriteEndObject();
        }

        public override IDictionary<Address, IxiNumber> ReadJson(JsonReader reader, Type objectType, IDictionary<Address, IxiNumber> existingValue, bool hasExistingValue, JsonSerializer serializer)
        {
            var dict = new Dictionary<Address, IxiNumber>();
            if (reader.TokenType == JsonToken.Null)
                return dict;

            var obj = serializer.Deserialize<Dictionary<string, string>>(reader);
            if (obj != null)
            {
                foreach (var kv in obj)
                {
                    dict[new Address(kv.Key)] = new IxiNumber(kv.Value);
                }
            }
            return dict;
        }
    }

    /// <summary>
    /// An activity item which describes a potentially interesting event on the DLT or S2 network.
    /// </summary>
    public class ActivityObject
    {
        [JsonConverter(typeof(TXIDConverter))]
        public byte[] id { get; set; }
        public byte[] seedHash { get; set; }

        [JsonConverter(typeof(AddressConverter))]
        public Address walletAddress { get; set; }

        [JsonConverter(typeof(AddressIxiNumberDictConverter))]
        public IDictionary<Address, IxiNumber> addressList { get; set; }
        public ActivityType type { get; set; }
        public byte[] data { get; set; }

        [JsonConverter(typeof(IxiNumberConverter))]
        public IxiNumber value { get; set; }
        public long timestamp { get; set; }
        public ActivityStatus status { get; set; }
        public ulong blockHeight { get; set; }

        public ActivityObject(byte[] seedHash,
                              Address walletAddress,
                              byte[] id,
                              IDictionary<Address, IxiNumber> addressList,
                              ActivityType type,
                              byte[] data,
                              IxiNumber value,
                              long timestamp,
                              ActivityStatus status,
                              ulong blockHeight)
        {
            this.id = id;
            this.seedHash = seedHash.AsSpan(0, 16).ToArray();
            this.walletAddress = walletAddress;
            this.addressList = addressList;
            this.type = type;
            this.data = data;
            this.value = value;
            this.timestamp = timestamp;
            this.status = status;
            this.blockHeight = blockHeight;
        }

        /// <summary>
        /// Reconstructs from serialized bytes
        /// </summary>
        public ActivityObject(byte[] bytes, byte[] seedHash, ActivityType type, byte[] id, byte[] metaBytes)
        {
            using (MemoryStream ms = new MemoryStream(bytes))
            using (BinaryReader br = new BinaryReader(ms))
            {
                this.seedHash = seedHash;
                this.type = type;
                this.id = id;

                int wlLen = (int)br.ReadIxiVarUInt();
                walletAddress = new Address(br.ReadBytes(wlLen));

                int addrCount = (int)br.ReadIxiVarUInt();
                addressList = new Dictionary<Address, IxiNumber>(addrCount);
                for (int i = 0; i < addrCount; i++)
                {
                    int aLen = (int)br.ReadIxiVarUInt();
                    byte[] aBytes = br.ReadBytes(aLen);
                    Address addr = new Address(aBytes);

                    int vLen = (int)br.ReadIxiVarUInt();
                    byte[] vBytes = br.ReadBytes(vLen);
                    IxiNumber val = new IxiNumber(vBytes);

                    addressList[addr] = val;
                }

                int dLen = (int)br.ReadIxiVarUInt();
                if (dLen > 0)
                {
                    data = br.ReadBytes(dLen);
                }

                int valLen = (int)br.ReadIxiVarUInt();
                value = new IxiNumber(br.ReadBytes(valLen));

                if (metaBytes != null)
                {
                    var metaData = ParseMetaBytes(metaBytes);
                    status = metaData.status;
                    blockHeight = metaData.blockHeight;
                    timestamp = metaData.timestamp;
                }
            }
        }

        public static (ActivityStatus status, ulong blockHeight, long timestamp) ParseMetaBytes(byte[] metaBytes)
        {
            using (MemoryStream ms = new MemoryStream(metaBytes))
            using (BinaryReader br = new BinaryReader(ms))
            {
                var status = (ActivityStatus)br.ReadByte();
                var blockHeight = br.ReadIxiVarUInt();
                var timestamp = (int)br.ReadIxiVarUInt();
                return (status, blockHeight, timestamp);
            }
        }

        /// <summary>
        /// Serialize the object to bytes, excluding seedHash, status, blockheight, timestamp, type and id.
        /// </summary>
        public byte[] GetBytes()
        {
            using (MemoryStream ms = new MemoryStream())
            using (BinaryWriter bw = new BinaryWriter(ms))
            {
                bw.Write(walletAddress.addressNoChecksum.GetIxiBytes());

                bw.Write(addressList.Count.GetIxiVarIntBytes());
                if (addressList != null)
                {
                    foreach (var kv in addressList)
                    {
                        byte[] addrBytes = kv.Key.addressNoChecksum;
                        bw.Write(addrBytes.GetIxiBytes());

                        byte[] valBytes = kv.Value.getBytes();
                        bw.Write(valBytes.GetIxiBytes());
                    }
                }

                bw.Write(data.GetIxiBytes());

                bw.Write(value.getBytes().GetIxiBytes());

                bw.Flush();
                return ms.ToArray();
            }
        }

        public byte[] GetMetaBytes()
        {
            return GetMetaBytes(status, blockHeight, timestamp);
        }

        public static byte[] GetMetaBytes(ActivityStatus status, ulong blockHeight, long timestamp)
        {
            using (MemoryStream ms = new MemoryStream())
            using (BinaryWriter bw = new BinaryWriter(ms))
            {
                bw.Write((byte)status);
                bw.Write(blockHeight.GetIxiVarIntBytes());
                bw.Write(timestamp.GetIxiVarIntBytes());

                bw.Flush();
                return ms.ToArray();
            }
        }
    }
}

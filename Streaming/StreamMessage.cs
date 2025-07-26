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

using IXICore.Meta;
using IXICore.Utils;
using Newtonsoft.Json;
using System;
using System.IO;

namespace IXICore
{
    class SpixiMessageInternal
    {
        public SpixiMessageCode type;
        public int channel;
        public object data;
    }
    public class StreamMessageDataConverter : JsonConverter<byte[]>
    {
        public override void WriteJson(JsonWriter writer, byte[] value, JsonSerializer serializer)
        {
            var sm = new SpixiMessage(value);

            var smi = new SpixiMessageInternal()
            {
                type = sm.type,
                channel = sm.channel
            };

            var data = SpixiMessageObjectMap.MapTypeToModel(sm.type, sm.data);
            if (data == null)
            {
                data = sm.data;
            }

            smi.data = data;

            serializer.Serialize(writer, smi);
        }

        public override byte[]? ReadJson(JsonReader reader, Type objectType, byte[]? existingValue, bool hasExistingValue, JsonSerializer serializer)
        {
            return JsonConvert.DeserializeObject<SpixiMessage>((string)reader.Value).getBytes();
        }
    }


    // The message codes available in S2.
    // Error and Info are free, while data requires a transaction
    public enum StreamMessageCode
    {
        error,      // Reserved for S2 nodes only
        info,       // Free, limited message type
        data        // Paid, transaction-based type
    }

    public enum StreamMessageSerializationType
    {
        network = 0,
        checksum = 1,
        storage = 2
    }

    public class StreamMessage
    {
        public int version { get; private set; } = 0;                 // Stream Message version

        public StreamMessageCode type;          // Stream Message type
        public Address realSender = null;        // Used by group chat bots, isn't transmitted to the network
        public Address sender = null;            // Sender wallet
        public Address recipient = null;         // Recipient wallet 

        private byte[] transaction = null;       // Unsigned transaction - obsolete, will be removed with v1

        [JsonConverter(typeof(StreamMessageDataConverter))]
        public byte[] data = null;              // Actual message data, encrypted or decrypted
        private byte[] sigdata = null;           // Signature data (for S2), encrypted - obsolete, will be removed with v1

        public byte[] originalData = null;      // Actual message data as was sent (before decryption)
        public byte[] originalChecksum = null;  // Checksum as it was before decryption

        public byte[] signature = null;         // Sender's signature

        public StreamMessageEncryptionCode encryptionType;

        public bool encrypted = false; // used locally to avoid double encryption of data

        public byte[] id;                      // Message unique id - TODO Can probably be removed and a hash used instead

        public long timestamp = 0; // TODO Can probably be moved to SpixiMessage

        public bool requireRcvConfirmation = true; // TODO Can probably be removed

        public StreamMessage(int version = 0)
        {
            this.version = version;
            id = Guid.NewGuid().ToByteArray(); // Generate a new unique id
            type = StreamMessageCode.info;
            sender = null;
            recipient = null;
            data = null;
            if (version == 0)
            {
                encryptionType = StreamMessageEncryptionCode.spixi1;
            }
            else if (version > 0)
            {
                encryptionType = StreamMessageEncryptionCode.spixi2;
            }
            timestamp = Clock.getNetworkTimestamp();
        }

        public StreamMessage(byte[] bytes, StreamMessageSerializationType serializationType = StreamMessageSerializationType.network)
        {
            if (bytes[0] == 0)
            {
                fromBytes_v0(bytes);
            }
            else
            {
                fromBytes_v1(bytes, serializationType);
            }
        }

        private void fromBytes_v0(byte[] bytes)
        {
            try
            {
                using (MemoryStream m = new MemoryStream(bytes))
                {
                    using (BinaryReader reader = new BinaryReader(m))
                    {
                        version = reader.ReadInt32();

                        int id_len = reader.ReadInt32();
                        if (id_len > 0)
                        {
                            id = reader.ReadBytes(id_len);
                        }

                        int message_type = reader.ReadInt32();
                        type = (StreamMessageCode)message_type;

                        int encryption_type = reader.ReadInt32();
                        encryptionType = (StreamMessageEncryptionCode)encryption_type;

                        int sender_length = reader.ReadInt32();
                        if (sender_length > 0)
                            sender = new Address(reader.ReadBytes(sender_length));

                        int recipient_length = reader.ReadInt32();
                        if (recipient_length > 0)
                            recipient = new Address(reader.ReadBytes(recipient_length));

                        int data_length = reader.ReadInt32();
                        if (data_length > 0)
                            data = reader.ReadBytes(data_length);

                        int tx_length = reader.ReadInt32();
                        if (tx_length > 0)
                            transaction = reader.ReadBytes(tx_length);

                        int sigdata_length = reader.ReadInt32();
                        if (sigdata_length > 0)
                            sigdata = reader.ReadBytes(sigdata_length);

                        encrypted = reader.ReadBoolean();
                        reader.ReadBoolean();

                        int sig_length = reader.ReadInt32();
                        if (sig_length > 0)
                            signature = reader.ReadBytes(sig_length);

                        timestamp = reader.ReadInt64();

                        if (reader.BaseStream.Length - reader.BaseStream.Position > 0)
                        {
                            requireRcvConfirmation = reader.ReadBoolean();
                        }
                        else
                        {
                            requireRcvConfirmation = true;
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Logging.error("Exception occurred while trying to construct StreamMessage from bytes: " + e);
                throw;
            }
        }

        private void fromBytes_v1(byte[] bytes, StreamMessageSerializationType serializationType)
        {
            try
            {
                using (MemoryStream m = new MemoryStream(bytes))
                {
                    using (BinaryReader reader = new BinaryReader(m))
                    {
                        version = (int)reader.ReadIxiVarUInt();

                        int id_len = (int)reader.ReadIxiVarUInt();
                        if (id_len > 0)
                        {
                            id = reader.ReadBytes(id_len);
                        }

                        int message_type = (int)reader.ReadIxiVarUInt();
                        type = (StreamMessageCode)message_type;

                        int encryption_type = (int)reader.ReadIxiVarUInt();
                        encryptionType = (StreamMessageEncryptionCode)encryption_type;

                        int sender_length = (int)reader.ReadIxiVarUInt();
                        if (sender_length > 0)
                            sender = new Address(reader.ReadBytes(sender_length));

                        int recipient_length = (int)reader.ReadIxiVarUInt();
                        if (recipient_length > 0)
                            recipient = new Address(reader.ReadBytes(recipient_length));

                        int data_length = (int)reader.ReadIxiVarUInt();
                        if (data_length > 0)
                            data = reader.ReadBytes(data_length);

                        timestamp = (long)reader.ReadIxiVarUInt();

                        int sig_length = (int)reader.ReadIxiVarUInt();
                        if (sig_length > 0)
                            signature = reader.ReadBytes(sig_length);

                        requireRcvConfirmation = reader.ReadBoolean();

                        if (serializationType == StreamMessageSerializationType.storage)
                        {
                            encrypted = reader.ReadBoolean();
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Logging.error("Exception occurred while trying to construct StreamMessage from bytes: " + e);
                throw;
            }
        }

        public byte[] getBytes(StreamMessageSerializationType serializationType = StreamMessageSerializationType.network)
        {
            if (version == 0)
            {
                return getBytes_v0(serializationType);
            }
            else
            {
                return getBytes_v1(serializationType);
            }
        }

        public byte[] getBytes_v0(StreamMessageSerializationType serializationType)
        {
            using (MemoryStream m = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.Write(version);

                    writer.Write(id.Length);
                    writer.Write(id);

                    // Write the type
                    writer.Write((int)type);

                    // Write the encryption type
                    writer.Write((int)encryptionType);

                    // Write the sender
                    if (sender != null)
                    {
                        writer.Write(sender.addressWithChecksum.Length);
                        writer.Write(sender.addressWithChecksum);
                    }
                    else
                    {
                        writer.Write(0);
                    }


                    // Write the recipient
                    if (recipient != null)
                    {
                        writer.Write(recipient.addressWithChecksum.Length);
                        writer.Write(recipient.addressWithChecksum);
                    }
                    else
                    {
                        writer.Write(0);
                    }

                    // Write the data
                    if (data != null)
                    {
                        writer.Write(data.Length);
                        writer.Write(data);
                    }
                    else
                    {
                        writer.Write(0);
                    }

                    // Write the tx
                    if (transaction != null)
                    {
                        writer.Write(transaction.Length);
                        writer.Write(transaction);
                    }
                    else
                    {
                        writer.Write(0);
                    }


                    // Write the sigdata
                    if (sigdata != null)
                    {
                        writer.Write(sigdata.Length);
                        writer.Write(sigdata);
                    }
                    else
                    {
                        writer.Write(0);
                    }

                    if (serializationType != StreamMessageSerializationType.checksum)
                    {
                        // TODO this likely doesn't have to be transmitted over network - it's more of a local helper
                        writer.Write(encrypted);
                        writer.Write(false);
                    }

                    // Write the sig
                    if (serializationType != StreamMessageSerializationType.checksum
                        && signature != null)
                    {
                        writer.Write(signature.Length);
                        writer.Write(signature);
                    }
                    else
                    {
                        writer.Write(0);
                    }

                    writer.Write(timestamp);

                    writer.Write(requireRcvConfirmation);
                }
                return m.ToArray();
            }
        }
        public byte[] getBytes_v1(StreamMessageSerializationType serializationType)
        {
            using (MemoryStream m = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.WriteIxiVarInt(version);

                    writer.WriteIxiVarInt(id.Length);
                    writer.Write(id);

                    // Write the type
                    writer.WriteIxiVarInt((int)type);

                    // Write the encryption type
                    writer.WriteIxiVarInt((int)encryptionType);

                    // Write the sender
                    if (sender != null)
                    {
                        writer.WriteIxiVarInt(sender.addressWithChecksum.Length);
                        writer.Write(sender.addressWithChecksum);
                    }
                    else
                    {
                        writer.WriteIxiVarInt(0);
                    }


                    // Write the recipient
                    if (recipient != null)
                    {
                        writer.WriteIxiVarInt(recipient.addressWithChecksum.Length);
                        writer.Write(recipient.addressWithChecksum);
                    }
                    else
                    {
                        writer.WriteIxiVarInt(0);
                    }

                    // Write the data
                    if (data != null)
                    {
                        writer.WriteIxiVarInt(data.Length);
                        writer.Write(data);
                    }
                    else
                    {
                        writer.WriteIxiVarInt(0);
                    }

                    writer.WriteIxiVarInt(timestamp);

                    if (serializationType != StreamMessageSerializationType.checksum)
                    {
                        // Write the sig
                        if (signature != null)
                        {
                            writer.WriteIxiVarInt(signature.Length);
                            writer.Write(signature);
                        }
                        else
                        {
                            writer.WriteIxiVarInt(0);
                        }

                        writer.Write(requireRcvConfirmation);

                        if (serializationType == StreamMessageSerializationType.storage)
                        {
                            writer.Write(encrypted);
                        }
                    }
                }
                return m.ToArray();
            }
        }

        private byte[] getAdditionalData()
        {
            using (MemoryStream m = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.Write(id);
                    writer.WriteIxiVarInt((int)type);
                    writer.WriteIxiVarInt(timestamp);
                }
                return m.ToArray();
            }
        }

        // Encrypts a provided message with aes, then chacha based on the keys provided
        public bool encrypt(byte[] public_key, byte[] aes_password, byte[] chacha_key)
        {
            if (encrypted)
            {
                return true;
            }

            byte[] encrypted_data = MessageCrypto.encrypt(encryptionType, data, public_key, aes_password, chacha_key, getAdditionalData());
            if (encrypted_data != null)
            {
                data = encrypted_data;
                encrypted = true;
                return true;
            }
            return false;
        }

        public bool decrypt(byte[] private_key, byte[] aes_key, byte[] chacha_key)
        {
            if (originalData != null)
            {
                return true;
            }
            byte[] decrypted_data = MessageCrypto.decrypt(encryptionType, data, private_key, aes_key, chacha_key, getAdditionalData());
            if (decrypted_data != null)
            {
                originalData = data;
                originalChecksum = calculateChecksum();
                data = decrypted_data;
                return true;
            }
            return false;
        }

        public byte[] calculateChecksum()
        {
            if (version == 0)
            {
                return Crypto.sha512(getBytes(StreamMessageSerializationType.checksum));
            }
            else
            {
                return CryptoManager.lib.sha3_512(getBytes(StreamMessageSerializationType.checksum));
            }
        }

        public bool sign(byte[] private_key)
        {
            byte[] checksum = calculateChecksum();
            signature = CryptoManager.lib.getSignature(checksum, private_key);
            if (signature != null)
            {
                return true;
            }
            return false;
        }

        public bool verifySignature(byte[] public_key)
        {
            byte[] checksum = null;
            if (version > 0)
            {
                checksum = originalChecksum;
            }
            if (checksum == null)
            {
                checksum = calculateChecksum();
            }
            return CryptoManager.lib.verifySignature(checksum, public_key, signature);
        }
    }
}

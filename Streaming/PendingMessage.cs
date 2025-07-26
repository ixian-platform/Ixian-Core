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
using System;
using System.IO;

namespace IXICore.Streaming
{
    class PendingMessage
    {
        public string filePath = null;

        public StreamMessage streamMessage = null;
        public bool sendToServer = false;
        public bool sendPushNotification = false;
        public bool removeAfterSending = false;

        public PendingMessage(StreamMessage stream_message, bool send_to_server, bool send_push_notification, bool remove_after_sending)
        {
            streamMessage = stream_message;
            sendToServer = send_to_server;
            sendPushNotification = send_push_notification;
            removeAfterSending = remove_after_sending;
        }

        public PendingMessage(string file_path)
        {
            filePath = file_path;
            fromBytes(File.ReadAllBytes(file_path));
        }

        private void fromBytes(byte[] bytes)
        {
            using (MemoryStream m = new MemoryStream(bytes))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    try
                    {
                        int sm_length = reader.ReadInt32();
                        byte[] sm_bytes = reader.ReadBytes(sm_length);
                        streamMessage = new StreamMessage(sm_bytes, StreamMessageSerializationType.storage);

                        sendToServer = reader.ReadBoolean();
                        sendPushNotification = reader.ReadBoolean();
                        removeAfterSending = reader.ReadBoolean();
                    }
                    catch (Exception e)
                    {
                        Logging.error("Cannot create pending message from bytes: {0}", e);
                        throw;
                    }
                }
            }
        }

        private byte[] toBytes()
        {
            using (MemoryStream m = new MemoryStream(5120))
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    byte[] data = streamMessage.getBytes(StreamMessageSerializationType.storage);
                    writer.Write(data.Length);
                    writer.Write(data);

                    writer.Write(sendToServer);
                    writer.Write(sendPushNotification);
                    writer.Write(removeAfterSending);
                }
                return m.ToArray();
            }
        }

        public void save(string root_path)
        {
            string friend_path = Path.Combine(root_path, streamMessage.recipient.ToString());
            if (filePath == null)
            {
                filePath = Path.Combine(friend_path, Clock.getTimestampMillis() + "-" + Crypto.hashToString(streamMessage.id));
            }
            if(!Directory.Exists(friend_path))
            {
                Directory.CreateDirectory(friend_path);
            }
            File.WriteAllBytes(filePath, toBytes());
        }
    }
}

// Copyright (C) 2017-2020 Ixian OU
// This file is part of Ixian Core - www.github.com/ProjectIxian/Ixian-Core
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
using IXICore.Utils;
using System.Text;

namespace IXICore.Network
{
    public class NetworkEvents
    {
        // Message codes are for the most part pairs (send/receive)
        public enum Type
        {
            all = -1, // only used for detaching
            keepAlive,
        }


        // Prepares an event message data with a provided type and address
        public static byte[] prepareEventMessageData(Type type, byte[] cuckoo_filter)
        {
            MemoryStream m = new MemoryStream();
            using (BinaryWriter writer = new BinaryWriter(m, Encoding.UTF8, true))
            {
                writer.Write((int)type);
                if(cuckoo_filter != null)
                {
                    writer.Write(cuckoo_filter.Length);
                    if (cuckoo_filter.Length > 0)
                    {
                        writer.Write(cuckoo_filter);
                    }
                }else
                {
                    writer.Write((int)0);
                }
#if TRACE_MEMSTREAM_SIZES
                    Logging.info(String.Format("NetworkEvents::prepareEventMessageData: {0}", m.Length));
#endif
            }

            return m.ToArray();
        }

        // Handles a received attach event message and adds event subscriptions for the provided endpoint
        public static void handleAttachEventMessage(byte[] data, RemoteEndpoint endpoint)
        {
            if (data == null || endpoint == null)
            {
                Logging.warn(string.Format("Invalid protocol message event data"));
                return;
            }

            using (MemoryStream m = new MemoryStream(data))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    int type = reader.ReadInt32();
                    int filter_len = reader.ReadInt32();
                    byte[] filter = reader.ReadBytes(filter_len);

                    endpoint.attachEvent((NetworkEvents.Type)type, filter);
                }
            }
        }

        // Handles a received detach event message and removes event subscriptions for the provided endpoint
        public static void handleDetachEventMessage(byte[] data, RemoteEndpoint endpoint)
        {
            if (data == null || endpoint == null)
            {
                Logging.warn(string.Format("Invalid protocol message event data"));
                return;
            }

            using (MemoryStream m = new MemoryStream(data))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    int type = reader.ReadInt32();
                    if(type == -1)
                    {
                        endpoint.detachEventType((NetworkEvents.Type) type);
                        return;
                    }

                    int addr_len = reader.ReadInt32();
                    if(addr_len == 0)
                    {
                        endpoint.detachEventType((NetworkEvents.Type) type);
                        return;
                    }

                    byte[] address = reader.ReadBytes(addr_len);

                    endpoint.detachEventAddress((NetworkEvents.Type) type, address);
                }
            }
        }
    }
}

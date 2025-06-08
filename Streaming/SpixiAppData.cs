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

namespace IXICore
{
    class SpixiAppData
    {
        public byte[] sessionId = null;
        public byte[] data = null;
        public string appId = null;

        public SpixiAppData(byte[] session_id, byte[] in_data, string app_id = null)
        {
            sessionId = session_id;
            data = in_data;
            appId = app_id;
        }

        public SpixiAppData(byte[] bytes)
        {
            try
            {
                using (MemoryStream m = new MemoryStream(bytes))
                {
                    using (BinaryReader reader = new BinaryReader(m))
                    {
                        byte session_id_length = reader.ReadByte();
                        if (session_id_length > 0)
                            sessionId = reader.ReadBytes(session_id_length);

                        int data_length = reader.ReadInt32();
                        if (data_length > 0)
                            data = reader.ReadBytes(data_length);

                        // Read App ID if available
                        if(reader.PeekChar() != -1)
                        {
                            appId = reader.ReadString();
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Logging.error("Exception occurred while trying to construct SpixiAppData from bytes: " + e);
            }
        }

        public byte[] getBytes()
        {
            using (MemoryStream m = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    // Write the session ID
                    if (sessionId != null)
                    {
                        writer.Write((byte)sessionId.Length);
                        writer.Write(sessionId);
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

                    // Write App ID, should always be written last
                    if(appId != null)
                    {
                        writer.Write(appId);
                    }
                }
                return m.ToArray();
            }
        }
    }
}

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

using System.IO;

namespace IXICore.Streaming.Models
{
    public class FileHeaderMessage
    {
        public string Uid { get; set; }
        public string FileName { get; set; }
        public ulong FileSize { get; set; }
        public byte[]? Preview { get; set; }
        public int PacketSize { get; set; }
        public int Channel { get; set; }

        public FileHeaderMessage(string uid, string fileName, ulong fileSize, byte[]? preview, int packetSize, int channel)
        {
            Uid = uid;
            FileName = fileName;
            FileSize = fileSize;
            Preview = preview;
            PacketSize = packetSize;
            Channel = channel;
        }

        public FileHeaderMessage(byte[] data)
        {
            using (MemoryStream m = new MemoryStream(data))
            using (BinaryReader reader = new BinaryReader(m))
            {
                Uid = reader.ReadString();
                FileName = reader.ReadString();
                FileSize = reader.ReadUInt64();

                int previewLength = reader.ReadInt32();
                if (previewLength > 0)
                {
                    Preview = reader.ReadBytes(previewLength);
                }
                else
                {
                    Preview = null;
                }

                PacketSize = reader.ReadInt32();
                Channel = reader.ReadInt32();
            }
        }

        public byte[] getBytes()
        {
            using (MemoryStream m = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.Write(Uid);
                    writer.Write(FileName);
                    writer.Write(FileSize);

                    // Write the preview data
                    if (Preview != null && Preview.Length > 0)
                    {
                        writer.Write(Preview.Length);
                        writer.Write(Preview);
                    }
                    else
                    {
                        writer.Write(0);
                    }

                    writer.Write(PacketSize);
                    writer.Write(Channel);
                }
                return m.ToArray();
            }
        }
    }
}
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
using System.Buffers.Binary;
using System.IO;

namespace IXICore.Utils
{
    // VarInt functions convert long/ulong to variable length bytes and vice-versa and was designed to save space.
    // Our variation of VarInt supports signed and unsigned integers.
    // Negative integers or integers bigger than 0xf7 (247) have an additional byte at the beginning of the byte
    // sequence, which specifies length and type of the number represented.
    //
    // Codes for the initial byte are:
    // 0xf8 - negative short (2 bytes)
    // 0xf9 - negative int (4 bytes)
    // 0xfa - negative long (8 bytes)
    // 0xfb - negative reserved for potential future use (x bytes)
    // 0xfc - short (2 bytes)
    // 0xfd - int (4 bytes)
    // 0xfe - long (8 bytes)
    // 0xff - reserved for potential future use (x bytes)
    //
    // VarInt class extends:
    // - ulong/long with GetVarIntBytes
    // - byte[] with GetVarInt/GetVarUint
    // - BinaryWriter with WriteVarInt
    // - BinaryReader with ReadVarInt/ReadVarUInt
    public static class IxiVarInt
    {
        // int extension
        public static byte[] GetIxiVarIntBytes(this int value)
        {
            return GetIxiVarIntBytes((long)value);
        }

        // long extension
        public static byte[] GetIxiVarIntBytes(this long value)
        {
            bool negative = value < 0;

            ulong abs = negative ? value.ToUlongAbs() : (ulong)value;

            if (!negative && abs < 0xf8)
            {
                return new byte[1] { (byte)abs };
            }
            else if (abs <= 0xffff)
            {
                var bytes = new byte[3];
                bytes[0] = negative ? (byte)0xf8 : (byte)0xfc;
                BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(1), (ushort)abs);
                return bytes;
            }
            else if (abs <= 0xffffffff)
            {
                var bytes = new byte[5];
                bytes[0] = negative ? (byte)0xf9 : (byte)0xfd;
                BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(1), (uint)abs);
                return bytes;
            }
            else
            {
                var bytes = new byte[9];
                bytes[0] = negative ? (byte)0xfa : (byte)0xfe;
                BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(1), abs);
                return bytes;
            }
        }

        // ulong extension
        public static byte[] GetIxiVarIntBytes(this ulong value)
        {
            if (value < 0xf8)
            {
                return new byte[1] { (byte)value };
            }
            else if (value <= 0xffff)
            {
                var bytes = new byte[3];
                bytes[0] = 0xfc;
                BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(1), (ushort)value);
                return bytes;
            }
            else if (value <= 0xffffffff)
            {
                var bytes = new byte[5];
                bytes[0] = 0xfd;
                BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(1), (uint)value);
                return bytes;
            }
            else
            {
                var bytes = new byte[9];
                bytes[0] = 0xfe;
                BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(1), value);
                return bytes;
            }
        }

        // byte[] extensions
        public static (long num, int bytesRead) GetIxiVarInt(this byte[] data, int offset)
        {
            var span = data.AsSpan(offset);
            if (TryReadIxiVarInt(span, 0, out long val, out int read))
            {
                return (val, read);
            }
            throw new InvalidDataException("Cannot decode VarInt from bytes, unknown type " + data[offset].ToString());
        }

        public static (ulong num, int bytesRead) GetIxiVarUInt(this byte[] data, int offset)
        {
            var span = data.AsSpan(offset);
            if (TryReadIxiVarUInt(span, 0, out ulong val, out int read))
            {
                return (val, read);
            }

            // If signed type (< 0xfc) throw a signed-type-used error
            byte type = data[offset];
            if (type < 0xfc)
            {
                throw new InvalidDataException("Cannot decode VarInt from bytes, signed type was used " + type.ToString());
            }
            throw new InvalidDataException("Cannot decode VarInt from bytes, unknown type " + type.ToString());
        }

        // BinaryWriter extensions
        public static void WriteIxiVarInt(this BinaryWriter writer, long value)
        {
            Span<byte> tmp = stackalloc byte[9];
            int written = WriteIxiVarInt(tmp, value);
            writer.Write(tmp.Slice(0, written));
        }

        public static void WriteIxiVarInt(this BinaryWriter writer, ulong value)
        {
            Span<byte> tmp = stackalloc byte[9];
            int written = WriteIxiVarInt(tmp, value);
            writer.Write(tmp.Slice(0, written));
        }

        // BinaryReader extensions
        public static ulong ReadIxiVarUInt(this BinaryReader reader)
        {
            int first = reader.ReadByte();
            if (first < 0xf8)
            {
                return (ulong)first;
            }

            Span<byte> tmp = stackalloc byte[9];
            tmp[0] = (byte)first;

            int payloadLen = tmp[0] switch
            {
                0xfc => 2,
                0xfd => 4,
                0xfe => 8,
                _ => throw new InvalidDataException("Unknown VarUInt type: " + tmp[0])
            };

            if (payloadLen > 0)
            {
                reader.BaseStream.ReadExactly(tmp.Slice(1, payloadLen));
            }

            if (TryReadIxiVarUInt(tmp, 0, out ulong value, out _))
                return value;

            throw new InvalidDataException("Cannot decode VarUInt from bytes");
        }

        public static long ReadIxiVarInt(this BinaryReader reader)
        {
            int first = reader.ReadByte();
            Span<byte> tmp = stackalloc byte[9];
            tmp[0] = (byte)first;

            int payloadLen = tmp[0] switch
            {
                < 0xf8 => 0,
                0xf8 => 2,
                0xf9 => 4,
                0xfa => 8,
                0xfc => 2,
                0xfd => 4,
                0xfe => 8,
                _ => throw new InvalidDataException("Unknown VarInt type: " + tmp[0])
            };

            if (payloadLen > 0)
            {
                reader.BaseStream.ReadExactly(tmp.Slice(1, payloadLen));
            }

            if (TryReadIxiVarInt(tmp, 0, out long value, out _))
                return value;

            throw new InvalidDataException("Cannot decode VarInt from bytes");
        }

        public static IxiNumber ReadIxiNumber(this BinaryReader reader)
        {
            ulong rawLen = reader.ReadIxiVarUInt();
            if (rawLen > int.MaxValue)
            {
                throw new InvalidDataException("IxiNumber length too large.");
            }

            int len = (int)rawLen;
            if (len == 0)
            {
                throw new InvalidDataException("IxiNumber length is zero.");
            }

            // Allocate buffer once and fill directly
            byte[] buffer = GC.AllocateUninitializedArray<byte>(len);
            reader.BaseStream.ReadExactly(buffer);

            return new IxiNumber(buffer);
        }

        public static void WriteIxiNumber(this BinaryWriter writer, IxiNumber number)
        {
            var bytes = number.getBytes();
            writer.WriteIxiVarInt(bytes.Length);
            writer.Write(bytes);
        }

        public static bool TryReadIxiVarInt(ReadOnlySpan<byte> span, int offset, out long value, out int bytesRead)
        {
            value = 0;
            bytesRead = 0;
            if (span.Length - offset <= 0) return false;

            byte type = span[offset];
            if (type < 0xf8)
            {
                value = type;
                bytesRead = 1;
                return true;
            }

            switch (type)
            {
                case 0xf8:
                    if (span.Length - offset < 3) return false;
                    {
                        ushort u = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(offset + 1, 2));
                        value = -(long)u;
                        bytesRead = 3;
                        return true;
                    }
                case 0xf9:
                    if (span.Length - offset < 5) return false;
                    {
                        uint u = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(offset + 1, 4));
                        value = -(long)u;
                        bytesRead = 5;
                        return true;
                    }
                case 0xfa:
                    if (span.Length - offset < 9) return false;
                    {
                        ulong u = BinaryPrimitives.ReadUInt64LittleEndian(span.Slice(offset + 1, 8));
                        if (u == (ulong)long.MaxValue + 1UL)
                        {
                            value = long.MinValue;
                        }
                        else if (u <= (ulong)long.MaxValue)
                        {
                            value = -(long)u;
                        }
                        else
                        {
                            throw new OverflowException("Cannot represent as signed long");
                        }
                        bytesRead = 9;
                        return true;
                    }
                case 0xfc:
                    if (span.Length - offset < 3) return false;
                    {
                        ushort u = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(offset + 1, 2));
                        value = u;
                        bytesRead = 3;
                        return true;
                    }
                case 0xfd:
                    if (span.Length - offset < 5) return false;
                    {
                        uint u = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(offset + 1, 4));
                        value = u;
                        bytesRead = 5;
                        return true;
                    }
                case 0xfe:
                    if (span.Length - offset < 9) return false;
                    {
                        ulong u = BinaryPrimitives.ReadUInt64LittleEndian(span.Slice(offset + 1, 8));
                        value = u <= long.MaxValue ? (long)u : throw new OverflowException("Cannot represent as signed long");
                        bytesRead = 9;
                        return true;
                    }
                default:
                    return false;
            }
        }

        public static bool TryReadIxiVarUInt(ReadOnlySpan<byte> span, int offset, out ulong value, out int bytesRead)
        {
            value = 0;
            bytesRead = 0;
            if (span.Length - offset <= 0) return false;

            byte type = span[offset];
            if (type < 0xf8)
            {
                value = type;
                bytesRead = 1;
                return true;
            }

            switch (type)
            {
                case 0xfc:
                    if (span.Length - offset < 3) return false;
                    {
                        ushort u = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(offset + 1, 2));
                        value = u;
                        bytesRead = 3;
                        return true;
                    }
                case 0xfd:
                    if (span.Length - offset < 5) return false;
                    {
                        uint u = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(offset + 1, 4));
                        value = u;
                        bytesRead = 5;
                        return true;
                    }
                case 0xfe:
                    if (span.Length - offset < 9) return false;
                    {
                        ulong u = BinaryPrimitives.ReadUInt64LittleEndian(span.Slice(offset + 1, 8));
                        value = u;
                        bytesRead = 9;
                        return true;
                    }
                default:
                    return false;
            }
        }

        // Writes a long to a provided span, returns bytes written
        public static int WriteIxiVarInt(Span<byte> buffer, long value)
        {
            bool negative = value < 0;
            ulong abs = value.ToUlongAbs();

            if (!negative && abs < 0xf8)
            {
                buffer[0] = (byte)abs;
                return 1;
            }
            else if (abs <= 0xffff)
            {
                buffer[0] = negative ? (byte)0xf8 : (byte)0xfc;
                BinaryPrimitives.WriteUInt16LittleEndian(buffer.Slice(1), (ushort)abs);
                return 3;
            }
            else if (abs <= 0xffffffff)
            {
                buffer[0] = negative ? (byte)0xf9 : (byte)0xfd;
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(1), (uint)abs);
                return 5;
            }
            else
            {
                buffer[0] = negative ? (byte)0xfa : (byte)0xfe;
                BinaryPrimitives.WriteUInt64LittleEndian(buffer.Slice(1), abs);
                return 9;
            }
        }

        // Writes a ulong to a span, returns bytes written
        public static int WriteIxiVarInt(Span<byte> buffer, ulong value)
        {
            if (value < 0xf8)
            {
                buffer[0] = (byte)value;
                return 1;
            }
            else if (value <= 0xffff)
            {
                buffer[0] = 0xfc;
                BinaryPrimitives.WriteUInt16LittleEndian(buffer.Slice(1), (ushort)value);
                return 3;
            }
            else if (value <= 0xffffffff)
            {
                buffer[0] = 0xfd;
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(1), (uint)value);
                return 5;
            }
            else
            {
                buffer[0] = 0xfe;
                BinaryPrimitives.WriteUInt64LittleEndian(buffer.Slice(1), value);
                return 9;
            }
        }
    }
}

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
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace IXICore.Utils
{
    public static class IxiUtils
    {
        // Helper for validating IPv4 addresses
        static public bool validateIPv4(string ipString)
        {
            if (String.IsNullOrWhiteSpace(ipString))
            {
                return false;
            }

            string[] splitValues = ipString.Split('.');
            if (splitValues.Length != 4)
            {
                return false;
            }

            byte tempForParsing;
            return splitValues.All(r => byte.TryParse(r, out tempForParsing));
        }

        static public void executeProcess(string filename, string arguments, bool wait_for_exit)
        {
            var psi = new ProcessStartInfo();
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;

            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;

            psi.FileName = filename;
            psi.Arguments = arguments;

            var p = Process.Start(psi);
            if (wait_for_exit)
            {
                p.WaitForExit();
            }
        }

        // Extension methods
        public static TValue TryGet<TKey, TValue>(this IDictionary<TKey, TValue> dictionary, TKey key)
        {
            TValue value;
            dictionary.TryGetValue(key, out value);
            return value;
        }

        public static void AddOrReplace<TKey, TValue>(this IDictionary<TKey, TValue> dico, TKey key, TValue value)
        {
            dico[key] = value;
        }

        // bytes extension
        public static byte[] GetIxiBytes(this byte[] value)
        {
            if (value == null)
            {
                return new byte[1] { 0 };
            }

            byte[] lenBytes = value.Length.GetIxiVarIntBytes();
            byte[] bytes = new byte[lenBytes.Length + value.Length];
            Array.Copy(lenBytes, 0, bytes, 0, lenBytes.Length);
            Array.Copy(value, 0, bytes, lenBytes.Length, value.Length);
            return bytes;
        }

        public static (byte[] bytes, int bytesRead) ReadIxiBytes(this byte[] value, int offset)
        {
            int bytesRead = 0;

            var len = value.GetIxiVarUInt(offset);
            offset += len.bytesRead;
            bytesRead += len.bytesRead;

            if (len.num < 0 || len.num > int.MaxValue)
            {
                throw new Exception("Invalid length specified: " + len.num);
            }

            if (len.num == 0)
            {
                return (null, offset);
            }

            byte[] bytes = new byte[len.num];
            Array.Copy(value, offset, bytes, 0, (int)len.num);
            offset += (int)len.num;
            bytesRead += (int)len.num;

            return (bytes, bytesRead);
        }

        public static byte[] copy(byte[] source)
        {
            if (source == null)
            {
                return null;
            }

            byte[] newObj = new byte[source.Length];
            Array.Copy(source, newObj, source.Length);
            return newObj;
        }

        public static Address copy(Address source)
        {
            if (source == null)
            {
                return null;
            }

            return new Address(source);
        }

        // TODO test and replace with Cris's implementation
        public static byte[] calculateMerkleRoot(List<byte[]> hashes)
        {
            if (hashes == null || hashes.Count == 0)
            {
                return null;
            }

            if (hashes.Count == 1)
            {
                return hashes.First();
            }

            while (hashes.Count > 1)
            {
                List<byte[]> newHashes = new List<byte[]>();
                for (int i = 0; i < hashes.Count; i += 2)
                {
                    byte[] neighbourHash;
                    if (i + 1 < hashes.Count)
                    {
                        neighbourHash = hashes[i + 1];
                    }
                    else
                    {
                        neighbourHash = hashes[i];
                    }

                    byte[] pair = hashes[i].Concat(neighbourHash).ToArray();
                    byte[] hash = CryptoManager.lib.sha3_512sq(pair);
                    newHashes.Add(hash);
                }
                hashes = newHashes;
            }

            return hashes.First();
        }

        public static byte[] GetBytesBE(this ulong value)
        {
            byte[] b = new byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(b, value);
            return b;
        }
        public static byte[] GetBytesBE(this long value)
        {
            byte[] b = new byte[8];
            BinaryPrimitives.WriteInt64BigEndian(b, value);
            return b;
        }

        public static byte[] GetBytesBE(this int value)
        {
            byte[] b = new byte[4];
            BinaryPrimitives.WriteInt32BigEndian(b, value);
            return b;
        }

        public static byte[] GetBytesBE(this short value)
        {
            byte[] b = new byte[2];
            BinaryPrimitives.WriteInt16BigEndian(b, value);
            return b;
        }

        // Converts long to ulong safely for negative numbers
        public static ulong ToUlongAbs(this long value)
        {
            return value == long.MinValue ? (ulong)long.MaxValue + 1 : (ulong)Math.Abs(value);
        }
    }


    // Extension - lambda comparer for stuff like SortedSet
    public class LambdaComparer<T> : IComparer<T>
    {
        private readonly Comparison<T> comparison;
        public LambdaComparer(Comparison<T> comparison)
        {
            this.comparison = comparison;
        }
        public int Compare(T x, T y)
        {
            return comparison(x, y);
        }
    }
}

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

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace IXICore
{
    /// <summary>
    /// Shortcuts for some common Ixian cryptographic operations.
    /// </summary>
    public class Crypto
    {
        [ThreadStatic]
        static SHA256 sha256Engine = null;
        [ThreadStatic]
        static SHA512 sha512Engine = null;

        /// <summary>
        /// Converts a byte-field into a hexadecimal string representation.
        /// </summary>
        /// <param name="data">Byte-field.</param>
        /// <returns>Hexadecimal string representation of the byte field.</returns>
        public static string hashToString(byte[] data)
        {
            if(data == null)
            {
                return "null";
            }
            StringBuilder hash = new StringBuilder();
            foreach (byte theByte in data)
            {
                hash.Append(theByte.ToString("x2"));
            }
            return hash.ToString();
        }

        /// <summary>
        /// Converts a hexadecimal string value of any length into a byte-field representation.
        /// </summary>
        /// <param name="data">Hexadecimal string</param>
        /// <returns>Byte array with the value of the input hexadecimal string.</returns>
        public static byte[] stringToHash(string data)
        {
            int NumberChars = data.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(data.Substring(i, 2), 16);
            }
            return bytes;
        }

        /// <summary>
        ///  Computes a SHA256 value of the given data. It is possible to calculate the hash for a subset of the input data by
        ///  using the `offset` and `count` parameters.
        /// </summary>
        /// <param name="data">Source data for hashing.</param>
        /// <param name="offset">Byte offset into the data. Default = 0</param>
        /// <param name="count">Number of bytes to use in the calculation. Default, 0, means use all available bytes.</param>
        /// <returns>SHA256 hash of the input data.</returns>
        public static byte[] sha256(byte[] data, int offset = 0, int count = 0)
        {
            if (count == 0)
            {
                count = data.Length - offset;
            }
            if(sha256Engine == null)
            {
                sha256Engine = SHA256.Create();
            }
            return sha256Engine.ComputeHash(data, offset, count);
        }

        /// <summary>
        ///  Computes a SHA256 value of the contents of a file using a buffered stream for efficiency.
        ///  Optimized for large files and low-memory environments.
        /// </summary>
        /// <param name="file_path">Path to the file to be hashed.</param>
        /// <returns>SHA256 hash of the file contents.</returns>
        public static string sha256OfFile(string file_path)
        {
            if (string.IsNullOrWhiteSpace(file_path))
            {
                throw new ArgumentException("file_path incorrect", nameof(file_path));
            }

            if (!File.Exists(file_path))
            {
                throw new FileNotFoundException("File not found", file_path);
            }

            if (sha256Engine == null)
            {
                sha256Engine = SHA256.Create();
            }

            using (var stream = new BufferedStream(File.OpenRead(file_path), 8192)) // 8KB
            {
                var hash = sha256Engine.ComputeHash(stream);
                return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
            }
        }

        /// <summary>
        ///  Computes a SHA512 value of the given data. It is possible to calculate the hash for a subset of the input data by
        ///  using the `offset` and `count` parameters.
        /// </summary>
        /// <param name="data">Source data for hashing.</param>
        /// <param name="offset">Byte offset into the data. Default = 0</param>
        /// <param name="count">Number of bytes to use in the calculation. Default, 0, means use all available bytes.</param>
        /// <returns>SHA512 hash of the input data.</returns>
        public static byte[] sha512(byte[] data, int offset = 0, int count = 0)
        {
#if USEBC || WINDOWS_UWP || NETCORE
			Sha512Digest sha = new Sha512Digest();
			sha.BlockUpdate(data, offset, count);
			byte[] rv = new byte[64];
			sha.DoFinal(rv, 0);
            return rv;
#else
            if(count == 0)
            {
                count = data.Length - offset;
            }
            if (sha512Engine == null)
            {
                sha512Engine = SHA512.Create();
            }
            return sha512Engine.ComputeHash(data, offset, count);
#endif
        }

        /// <summary>
        ///  Computes a (SHA512)^2 value of the given data. It is possible to calculate the hash for a subset of the input data by
        ///  using the `offset` and `count` parameters.
        /// </summary>
        /// <remarks>
        ///  The term (SHA512)^2 in this case means hashing the value twice - e.g. using SHA512 again on the computed hash value.
        /// </remarks>
        /// <param name="data">Source data for hashing.</param>
        /// <param name="offset">Byte offset into the data. Default = 0</param>
        /// <param name="count">Number of bytes to use in the calculation. Default, 0, means use all available bytes.</param>
        /// <returns>SHA256 squared hash of the input data.</returns>
        public static byte[] sha512sq(byte[] data, int offset = 0, int count = 0)
        {
#if USEBC || WINDOWS_UWP || NETCORE
			/*Sha512Digest sha = new Sha512Digest();
			sha.BlockUpdate(data, offset, count);
			byte[] rv = new byte[64];
			sha.DoFinal(rv, 0);
			sha.BlockUpdate(rv, 0, rv.Length);
			sha.DoFinal(rv, 0);
			return new uint256(rv);*/
#else
            if (count == 0)
            {
                count = data.Length - offset;
            }
            if (sha512Engine == null)
            {
                sha512Engine = SHA512.Create();
            }
            var h = sha512Engine.ComputeHash(data, offset, count);
            return sha512Engine.ComputeHash(h, 0, h.Length);
#endif
        }

        /// <summary>
        ///  Computes a trunc(N, (SHA512)^2) value of the given data. It is possible to calculate the hash for a subset of the input data by
        ///  using the `offset` and `count` parameters.
        /// </summary>
        /// <remarks>
        ///  The term (SHA512)^2 in this case means hashing the value twice - e.g. using SHA512 again on the computed hash value.
        ///  The trunc(N, X) function represents taking only the first `N` bytes of the byte-field `X`.
        /// </remarks>
        /// <param name="data">Source data for hashing.</param>
        /// <param name="offset">Byte offset into the data. Default = 0</param>
        /// <param name="count">Number of bytes to use in the calculation. Default, 0, means use all available bytes.</param>
        /// <param name="hash_length">Number of bytes to keep from the truncated hash.</param>
        /// <returns>SHA256 squared and truncated hash of the input data.</returns>
        public static byte[] sha512sqTrunc(byte[] data, int offset = 0, int count = 0, int hash_length = 44)
        {
            byte[] shaTrunc = new byte[hash_length];
            Array.Copy(sha512sq(data, offset, count), shaTrunc, hash_length);
            return shaTrunc;
        }

        /// <summary>
        ///  Computes a (SHA512)^4 value of the given data. It is possible to calculate the hash for a subset of the input data by
        ///  using the `offset` and `count` parameters.
        /// </summary>
        /// <remarks>
        ///  The term (SHA512)^4 in this case means hashing the value four times - e.g. using SHA512 repeatedly on the computed hash value.
        /// </remarks>
        /// <param name="data">Source data for hashing.</param>
        /// <param name="offset">Byte offset into the data. Default = 0</param>
        /// <param name="count">Number of bytes to use in the calculation. Default, 0, means use all available bytes.</param>
        /// <returns>SHA256 quad hash of the input data.</returns>
        public static byte[] sha512qu(byte[] data, int offset = 0, int count = 0)
        {
            return sha512sq(sha512sq(data, offset, count));
        }

        /// <summary>
        ///  Computes a trunc(N, (SHA512)^4) value of the given data. It is possible to calculate the hash for a subset of the input data by
        ///  using the `offset` and `count` parameters.
        /// </summary>
        /// <remarks>
        ///  The term (SHA512)^4 in this case means hashing the value four times - e.g. using SHA512 repeatedly on the computed hash value.
        ///  The trunc(N, X) function represents taking only the first `N` bytes of the byte-field `X`.
        /// </remarks>
        /// <param name="data">Source data for hashing.</param>
        /// <param name="offset">Byte offset into the data. Default = 0</param>
        /// <param name="count">Number of bytes to use in the calculation. Default, 0, means use all available bytes.</param>
        /// <param name="hash_length">Number of bytes to keep from the truncated hash.</param>
        /// <returns>SHA256 quad and truncated hash of the input data.</returns>

        public static byte[] sha512quTrunc(byte[] data, int offset = 0, int count = 0, int hash_length = 32)
        {
            byte[] shaTrunc = new byte[hash_length];
            Array.Copy(sha512qu(data, offset, count), shaTrunc, hash_length);
            return shaTrunc;
        }
    }
}
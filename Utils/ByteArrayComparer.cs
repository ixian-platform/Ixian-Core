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
using System.Linq;
using System.Runtime.CompilerServices;

namespace IXICore.Utils
{
    public class _ByteArrayComparer
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int Compare(byte[] x, byte[] y)
        {
            return ((ReadOnlySpan<byte>)x).SequenceCompareTo(y);
        }
    }

    public class ByteArrayComparer : IComparer<byte[]>, IEqualityComparer<byte[]>
    {
        public int Compare(byte[] x, byte[] y)
        {
            return _ByteArrayComparer.Compare(x, y);
        }
        public bool Equals(byte[] left, byte[] right)
        {
            if (left == null || right == null)
            {
                return left == right;
            }
            if (ReferenceEquals(left, right))
            {
                return true;
            }
            if (left.Length != right.Length)
            {
                return false;
            }
            return left.SequenceEqual(right);
        }
        public int GetHashCode(byte[] key)
        {
            if (key == null)
            {
                return -1;
            }
            int value = key.Length;
            if (value >= 4)
            {
                return BitConverter.ToInt32(key, value - 4); // take last 4 bytes
            }
            foreach (var b in key)
            {
                value <<= 8;
                value += b;
            }
            return value;
        }
    }
}

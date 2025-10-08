using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IXICore.Utils
{
    public class AddressComparer : IComparer<Address>, IEqualityComparer<Address>
    {
        public int Compare(Address x, Address y)
        {
            return _ByteArrayComparer.Compare(x.addressNoChecksum, y.addressNoChecksum);
        }
        public bool Equals(Address left, Address right)
        {
            if (left == null || right == null)
            {
                return left == right;
            }
            if (ReferenceEquals(left, right))
            {
                return true;
            }
            if (left.addressNoChecksum.Length != right.addressNoChecksum.Length)
            {
                return false;
            }
            return left.addressNoChecksum.SequenceEqual(right.addressNoChecksum);
        }
        public int GetHashCode(Address key)
        {
            if (key == null)
            {
                return -1;
            }
            int value = key.addressNoChecksum.Length;
            if (value >= 4)
            {
                return BitConverter.ToInt32(key.addressNoChecksum, value - 4); // take last 4 bytes
            }
            foreach (var b in key.addressNoChecksum)
            {
                value <<= 8;
                value += b;
            }
            return value;
        }
    }
}

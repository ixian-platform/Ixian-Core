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
using System.Linq;
using System.Collections.Generic;
using System.Text;
using System.IO;

namespace IXICore.Utils
{
    public class Cuckoo
    {
        // used both for insert and get operations
        public enum CuckooStatus
        {
            OK,
            NotEnoughSpace,
        }
        private int maxKicks = 500;
        private int itemSize = 4;
        private int associativity = 4;
        private int numBuckets;
        private byte[] cuckooData;
        private byte[] kickVictim;
        private readonly Random RNG = new Random();
        private int bucketSize
        {
            get
            {
                return itemSize * associativity;
            }
        }

        public int numItems { get; private set; } = 0;

        #region Utility functions
        private static int round_up_to_pow2(int x)
        {
            x--;
            x |= x >> 1;
            x |= x >> 2;
            x |= x >> 4;
            x |= x >> 8;
            x |= x >> 16;
            x |= x >> 32;
            x++;
            return x;
        }
        #endregion

        public Cuckoo(int expected_items, int max_kicks = 0)
        {
            if (max_kicks != 0)
            {
                maxKicks = max_kicks;
            }
            // approx number of buckets
            int num_buckets = Math.Max(1, expected_items / associativity);
            // align to nearest power of two (upward)
            num_buckets = round_up_to_pow2(num_buckets);
            //
            double exp_utilization = (double)expected_items / (double)num_buckets / (double)associativity;
            if(exp_utilization > 0.96)
            {
                num_buckets <<= 1;
            }
            //
            numBuckets = num_buckets;
            cuckooData = new byte[numBuckets * associativity * itemSize];
        }

        public Cuckoo(byte[] filter)
        {
            setFilterBytes(filter);
        }

        private void calculateIndexAndTag(byte[] item, ref int index, ref byte[] tag)
        {
            byte[] hash = CryptoManager.lib.sha3_512(item);
            tag = new byte[itemSize];
            Array.Copy(hash, hash.Length - itemSize, tag, 0, itemSize);
            if(tag.All(b => b == 0))
            {
                // we don't want all zero tags, because those indicate free spots in the buckets
                tag[tag.Length - 1] = 1;
            }
            ulong raw_index;
            if (itemSize == 4)
            {
                raw_index = (ulong)BitConverter.ToUInt32(tag, 0);
            }
            else if (itemSize == 8)
            {
                raw_index = (ulong)BitConverter.ToUInt64(tag, 0);
            }
            else
            {
                throw new Exception(string.Format("Invalid item size ({0}) for Cuckoo filter.", itemSize));
            }
            // trick from Bin Fan et. al: If divisor is a power of two, we can
            // replace modulo operation with a binary and
            index = (int)(raw_index & (ulong)(numBuckets - 1));
        }

        private int calculateAltIndex(int idx1, byte[] tag)
        {
            byte[] tag_hash = CryptoManager.lib.sha3_512(tag);
            ulong raw_hash;
            if (itemSize == 4)
            {
                raw_hash = (ulong)BitConverter.ToUInt32(tag_hash, 0);
            }
            else if (itemSize == 8)
            {
                raw_hash = (ulong)BitConverter.ToUInt64(tag_hash, 0);
            }
            else
            {
                throw new Exception(string.Format("Invalid item size ({0}) for Cuckoo filter.", itemSize));
            }
            ulong alt_index = (ulong)idx1 ^ raw_hash;
            return (int)(alt_index & (ulong)(numBuckets - 1));
        }


        private bool isZero(byte[] addr, int idx)
        {
            for (int i = idx; i < idx + itemSize; i++)
            {
                if (addr[i] != 0)
                {
                    return false;
                }
            }
            return true;
        }

        private bool areEqual(byte[] addr1, int idx1, byte[] addr2, int idx2)
        {
            for (int i = 0; i < itemSize; i++)
            {
                if (addr1[idx1 + i] != addr2[idx2 + i])
                {
                    return false;
                }
            }
            return true;
        }

        private byte[] insertIntoBucket(int b_idx, byte[] tag)
        {
            for (int i = 0; i < associativity; i++)
            {
                if (isZero(cuckooData, (b_idx * bucketSize) + (i * itemSize)))
                {
                    Array.Copy(tag, 0, cuckooData, (b_idx * bucketSize) + (i * itemSize), itemSize);
                    return null;
                }
            }
            // bucket is completely full
            int evict_bucket = RNG.Next(0, associativity);
            byte[] evicted_tag = new byte[itemSize];
            Array.Copy(cuckooData, (b_idx * bucketSize) + (evict_bucket * itemSize), evicted_tag, 0, itemSize);
            Array.Copy(tag, 0, cuckooData, (b_idx * bucketSize) + (evict_bucket * itemSize), itemSize);
            return evicted_tag;
        }

        private bool removeFromBucket(int b_idx, byte[] tag)
        {
            for (int i=0;i<associativity;i++)
            {
                if(areEqual(tag, 0, cuckooData, (b_idx*bucketSize) + (i*itemSize)))
                {
                    for(int j = 0; j < itemSize; j++)
                    {
                        cuckooData[(b_idx * bucketSize) + (i * itemSize) + j] = 0;
                    }
                    return true;
                }
            }
            return false;
        }

        private bool bucketHasRoom(int b_idx)
        {
            for (int i = 0; i < associativity; i++)
            {
                if (isZero(cuckooData, (b_idx * bucketSize) + (i * itemSize)))
                {
                    return true;
                }
            }
            return false;
        }

        private bool bucketHasItem(int b_idx, byte[] tag)
        {
            for (int i = 0; i < associativity; i++)
            {
                if(areEqual(tag, 0, cuckooData, (b_idx*bucketSize) + (i*itemSize)))
                {
                    return true;
                }
            }
            return false;
        }

        public CuckooStatus Add(byte[] item)
        {
            if(kickVictim != null)
            {
                return CuckooStatus.NotEnoughSpace;
            }
            int idx1 = 0;
            byte[] tag = null;
            calculateIndexAndTag(item, ref idx1, ref tag);
            int idx2 = calculateAltIndex(idx1, tag);

            if(bucketHasItem(idx1, tag) || bucketHasItem(idx2, tag))
            {
                // already in the filter
                return CuckooStatus.OK;
            }

            if(bucketHasRoom(idx1))
            {
                insertIntoBucket(idx1, tag);
                numItems += 1;
                return CuckooStatus.OK;
            }
            if(bucketHasRoom(idx2))
            {
                insertIntoBucket(idx2, tag);
                numItems += 1;
                return CuckooStatus.OK;
            }

            for(int i = 0; i < maxKicks; i++)
            {
                tag = insertIntoBucket(idx1, tag);
                if (tag == null)
                {
                    numItems += 1;
                    return CuckooStatus.OK;
                }
                idx1 = calculateAltIndex(idx1, tag);
            }
            
            if(tag != null)
            {
                kickVictim = tag;
            }
            numItems += 1;
            return CuckooStatus.OK;
        }

        public bool Contains(byte[] item)
        {
            byte[] tag = null;
            int idx1 = 0;
            calculateIndexAndTag(item, ref idx1, ref tag);
            int idx2 = calculateAltIndex(idx1, tag);
            if (kickVictim != null)
            {
                if(areEqual(tag, 0, kickVictim, 0))
                {
                    return true;
                }
            }
            if(bucketHasItem(idx1, tag) || bucketHasItem(idx2, tag))
            {
                return true;
            }
            return false;
        }

        public void Delete(byte[] item)
        {
            byte[] tag = null;
            int idx1 = 0;
            calculateIndexAndTag(item, ref idx1, ref tag);
            int idx2 = calculateAltIndex(idx1, tag);
            if (kickVictim != null)
            {
                if (areEqual(tag, 0, kickVictim, 0))
                {
                    kickVictim = null;
                }
            }
            if(removeFromBucket(idx1, tag) || removeFromBucket(idx2, tag))
            {
                numItems -= 1;
            }
        }

        private byte numItemsInBucket(int b_idx)
        {
            byte num = 0;
            for(int i=0;i<associativity;i++)
            {
                if(!isZero(cuckooData, (b_idx*bucketSize) + (i*itemSize)))
                {
                    num++;
                } else
                {
                    break;
                }
            }
            return num;
        }

        public byte[] getFilterBytes()
        {
            // worst case allocation
            using (MemoryStream ms = new MemoryStream(numBuckets * bucketSize))
            using (BinaryWriter w = new BinaryWriter(ms))
            {
                // metadata
                w.Write((byte)itemSize);
                w.Write((byte)associativity);
                w.Write(numBuckets);
                if (kickVictim != null)
                {
                    w.Write(kickVictim.Length);
                    w.Write(kickVictim);
                }
                else
                {
                    w.Write(0);
                }
                w.Write(numItems);
                for (int i = 0; i < numBuckets; i++)
                {
                    byte b_a = numItemsInBucket(i);
                    w.Write(b_a);
                    w.Write(cuckooData, (i * bucketSize), b_a * itemSize);
                }
                return ms.ToArray();
            }
        }

        public void setFilterBytes(byte[] filter)
        {
            using (MemoryStream ms = new MemoryStream(filter))
            using (BinaryReader r = new BinaryReader(ms))
            {
                // metadata
                itemSize = (int)r.ReadByte();
                associativity = (int)r.ReadByte();
                numBuckets = r.ReadInt32();
                int kick_victim_len = r.ReadInt32();
                if (kick_victim_len > 0)
                {
                    kickVictim = r.ReadBytes(kick_victim_len);
                }
                numItems = r.ReadInt32();
                cuckooData = new byte[numBuckets * bucketSize];
                for (int i = 0; i < numBuckets; i++)
                {
                    byte b_a = r.ReadByte();
                    if (b_a == 0) continue;
                    byte[] bucket = r.ReadBytes(b_a * itemSize);
                    Array.Copy(bucket, 0, cuckooData, i * bucketSize, b_a * itemSize);
                }
            }
        }
    }
}

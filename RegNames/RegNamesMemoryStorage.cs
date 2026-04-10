// Copyright (C) 2017-2024 Ixian OU
// This file is part of Ixian Core - www.github.com/ProjectIxian/Ixian-Core
//
// Ixian Core is free software: you can redistribute it and/or modify
// it under the terms of the MIT License as published
// by the Open Source Initiative.
//
// Ixian Core is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// MIT License for more details.
//

using IXICore.Meta;
using IXICore.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace IXICore.RegNames
{
    public class RegNamesMemoryStorage : IRegNameStorage
    {
        SortedDictionary<byte[], RegisteredNameRecord> names = new SortedDictionary<byte[], RegisteredNameRecord>(new ByteArrayComparer());

        private string storagePath = "names";
        private ulong saveInterval = 1000;

        private IxiNumber rewardPool = 0;
        private ulong highestExpirationBlockHeight = 0;

        public RegNamesMemoryStorage(string storagePath, ulong saveInterval)
        {
            this.storagePath = storagePath;
            this.saveInterval = saveInterval;
        }

        public ulong loadFromDisk(ulong restoreFromBlockNum = 0)
        {
            if (restoreFromBlockNum == 0)
            {
                return 0;
            }

            restoreFromBlockNum = ((ulong)(restoreFromBlockNum / saveInterval)) * saveInterval;
            string dbPath = "";

            FileStream fs = null;
            while (fs == null)
            {
                dbPath = storagePath + Path.DirectorySeparatorChar + "0000" + Path.DirectorySeparatorChar + restoreFromBlockNum + ".dat";
                if (File.Exists(dbPath))
                {
                    fs = File.Open(dbPath, FileMode.Open, FileAccess.Read, FileShare.None);
                }
                else
                {
                    if (restoreFromBlockNum < saveInterval)
                    {
                        return 0;
                    }
                    restoreFromBlockNum -= saveInterval;
                }
            }
            try
            {
                byte[] namesVersionBytes = new byte[4];
                fs.Read(namesVersionBytes, 0, 4);
                BitConverter.ToInt32(namesVersionBytes, 0); // version

                byte[] rewardPoolLenBytes = new byte[4];
                fs.Read(rewardPoolLenBytes, 0, 4);
                int rewardPoolLen = BitConverter.ToInt32(rewardPoolLenBytes, 0);

                byte[] rewardPoolBytes = new byte[rewardPoolLen];
                fs.Read(rewardPoolBytes, 0, rewardPoolLen);

                rewardPool = new IxiNumber(rewardPoolBytes);

                byte[] highestExpirationBlockHeightBytes = new byte[8];
                fs.Read(highestExpirationBlockHeightBytes, 0, 8);

                highestExpirationBlockHeight = BitConverter.ToUInt64(highestExpirationBlockHeightBytes, 0);

                byte[] nameCountBytes = new byte[8];
                fs.Read(nameCountBytes, 0, 8);

                long nameCount = BitConverter.ToInt64(nameCountBytes, 0);

                for (long i = 0; i < nameCount; i++)
                {
                    byte[] lenBytes = new byte[4];
                    fs.Read(lenBytes, 0, 4);

                    int len = BitConverter.ToInt32(lenBytes, 0);

                    byte[] entryBytes = new byte[len];
                    fs.Read(entryBytes, 0, len);

                    RegisteredNameRecord regName = new RegisteredNameRecord(entryBytes);

                    byte[] recordCountBytes = new byte[4];
                    fs.Read(recordCountBytes, 0, 4);
                    int recordCount = BitConverter.ToInt32(recordCountBytes, 0);

                    for (int j = 0; j < recordCount; j++)
                    {
                        byte[] recordLenBytes = new byte[4];
                        fs.Read(recordLenBytes, 0, 4);

                        int recordLen = BitConverter.ToInt32(recordLenBytes, 0);

                        byte[] recordBytes = new byte[recordLen];
                        fs.Read(recordBytes, 0, recordLen);

                        regName.dataRecords.Add(new RegisteredNameDataRecord(recordBytes, true));
                    }

                    names.Add(regName.name, regName);
                }
                fs.Close();
            }
            catch (Exception e)
            {
                fs.Close();
                Logging.error("An exception occurred while reading file '" + dbPath + "': " + e);
                File.Delete(dbPath);
                loadFromDisk();
            }

            return restoreFromBlockNum;
        }

        public void clear()
        {
            lock(names)
            {
                names.Clear();
                rewardPool = 0;
            }
        }

        public void saveToDisk(ulong blockNum)
        {
            string dbPath = storagePath + Path.DirectorySeparatorChar + "0000" + Path.DirectorySeparatorChar + blockNum + ".dat";

            FileStream fs = File.Open(dbPath, FileMode.Create, FileAccess.Write, FileShare.None);
            fs.Write(BitConverter.GetBytes(0), 0, 4);

            lock (names)
            {
                fs.Write(BitConverter.GetBytes(rewardPool.getBytes().Length), 0, 4);
                fs.Write(rewardPool.getBytes());

                fs.Write(BitConverter.GetBytes(highestExpirationBlockHeight));

                fs.Write(BitConverter.GetBytes(names.LongCount()), 0, 8);

                foreach (var kv in names)
                {
                    byte[] entryBytes = kv.Value.toBytes(RegNameRecordByteTypes.full);
                    fs.Write(BitConverter.GetBytes(entryBytes.Length), 0, 4);
                    fs.Write(entryBytes, 0, entryBytes.Length);

                    fs.Write(BitConverter.GetBytes(kv.Value.dataRecords.Count), 0, 4);
                    foreach (var record in kv.Value.dataRecords)
                    {
                        byte[] recordBytes = record.toBytes(true);
                        fs.Write(BitConverter.GetBytes(recordBytes.Length), 0, 4);
                        fs.Write(recordBytes, 0, recordBytes.Length);
                    }
                }
            }
            fs.Close();
        }

        public byte[] getRegNameHeaderBytes(byte[] name)
        {
            RegisteredNameRecord regName;
            if (names.TryGetValue(name, out regName))
            {
                return regName.toBytes(RegNameRecordByteTypes.full);
            }
            return null;
        }

        public bool createRegName(RegisteredNameRecord regName)
        {
            lock (names)
            {
                if (names.ContainsKey(regName.name))
                {
                    return false;
                }
                names.Add(regName.name, regName);
            }
            return true;
        }

        public bool removeRegName(byte[] name)
        {
            lock (names)
            {
                if (!names.ContainsKey(name))
                {
                    return false;
                }
                names.Remove(name);
            }
            return true;
        }

        public RegisteredNameRecord getRegNameHeader(byte[] name)
        {
            RegisteredNameRecord regName;
            lock (names)
            {
                if (names.TryGetValue(name, out regName))
                {
                    return new RegisteredNameRecord(regName);
                }
            }
            return null;
        }

        public bool updateRegName(RegisteredNameRecord regName, bool addIfNotPresent)
        {
            lock (names)
            {
                if (!names.ContainsKey(regName.name))
                {
                    if (addIfNotPresent)
                    {
                        names.Add(regName.name, regName);
                        return true;
                    } else
                    {
                        return false;
                    }
                }
                names[regName.name] = regName;
            }
            return true;
        }

        public void deleteCache()
        {
            string db_path = storagePath + Path.DirectorySeparatorChar + "0000" + Path.DirectorySeparatorChar;
            string[] fileNames = Directory.GetFiles(db_path);
            foreach (string fileName in fileNames)
            {
                File.Delete(fileName);
            }
        }

        public RegisteredNameRecord[] debugGetRegisteredNames()
        {
            lock (names)
            {
                return names.Take(50).Select(x => x.Value).ToArray();
            }
        }

        public IxiNumber increaseRewardPool(IxiNumber fee)
        {
            lock (names)
            {
                rewardPool += fee;
                return rewardPool;
            }
        }

        public IxiNumber decreaseRewardPool(IxiNumber fee)
        {
            lock (names)
            {
                rewardPool -= fee;
                if (rewardPool < 0)
                {
                    Logging.error("Fatal error: Reward pool is less than zero.");
                    IxianHandler.requestShutdown();
                    throw new Exception("Reward pool is less than zero.");
                }
                return rewardPool;
            }
        }

        public ulong count()
        {
            lock (names)
            {
                return (ulong)names.LongCount();
            }
        }

        public IxiNumber getRewardPool()
        {
            return rewardPool;
        }

        public List<RegisteredNameRecord> getExpiredNames(ulong blockHeight)
        {
            lock (names)
            {
                return names.Values.Where(x => x.expirationBlockHeight < blockHeight).ToList();
            }
        }

        public ulong getHighestExpirationBlockHeight()
        {
            return highestExpirationBlockHeight;
        }

        public void setHighestExpirationBlockHeight(ulong blockHeight)
        {
            highestExpirationBlockHeight = blockHeight;
        }

        public byte[] calculateRegNameStateChecksum()
        {
            List<byte[]> hashes = new();
            lock (names)
            {
                foreach (var name in names.Values)
                {
                    hashes.Add(name.calculateChecksum(RegNameRecordByteTypes.forMerkle));
                }
            }
            var merkleRoot = IxiUtils.calculateMerkleRoot(hashes);
            if (merkleRoot == null)
            {
                merkleRoot = new byte[64];
            }
            return merkleRoot;
        }

    }
}

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
using IXICore.Network;
using IXICore.Utils;
using System;
using System.IO;
using System.Linq;

namespace IXICore
{
    public class KeepAlive
    {
        public int version = 2;
        public Address walletAddress = null;
        public byte[] deviceId = null;
        public long timestamp = 0;
        public string hostName = null;
        public byte[] signature = null;
        public char nodeType;
        public byte[] checksum = null; // Checksum is not transmitted over network
        public SignerPowSolution powSolution;

        public KeepAlive()
        {

        }

        public KeepAlive(byte[] kaBytes)
        {
            if (kaBytes[0] < 2)
            {
                // TODO temporary, remove after network upgrade
                fromBytes_v1(kaBytes);
            }
            else
            {
                fromBytes_v2(kaBytes);
            }
        }

        public byte[] getBytes(bool forChecksum = false)
        {
            if (version == 1)
            {
                // TODO temporary, remove after network upgrade
                return getBytes_v1(forChecksum);
            }
            else if(version == 2)
            {
                return getBytes_v2(forChecksum);
            }
            return null;
        }

        byte[] getBytes_v1(bool forChecksum = false)
        {
            using (MemoryStream m = new MemoryStream(640))
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.Write(1); // version

                    writer.Write(walletAddress.addressWithChecksum.Length);
                    writer.Write(walletAddress.addressWithChecksum);

                    writer.Write(new System.Guid(deviceId).ToString());

                    // Add the unix timestamp
                    writer.Write(timestamp);

                    writer.Write(hostName);
                    writer.Write(nodeType);

                    if (!forChecksum)
                    {
                        // Add a verifiable signature
                        writer.Write(signature.Length);
                        writer.Write(signature);
                    }

#if TRACE_MEMSTREAM_SIZES
                    Logging.info(String.Format("PresenceList::keepAlive_v1: {0}", m.Length));
#endif
                }

                return m.ToArray();
            }
        }

        byte[] getBytes_v2(bool forChecksum = false)
        {
            // Prepare the keepalive message
            using (MemoryStream m = new MemoryStream(640))
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.WriteIxiVarInt(2); // version

                    writer.WriteIxiVarInt(walletAddress.addressNoChecksum.Length);
                    writer.Write(walletAddress.addressNoChecksum);

                    writer.WriteIxiVarInt(deviceId.Length);
                    writer.Write(deviceId);

                    // Add the unix timestamp
                    writer.WriteIxiVarInt(timestamp);

                    writer.Write(hostName);
                    writer.Write(nodeType);

                    if(powSolution != null)
                    {
                        var solutionBytes = powSolution.getBytes();
                        writer.WriteIxiVarInt(solutionBytes.Length);
                        writer.Write(solutionBytes);
                    }else
                    {
                        writer.WriteIxiVarInt(0);
                    }

                    if (!forChecksum)
                    {
                        writer.WriteIxiVarInt(signature.Length);
                        writer.Write(signature);
                    }

#if TRACE_MEMSTREAM_SIZES
                    Logging.info(String.Format("PresenceList::keepAlive_v1: {0}", m.Length));
#endif
                }

                return m.ToArray();
            }
        }

        void fromBytes_v1(byte[] kaBytes)
        {
            // TODO temporary, remove after network upgrade
            try
            {
                using (MemoryStream m = new MemoryStream(kaBytes))
                {
                    using (BinaryReader reader = new BinaryReader(m))
                    {
                        version = reader.ReadInt32();

                        int walletLen = reader.ReadInt32();
                        walletAddress = new Address(reader.ReadBytes(walletLen));

                        string device_id_str = reader.ReadString();
                        deviceId = System.Guid.Parse(device_id_str).ToByteArray();
                        timestamp = reader.ReadInt64();
                        hostName = reader.ReadString();

                        nodeType = reader.ReadChar();

                        long checksumDataLen = m.Position;

                        int sigLen = reader.ReadInt32();
                        signature = reader.ReadBytes(sigLen);

                        checksum = kaBytes.Take((int)checksumDataLen).ToArray();
                    }
                }
            }
            catch (Exception e)
            {
                Logging.warn("Cannot create keep alive v1 from bytes: {0}", e.ToString());
                throw;
            }
        }

        void fromBytes_v2(byte[] kaBytes)
        {
            try
            {
                using (MemoryStream m = new MemoryStream(kaBytes))
                {
                    using (BinaryReader reader = new BinaryReader(m))
                    {
                        version = (int)reader.ReadIxiVarInt();

                        int walletLen = (int)reader.ReadIxiVarUInt();
                        walletAddress = new Address(reader.ReadBytes(walletLen));

                        int deviceid_len = (int)reader.ReadIxiVarUInt();
                        deviceId = reader.ReadBytes(deviceid_len);
                        timestamp = (long)reader.ReadIxiVarUInt();
                        hostName = reader.ReadString();

                        nodeType = reader.ReadChar();

                        int powSolutionLen = (int)reader.ReadIxiVarUInt();
                        if(powSolutionLen > 0)
                        {
                            powSolution = new SignerPowSolution(reader.ReadBytes(powSolutionLen), walletAddress);
                        }

                        int sigLen = (int)reader.ReadIxiVarUInt();
                        signature = reader.ReadBytes(sigLen);

                        calculateChecksum();
                    }
                }
            }
            catch (Exception e)
            {
                Logging.warn("Cannot create keep alive v2 from bytes: {0}", e.ToString());
                throw;
            }
        }

        public void calculateChecksum()
        {
            if (checksum != null)
            {
                return;
            }

            if(version <= 1)
            {
                checksum = getBytes(true);
            }else
            {
                byte[] tmpBytes = getBytes(true);
                byte[] tmpBytesWithLock = new byte[ConsensusConfig.ixianChecksumLock.Length + tmpBytes.Length];
                Array.Copy(ConsensusConfig.ixianChecksumLock, tmpBytesWithLock, ConsensusConfig.ixianChecksumLock.Length);
                Array.Copy(tmpBytes, 0, tmpBytesWithLock, ConsensusConfig.ixianChecksumLock.Length, tmpBytes.Length);
                checksum = CryptoManager.lib.sha3_512sqTrunc(tmpBytesWithLock);
            }
        }

        public void sign(byte[] privateKey)
        {
            if (signature != null)
            {
                return;
            }
            calculateChecksum();

            signature = CryptoManager.lib.getSignature(checksum, privateKey);
        }

        public bool verify(byte[] pubKey, IxiNumber minDifficulty)
        {
            if (powSolution == null)
            {
                // do nothing
            }
            else if (IxianHandler.status != NodeStatus.warmUp
                && !Presence.verifyPowSolution(powSolution, minDifficulty, walletAddress))
            {
                Logging.warn("Invalid pow solution received in verifyPresence, verification failed for {0}.", walletAddress.ToString());
                powSolution = null;
                return false;
            }

            try
            {
                if (hostName.Length > 21)
                {
                    Address addr = new Address(hostName);
                } else
                {
                    if (IxianHandler.networkType != NetworkType.reg)
                    {
                        var ipAddrStr = hostName.Split(":");
                        if (!IPv4Subnet.IsPublicIP(ipAddrStr[0]))
                        {
                            return false;
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Logging.error("Hostname error in KA.verify: " + e);
                return false;
            }

            if (!verifySignature(pubKey))
            {
                Logging.warn("[PL] KEEPALIVE tampering for {0} {1}, incorrect Sig.", walletAddress.ToString(), hostName);
                return false;
            }

            return true;
        }

        public bool verifySignature(byte[] pubKey)
        {
            if (signature == null)
            {
                return false;
            }
            calculateChecksum();
            // Verify the signature
            if (CryptoManager.lib.verifySignature(checksum, pubKey, signature) == false)
            {
                return false;
            }
            return true;
        }
    }
}

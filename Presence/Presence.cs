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
using System.Collections.Generic;
using System.IO;

namespace IXICore
{
    // The actual presence object, which can contain multiple PresenceAddress objects
    public class Presence
    {
        public int version = 1;
        public Address wallet;
        public byte[] pubkey;
        public byte[] metadata; 
        public List<PresenceAddress> addresses;

        public Presence()
        {
            wallet = null;
            pubkey = null;
            metadata = null;
            addresses = new List<PresenceAddress> { };
        }

        public Presence(Address wallet_address, byte[] node_pubkey, byte[] node_meta, PresenceAddress node_address)
        {
            wallet = wallet_address;
            pubkey = node_pubkey;
            metadata = node_meta;
            addresses = new List<PresenceAddress> { };
            addresses.Add(node_address);
        }

        public Presence(byte[] bytes)
        {
            try
            {
                if (bytes.Length > 102400)
                {
                    throw new Exception("Presence size is bigger than 100kB.");
                }

                // Prepare addresses
                addresses = new List<PresenceAddress> { };

                wallet = null;
                pubkey = null;
                metadata = null;


                using (MemoryStream m = new MemoryStream(bytes))
                {
                    using (BinaryReader reader = new BinaryReader(m))
                    {
                        if(bytes[0] == 0)
                        {
                            // TODO remove this section after upgrade to Presence v1
                            version = reader.ReadInt32();

                            int walletLen = reader.ReadInt32();
                            if (walletLen > 0)
                            {
                                wallet = new Address(reader.ReadBytes(walletLen));
                            }
                            int pubkeyLen = reader.ReadInt32();
                            if (pubkeyLen > 0)
                            {
                                pubkey = reader.ReadBytes(pubkeyLen);
                            }
                            int mdLen = reader.ReadInt32();
                            if (mdLen > 0)
                            {
                                metadata = reader.ReadBytes(mdLen);
                            }


                            // Read number of addresses
                            UInt16 number_of_addresses = reader.ReadUInt16();

                            // Read addresses
                            for (UInt16 i = 0; i < number_of_addresses; i++)
                            {
                                int byte_count = reader.ReadInt32();
                                if (byte_count > 0)
                                {
                                    byte[] address_bytes = reader.ReadBytes(byte_count);

                                    addresses.Add(new PresenceAddress(address_bytes, wallet));
                                }
                            }

                            if (m.Position < m.Length)
                            {
                                int pow_len = (int)reader.ReadIxiVarUInt();
                                var first_master = addresses.Find(x => x.type == 'M' && x.powSolution == null);
                                if (pow_len > 0
                                    && first_master != null)
                                {
                                    first_master.powSolution = new SignerPowSolution(reader.ReadBytes(pow_len), wallet);
                                }
                            }
                        }
                        else
                        {
                            version = (int)reader.ReadIxiVarInt();

                            int walletLen = (int)reader.ReadIxiVarUInt();
                            if (walletLen > 0)
                            {
                                wallet = new Address(reader.ReadBytes(walletLen));
                            }
                            int pubkeyLen = (int)reader.ReadIxiVarUInt();
                            if (pubkeyLen > 0)
                            {
                                pubkey = reader.ReadBytes(pubkeyLen);
                            }
                            int mdLen = (int)reader.ReadIxiVarUInt();
                            if (mdLen > 0)
                            {
                                metadata = reader.ReadBytes(mdLen);
                            }


                            // Read number of addresses
                            int number_of_addresses = (int)reader.ReadIxiVarUInt();

                            // Read addresses
                            for (int i = 0; i < number_of_addresses; i++)
                            {
                                int byte_count = (int)reader.ReadIxiVarUInt();
                                if (byte_count > 0)
                                {
                                    byte[] address_bytes = reader.ReadBytes(byte_count);

                                    addresses.Add(new PresenceAddress(address_bytes, wallet));
                                }
                            }

                            if (m.Position < m.Length)
                            {
                                // TODO legacy, remove after a few versions
                                int pow_len = (int)reader.ReadIxiVarUInt();
                                var first_master = addresses.Find(x => x.type == 'M' && x.powSolution == null);
                                if (pow_len > 0
                                    && first_master != null)
                                {
                                    first_master.powSolution = new SignerPowSolution(reader.ReadBytes(pow_len), wallet);
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Logging.error("Exception occurred while trying to construct Presence from bytes: " + e);
                throw;
            }
        }

        public byte[] getBytes(ushort from_index = 0, ushort count = 0)
        {
            using (MemoryStream m = new MemoryStream(1280))
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    if(version == 0)
                    {
                        // TODO remove this section after upgrade to Presence v1
                        writer.Write(version);

                        if (wallet != null)
                        {
                            writer.Write(wallet.addressWithChecksum.Length);
                            writer.Write(wallet.addressWithChecksum);
                        }
                        else
                        {
                            writer.Write(0);
                        }

                        if (pubkey != null)
                        {
                            writer.Write(pubkey.Length);
                            writer.Write(pubkey);
                        }
                        else
                        {
                            writer.Write(0);
                        }

                        if (metadata != null)
                        {
                            writer.Write(metadata.Length);
                            writer.Write(metadata);
                        }
                        else
                        {
                            writer.Write(0);
                        }

                        // Write the number of ips
                        UInt16 number_of_addresses = (ushort)((UInt16)addresses.Count - from_index);

                        if (count > 0 && number_of_addresses > count)
                        {
                            number_of_addresses = count;
                        }

                        writer.Write(number_of_addresses);

                        SignerPowSolution pow_solution = null;

                        // Write all ips
                        for (UInt16 i = from_index; i < number_of_addresses; i++)
                        {
                            if (addresses[i] == null)
                            {
                                writer.Write(0);
                                continue;
                            }

                            if (pow_solution == null)
                            {
                                pow_solution = addresses[i].powSolution;
                            }

                            byte[] address_data = addresses[i].getBytes();
                            if (address_data != null)
                            {
                                writer.Write(address_data.Length);
                                writer.Write(address_data);
                            }
                            else
                            {
                                writer.Write(0);
                            }
                        }

                        if (pow_solution != null)
                        {
                            byte[] powSolutionBytes = pow_solution.getBytes();
                            writer.WriteIxiVarInt(powSolutionBytes.Length);
                            writer.Write(powSolutionBytes);
                        }
                        else
                        {
                            writer.WriteIxiVarInt(0);
                        }
                    }
                    else
                    {
                        writer.WriteIxiVarInt(version);

                        if (wallet != null)
                        {
                            writer.WriteIxiVarInt(wallet.addressNoChecksum.Length);
                            writer.Write(wallet.addressNoChecksum);
                        }
                        else
                        {
                            writer.WriteIxiVarInt(0);
                        }

                        if (pubkey != null)
                        {
                            writer.WriteIxiVarInt(pubkey.Length);
                            writer.Write(pubkey);
                        }
                        else
                        {
                            writer.WriteIxiVarInt(0);
                        }

                        if (metadata != null)
                        {
                            writer.WriteIxiVarInt(metadata.Length);
                            writer.Write(metadata);
                        }
                        else
                        {
                            writer.WriteIxiVarInt(0);
                        }

                        // Write the number of ips
                        int number_of_addresses = addresses.Count - from_index;

                        if (count > 0 && number_of_addresses > count)
                        {
                            number_of_addresses = count;
                        }

                        writer.WriteIxiVarInt(number_of_addresses);

                        SignerPowSolution pow_solution = null;

                        // Write all ips
                        for (int i = from_index; i < number_of_addresses; i++)
                        {
                            if (addresses[i] == null)
                            {
                                writer.WriteIxiVarInt(0);
                                continue;
                            }

                            if (pow_solution == null && addresses[i].type == 'M')
                            {
                                // TODO legacy, remove after a few versions
                                pow_solution = addresses[i].powSolution;
                            }

                            byte[] address_data = addresses[i].getBytes();
                            if (address_data != null)
                            {
                                writer.WriteIxiVarInt(address_data.Length);
                                writer.Write(address_data);
                            }
                            else
                            {
                                writer.WriteIxiVarInt(0);
                            }
                        }

                        if(pow_solution != null)
                        {
                            // TODO legacy, remove after a few versions
                            byte[] powSolutionBytes = pow_solution.getBytes();
                            writer.WriteIxiVarInt(powSolutionBytes.Length);
                            writer.Write(powSolutionBytes);
                        }
                        else
                        {
                            writer.WriteIxiVarInt(0);
                        }
                    }

#if TRACE_MEMSTREAM_SIZES
                    Logging.info(String.Format("Presence::getBytes: {0}", m.Length));
#endif
                }
                return m.ToArray();
            }
        }

        public byte[][] getByteChunks()
        {
            ushort chunk_count = (ushort)Math.Ceiling((decimal)addresses.Count / 10);
            byte[][] presence_chunks = new byte[chunk_count][];
            for(ushort i = 0; i < chunk_count; i++)
            {
                presence_chunks[i] = getBytes((ushort)(i * 10), 10);
            }
            return presence_chunks;
        }

        public bool verify(IxiNumber minDifficulty)
        {
            if (pubkey == null || pubkey.Length < 32 || pubkey.Length > 2500)
            {
                return false;
            }

            List<PresenceAddress> valid_addresses = new List<PresenceAddress>();

            long currentTime = Clock.getNetworkTimestamp();

            bool validPowSolution = false;

            foreach (var entry in addresses)
            {
                if (entry.device.Length > 64)
                {
                    continue;
                }

                if (entry.nodeVersion.Length > 20)
                {
                    continue;
                }

                if (entry.address.Length > 24 && entry.address.Length < 9)
                {
                    continue;
                }

                long lTimestamp = entry.lastSeenTime;

                int expiration_time = CoreConfig.serverPresenceExpiration;

                switch(entry.type)
                {
                    case 'C':
                        expiration_time = CoreConfig.clientPresenceExpiration;
                        break;
                }

                // Check for tampering. Includes a +300, -30 second synchronization zone
                if ((currentTime - lTimestamp) > expiration_time)
                {
                    Logging.warn("[PL] Received expired presence for {0} {1}. Skipping; {2} - {3}", wallet.ToString(), entry.address, currentTime, lTimestamp);
                    continue;
                }

                if ((currentTime - lTimestamp) < -30)
                {
                    Logging.warn("[PL] Potential presence tampering for {0} {1}. Skipping; {2} - {3}", wallet.ToString(), entry.address, currentTime, lTimestamp);
                    continue;
                }

                if (!entry.verify(minDifficulty, wallet, pubkey))
                {
                    Logging.warn("Invalid presence address received in verifyPresence, signature verification failed for {0}.", wallet.ToString());
                    continue;
                }

                try
                {
                    if (entry.address.Length > 21)
                    {
                        Address addr = new Address(entry.address);
                    }
                    else
                    {
                        if (IxianHandler.networkType != NetworkType.reg)
                        {
                            var ipAddrStr = entry.address.Split(":");
                            if (!IPv4Subnet.IsPublicIP(ipAddrStr[0]))
                            {
                                continue;
                            }
                        }
                    }
                }
                catch (Exception e)
                {
                    Logging.error("Hostname error in Presence.verify: " + e);
                    continue;
                }

                valid_addresses.Add(entry);
            }

            if (valid_addresses.Count > 0)
            {
                addresses = valid_addresses;
                return true;
            }

            return false;
        }

        public static bool verifyPowSolution(SignerPowSolution signerPow, IxiNumber minDifficulty, Address wallet)
        {
            // TODO Omega remove this once blockHash is part of SignerPowSolution
            if (PresenceList.myPresenceType == 'C' || PresenceList.myPresenceType == 'R')
            {
                return true;
            }
            if (signerPow.blockNum + ConsensusConfig.getPlPowBlocksValidity(IxianHandler.getLastBlockVersion()) < IxianHandler.getLastBlockHeight())
            {
                Logging.warn("Expired pow solution received in verifyPowSolution, verification failed for {0}.", wallet.ToString());
                return false;
            }

            if (signerPow.blockNum > IxianHandler.getLastBlockHeight())
            {
                Logging.warn("Future pow solution received in verifyPowSolution, verification failed for {0}.", wallet.ToString());
                return false;
            }

            if (signerPow.difficulty < minDifficulty)
            {
                Logging.warn("Invalid or empty pow solution received in verifyPowSolution, verification failed for {0}.", wallet.ToString());
                return false;
            }
            return true;
        }
    }
}

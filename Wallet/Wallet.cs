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
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace IXICore
{
    public enum WalletType : byte
    {
        Normal,
        Multisig
    }

    public class Wallet
    {
        public Address id;
        public IxiNumber balance;
        public WalletType type;
        public byte requiredSigs;
        public List<Address> allowedSigners;
        public byte[] data;
        public byte[] publicKey;

        public byte countAllowedSigners
        {
            get
            {
                if (allowedSigners == null) return 0;
                return (byte)allowedSigners.Count;
            }
        }


        public Wallet()
        {
            id = null;
            balance = new IxiNumber();
            type = WalletType.Normal;
            requiredSigs = 1;
            allowedSigners = null;
            data = null;
            publicKey = null;
        }

        public Wallet(Address w_id, IxiNumber w_balance)
        {
            id = w_id;
            balance = w_balance;
            type = WalletType.Normal;
            requiredSigs = 1;
            allowedSigners = null;
            data = null;
            publicKey = null;
        }

        public Wallet(Wallet wallet)
        {
            id = wallet.id;
            balance = wallet.balance;
            type = wallet.type;
            requiredSigs = wallet.requiredSigs;
            if (wallet.allowedSigners != null)
            {
                allowedSigners = new List<Address>();
                for (int i = 0; i < wallet.allowedSigners.Count; i++)
                {
                    var allowedSigner = new byte[wallet.allowedSigners[i].addressNoChecksum.Length];
                    Array.Copy(wallet.allowedSigners[i].addressNoChecksum, allowedSigner, wallet.allowedSigners[i].addressNoChecksum.Length);
                    allowedSigners.Add(new Address(allowedSigner));
                }
            }
            data = wallet.data;
            publicKey = wallet.publicKey;
        }

        public Wallet(byte[] bytes)
        {
            using (MemoryStream m = new MemoryStream(bytes))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    try
                    {
                        int idLen = reader.ReadInt32();
                        id = new Address(reader.ReadBytes(idLen));
                        string balance_str = reader.ReadString();
                        balance = new IxiNumber(balance_str);

                        int dataLen = reader.ReadInt32();
                        if (dataLen > 0)
                        {
                            data = reader.ReadBytes(dataLen);
                        }

                        type = (WalletType)reader.ReadByte();
                        requiredSigs = reader.ReadByte();
                        byte num_allowed_sigs = reader.ReadByte();
                        if (num_allowed_sigs > 0)
                        {
                            allowedSigners = new List<Address>();
                            for (int i = 0; i < num_allowed_sigs; i++)
                            {
                                int signerLen = reader.ReadInt32();
                                allowedSigners.Add(new Address(reader.ReadBytes(signerLen)));
                            }
                        }
                        else
                        {
                            allowedSigners = null;
                        }

                        int pkLen = reader.ReadInt32();
                        if (pkLen > 0)
                        {
                            publicKey = reader.ReadBytes(pkLen);
                        }
                    }
                    catch (Exception)
                    {

                    }
                }
            }
        }

        public byte[] getBytes()
        {
            using (MemoryStream m = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writeBytes(writer);
#if TRACE_MEMSTREAM_SIZES
                    Logging.info(String.Format("Wallet::getBytes: {0}", m.Length));
#endif
                }
                return m.ToArray();
            }
        }

        public void writeBytes(BinaryWriter writer)
        {
            try
            {
                writer.Write(id.addressWithChecksum.Length);
                writer.Write(id.addressWithChecksum);
                writer.Write(balance.ToString());

                if (data != null)
                {
                    writer.Write(data.Length);
                    writer.Write(data);
                }
                else
                {
                    writer.Write((int)0);
                }

                writer.Write((byte)type);
                writer.Write(requiredSigs);
                if (allowedSigners != null)
                {
                    writer.Write((byte)allowedSigners.Count);
                    for (int i = 0; i < allowedSigners.Count; i++)
                    {
                        writer.Write(allowedSigners[i].addressWithChecksum.Length);
                        writer.Write(allowedSigners[i].addressWithChecksum);
                    }
                }
                else
                {
                    writer.Write((byte)0);
                }

                if (publicKey != null)
                {
                    writer.Write(publicKey.Length);
                    writer.Write(publicKey);
                }
                else
                {
                    writer.Write((int)0);
                }
            }
            catch (Exception ex)
            {
                Logging.error("Error while serializing wallet: {0}", ex.Message);
            }
        }

        public byte[] calculateChecksum(int block_version)
        {
            List<byte> rawData = new List<byte>();

            rawData.AddRange(id.addressWithChecksum);
            rawData.AddRange(Encoding.UTF8.GetBytes(balance.ToString()));

            if (data != null)
            {
                rawData.AddRange(data);
            }

            if (publicKey != null)
            {
                rawData.AddRange(publicKey);
            }

            rawData.AddRange(BitConverter.GetBytes((int)type));
            rawData.AddRange(BitConverter.GetBytes((short)requiredSigs));

            if (allowedSigners != null)
            {
                foreach (var entry in allowedSigners)
                {
                    rawData.AddRange(entry.addressWithChecksum);
                }
            }
            if (block_version <= BlockVer.v2)
            {
                return Crypto.sha512quTrunc(rawData.ToArray());
            }
            else
            {
                return Crypto.sha512sqTrunc(rawData.ToArray(), 0, 0, 64);
            }
        }

        public bool isValidSigner(Address address)
        {
            if (address.addressNoChecksum.SequenceEqual(id.addressNoChecksum)) return true;
            if (allowedSigners != null)
            {
                foreach (var accepted_signer in allowedSigners)
                {
                    if (address.addressNoChecksum.SequenceEqual(accepted_signer.addressNoChecksum)) return true;
                }
            }
            return false;
        }

        public void addValidSigner(Address address)
        {
            if (isValidSigner(address)) return;
            if (allowedSigners == null)
            {
                allowedSigners = new List<Address>();
            }

            allowedSigners.Add(address);
        }

        public void delValidSigner(Address address)
        {
            if (!isValidSigner(address)) return;
            if (id.addressNoChecksum.SequenceEqual(address.addressNoChecksum)) return; // can't remove self
            allowedSigners.RemoveAll(x => x.addressNoChecksum.SequenceEqual(address.addressNoChecksum));
        }

        /// <summary>
        /// Returns true if this wallet has no data, no public key, no multisig data nor any balance (it can be deleted from WalletState)
        /// </summary>
        /// <returns>True, if the Wallet may be safely deleted from WalletState.</returns>
        public bool isEmptyWallet()
        {
            return balance.getAmount() == 0;
        }
    }
}
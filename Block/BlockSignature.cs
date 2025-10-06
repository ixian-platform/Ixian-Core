// Copyright (C) 2017-2021 Ixian OU
// This file is part of Ixian Core - www.github.com/ProjectIxian/Ixian-Core
//
// Ixian DLT is free software: you can redistribute it and/or modify
// it under the terms of the MIT License as published
// by the Open Source Initiative.
//
// Ixian DLT is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// MIT License for more details.

using IXICore.Meta;
using IXICore.Utils;
using System;
using System.IO;

namespace IXICore
{
    public class BlockSignature
    {
        public ulong blockNum;
        public byte[] blockHash;
        public byte[] signature;
        public Address recipientPubKeyOrAddress;
        public SignerPowSolution powSolution;

        public BlockSignature()
        {

        }

        public BlockSignature(BlockSignature src)
        {
            blockNum = src.blockNum;

            if (src.blockHash != null)
            {
                blockHash = new byte[src.blockHash.Length];
                Array.Copy(src.blockHash, blockHash, blockHash.Length);
            }

            if (src.signature != null)
            {
                signature = new byte[src.signature.Length];
                Array.Copy(src.signature, signature, signature.Length);
            }

            byte[] address = src.recipientPubKeyOrAddress.getInputBytes();
            recipientPubKeyOrAddress = new Address(address, null, false);

            if (src.powSolution != null)
            {
                powSolution = new SignerPowSolution(src.powSolution);
            }
        }

        public BlockSignature(byte[] bytes, ulong blockNum, byte[] blockHash)
        {
            if (bytes.Length > 2048)
            {
                throw new Exception("Signature length is bigger than 2048B.");
            }
            try
            {
                using (MemoryStream m = new MemoryStream(bytes))
                {
                    using (BinaryReader reader = new BinaryReader(m))
                    {
                        if (blockNum == 0)
                        {
                            this.blockNum = reader.ReadIxiVarUInt();

                            int blockHashLen = (int)reader.ReadIxiVarUInt();
                            this.blockHash = reader.ReadBytes(blockHashLen);
                        }
                        else
                        {
                            this.blockNum = blockNum;
                            this.blockHash = blockHash;
                        }

                        int signerAddressLen = (int)reader.ReadIxiVarUInt();
                        recipientPubKeyOrAddress = new Address(reader.ReadBytes(signerAddressLen));

                        int powSolutionLen = (int)reader.ReadIxiVarUInt();
                        if (powSolutionLen > 0)
                        {
                            powSolution = new SignerPowSolution(reader.ReadBytes(powSolutionLen), recipientPubKeyOrAddress);
                        }

                        if (m.Position < m.Length)
                        {
                            int signatureLen = (int)reader.ReadIxiVarUInt();
                            if (signatureLen > 0)
                            {
                                signature = reader.ReadBytes(signatureLen);
                            }
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Logging.warn("Cannot create PoW Solution from bytes: {0}", e.ToString());
                throw;
            }
        }

        public byte[] getBytesForBlock(bool includeSignature = true, bool compacted = false)
        {
            using (MemoryStream m = new MemoryStream(1200))
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    byte[] address;
                    if (compacted)
                    {
                        address = recipientPubKeyOrAddress.addressNoChecksum;
                    }else
                    {
                        address = recipientPubKeyOrAddress.getInputBytes();
                    }
                    writer.WriteIxiVarInt(address.Length);
                    writer.Write(address);

                    if (powSolution != null)
                    {
                        byte[] powSolutionBytes = powSolution.getBytes(compacted);
                        writer.WriteIxiVarInt(powSolutionBytes.Length);
                        writer.Write(powSolutionBytes);
                    }
                    else
                    {
                        writer.WriteIxiVarInt(0);
                    }

                    if(signature != null && includeSignature && !compacted)
                    {
                        writer.WriteIxiVarInt(signature.Length);
                        writer.Write(signature);
                    }

#if TRACE_MEMSTREAM_SIZES
                    Logging.info(String.Format("NetworkProtocol::broadcastNewBlockSignature: {0}", m.Length));
#endif
                }

                return m.ToArray();
            }
        }

        public byte[] getBytesForBroadcast()
        {
            using (MemoryStream m = new MemoryStream(1152))
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.WriteIxiVarInt(blockNum);

                    writer.WriteIxiVarInt(blockHash.Length);
                    writer.Write(blockHash);

                    byte[] address = recipientPubKeyOrAddress.getInputBytes();
                    writer.WriteIxiVarInt(address.Length);
                    writer.Write(address);

                    if (powSolution != null)
                    {
                        byte[] powSolutionBytes = powSolution.getBytes();
                        writer.WriteIxiVarInt(powSolutionBytes.Length);
                        writer.Write(powSolutionBytes);
                    }else
                    {
                        writer.WriteIxiVarInt(0);
                    }

                    if (signature != null)
                    {
                        writer.WriteIxiVarInt(signature.Length);
                        writer.Write(signature);
                    }

#if TRACE_MEMSTREAM_SIZES
                    Logging.info(String.Format("NetworkProtocol::broadcastNewBlockSignature: {0}", m.Length));
#endif
                }

                return m.ToArray();
            }
        }
    }
}

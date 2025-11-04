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

using IXICore.Meta;
using IXICore.Utils;
using Newtonsoft.Json;
using System;
using System.IO;

namespace IXICore
{
    public class IxiNumberConverter : JsonConverter<IxiNumber>
    {
        public override void WriteJson(JsonWriter writer, IxiNumber value, JsonSerializer serializer)
        {
            writer.WriteValue(value.ToString());
        }

        public override IxiNumber ReadJson(JsonReader reader, Type objectType, IxiNumber existingValue, bool hasExistingValue, JsonSerializer serializer)
        {
            string s = (string)reader.Value;

            return new IxiNumber(s);
        }
    }

    public class SignerPowSolution
    {
        public static readonly ulong maxTargetBits = 0x39FFFFFFFFFFFFFF; // Highest possible value for target bits with 64 byte hashes -> lowest difficulty
        private static readonly IxiNumber maxTargetHash = new IxiNumber(Crypto.stringToHash("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000FFFFFFFFFFFFFF00"));

        public ulong blockNum;
        public byte[] solution;
        public byte[] signingPubKey;

        [JsonIgnore]
        public IxianKeyPair keyPair; // keyPair is not trasmitted over the network

        private Address recipientAddress = null; // solverAddress is not trasmitted over the network
        private byte[] _checksum = null;
        public byte[] checksum
        {
            get
            {
                if (_checksum == null)
                {
                    var targetBlockHash = IxianHandler.getBlockHash(blockNum);
                    _checksum = solutionToHash(solution, blockNum, targetBlockHash, recipientAddress, signingPubKey);
                }
                return _checksum;
            }
            set
            {
                _checksum = value;
            }
        } // checksum is not trasmitted over the network

        private IxiNumber _difficulty = 0;

        [JsonConverter(typeof(IxiNumberConverter))]
        public IxiNumber difficulty
        {
            get
            {
                if (_difficulty == 0)
                {
                    _difficulty = hashToDifficulty(checksum);
                }
                return _difficulty;
            }
        }  // difficulty is not transmitted over the network

        private ulong _bits = 0;
        public ulong bits
        {
            get
            {
                if (_bits == 0)
                {
                    _bits = hashToBits(checksum);
                }
                return _bits;
            }
        }  // bits are not transmitted over the network

        public SignerPowSolution(Address recipientAddress)
        {
            this.recipientAddress = recipientAddress;
        }

        public SignerPowSolution(SignerPowSolution src)
        {
            blockNum = src.blockNum;

            solution = new byte[src.solution.Length];
            Array.Copy(src.solution, solution, solution.Length);

            byte[] signingPubKeyBytes = new byte[src.signingPubKey.Length];
            Array.Copy(src.signingPubKey, signingPubKeyBytes, signingPubKeyBytes.Length);
            signingPubKey = signingPubKeyBytes;

            byte[] recipientAddressBytes = new byte[src.recipientAddress.addressNoChecksum.Length];
            Array.Copy(src.recipientAddress.addressNoChecksum, recipientAddressBytes, recipientAddressBytes.Length);
            recipientAddress = new Address(recipientAddressBytes);

            keyPair = src.keyPair;

            if (src._checksum != null)
            {
                byte[] checksumBytes = new byte[src._checksum.Length];
                Array.Copy(src._checksum, checksumBytes, checksumBytes.Length);
                _checksum = checksumBytes;
            }

            _difficulty = src._difficulty;

            _bits = src._bits;
        }

        public byte[] sign(byte[] bytesToSign)
        {
            return CryptoManager.lib.getSignature(CryptoManager.lib.sha3_512sq(bytesToSign), keyPair.privateKeyBytes);
        }

        public SignerPowSolution(byte[] bytes, Address recipientAddress)
        {
            try
            {
                using (MemoryStream m = new MemoryStream(bytes))
                {
                    using (BinaryReader reader = new BinaryReader(m))
                    {
                        blockNum = reader.ReadIxiVarUInt();

                        int solutionLen = (int)reader.ReadIxiVarUInt();
                        if (solutionLen > 64)
                        {
                            throw new InvalidDataException("solution can't be larger than 64 bytes.");
                        }
                        solution = reader.ReadBytes(solutionLen);

                        int signingPubKeyLen = (int)reader.ReadIxiVarUInt();
                        if (signingPubKeyLen > 300)
                        {
                            throw new InvalidDataException("signingPubKeyLen can't be larger than 300 bytes.");
                        }
                        signingPubKey = reader.ReadBytes(signingPubKeyLen);

                        this.recipientAddress = recipientAddress;
                    }
                }
            }
            catch (Exception e)
            {
                Logging.warn("Cannot create PoW Solution from bytes: {0}", e.ToString());
                throw;
            }
        }

        public byte[] getBytes(bool compacted = false)
        {
            using (MemoryStream m = new MemoryStream(640))
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.WriteIxiVarInt(blockNum);

                    writer.WriteIxiVarInt(solution.Length);
                    writer.Write(solution);

                    byte[] pubKey = signingPubKey;
                    if (compacted)
                    {
                        if (signingPubKey.Length > 64)
                        {
                            pubKey = CryptoManager.lib.sha3_512sq(signingPubKey);
                        }
                    }
                    writer.WriteIxiVarInt(pubKey.Length);
                    writer.Write(pubKey);
#if TRACE_MEMSTREAM_SIZES
                    Logging.info(String.Format("SignerPowSolution::getBytes: {0}", m.Length));
#endif
                }

                return m.ToArray();
            }
        }


        public static byte[] bitsToHash(ulong bits)
        {
            if (bits > maxTargetBits)
            {
                throw new ArgumentOutOfRangeException(String.Format("bits can't be higher than maxTargetBits: {0} < {1}", bits, maxTargetBits));
            }
            byte[] targetBytes = BitConverter.GetBytes(bits);
            int firstPos = targetBytes[7];

            byte[] hash = new byte[firstPos + 8];
            Array.Copy(targetBytes, 0, hash, firstPos, 7);
            return hash;
        }

        public static ulong hashToBits(byte[] hashBytes)
        {
            int len = hashBytes.Length;
            if (len < 8)
            {
                byte[] tmpHash = new byte[8];
                Array.Copy(hashBytes, tmpHash, len);
                hashBytes = tmpHash;
                len = tmpHash.Length;
            }

            int zeroes = 0;
            while (zeroes < len - 7)
            {
                if (hashBytes[len - 1 - zeroes] != 0)
                {
                    break;
                }
                zeroes++;
            }
            int firstPos = len - zeroes - 7;

            byte[] targetBytes = new byte[8];
            Array.Copy(hashBytes, firstPos, targetBytes, 0, 7);
            targetBytes[7] = (byte)firstPos;

            return BitConverter.ToUInt64(targetBytes, 0);
        }

        // Returns hash in Little Endian
        public static byte[] difficultyToHash(IxiNumber difficulty)
        {
            if (difficulty < 0)
            {
                throw new ArgumentOutOfRangeException(String.Format("Difficulty can't be negative: {0}", difficulty));
            }
            if (difficulty.getAmount() < 1)
            {
                difficulty = new IxiNumber(new System.Numerics.BigInteger(1));
            }
            IxiNumber biHash = maxTargetHash / difficulty;
            return biHash.getBytes();
        }

        // Accepts hash in little endian
        public static IxiNumber hashToDifficulty(byte[] hashBytes)
        {
            IxiNumber biHashBytes = new IxiNumber(hashBytes);
            if (biHashBytes < 0)
            {
                return 0;
            }
            if (biHashBytes > maxTargetHash)
            {
                throw new OverflowException("Hash too large");
            }
            IxiNumber difficulty = maxTargetHash / biHashBytes;
            return difficulty;
        }

        public static ulong difficultyToBits(IxiNumber difficulty)
        {
            return hashToBits(difficultyToHash(difficulty));
        }

        public static IxiNumber bitsToDifficulty(ulong bits)
        {
            byte[] hash = bitsToHash(bits);
            return hashToDifficulty(hash);
        }

        public bool verifySolution(IxiNumber minimumDifficulty)
        {
            if(difficulty >= minimumDifficulty)
            {
                return true;
            }
            return false;
        }

        public static bool validateHash(byte[] hash, IxiNumber minimumDifficulty)
        {
            if(hashToDifficulty(hash) >= minimumDifficulty)
            {
                return true;
            }
            return false;
        }

        // Verify nonce
        public static bool verifySolution(byte[] solution, ulong blockNum, byte[] blockHash, Address recipientAddress, byte[] signingPubKey, IxiNumber difficulty)
        {
            byte[] hash = solutionToHash(solution, blockNum, blockHash, recipientAddress, signingPubKey);
            if(hash == null)
            {
                return false;
            }

            if (validateHash(hash, difficulty) == true)
            {
                // Hash is valid
                return true;
            }

            return false;
        }

        public static byte[] solutionToHash(byte[] solution, ulong blockNum, byte[] blockHash, Address recipientAddress, byte[] signingPubKey)
        {
            if (solution == null || solution.Length < 1 || solution.Length > 64)
            {
                return null;
            }

            byte[] signingPubKeyHash = signingPubKey;
            if(signingPubKey.Length > 64)
            {
                signingPubKeyHash = CryptoManager.lib.sha3_512sq(signingPubKey);
            }

            // TODO protect against spamming with invalid nonce/block_num
            byte[] blockNumBytes = blockNum.GetIxiVarIntBytes();
            byte[] challengeData = new byte[blockNumBytes.Length + blockHash.Length + recipientAddress.addressNoChecksum.Length + signingPubKeyHash.Length + solution.Length];
            
            System.Buffer.BlockCopy(blockNumBytes, 0, challengeData, 0, blockNumBytes.Length);
            System.Buffer.BlockCopy(blockHash, 0, challengeData, blockNumBytes.Length, blockHash.Length);
            System.Buffer.BlockCopy(recipientAddress.addressNoChecksum, 0, challengeData, blockNumBytes.Length + blockHash.Length, recipientAddress.addressNoChecksum.Length);
            System.Buffer.BlockCopy(signingPubKeyHash, 0, challengeData, blockNumBytes.Length + blockHash.Length + recipientAddress.addressNoChecksum.Length, signingPubKeyHash.Length);
            System.Buffer.BlockCopy(solution, 0, challengeData, blockNumBytes.Length + blockHash.Length + recipientAddress.addressNoChecksum.Length + signingPubKeyHash.Length, solution.Length);

            return CryptoManager.lib.sha3_512sq(challengeData);
        }
    }
}

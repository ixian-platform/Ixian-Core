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
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Threading;

namespace IXICore.Miner
{
    public class SignerPowMiner
    {
        private const int nonceLength = 32;

        IxianKeyPair currentKeyPair = null;
        ulong keyPairGeneratedBlockHeight = 0;
        Block activeBlock = null;
        private ulong currentBlockNum = 0; // Mining block number
        private SignerPowSolution lastSignerPowSolution = null;
        private ulong startedSolvingBlockHeight = 0; // Started solving time
        private IxiNumber solvingDifficulty = 0;

        // Stats
        public ulong lastHashRate { get; private set; } = 0; // Last reported hash rate
        private ulong hashesPerSecond = 0; // Total number of hashes per second
        private DateTime lastStatTime; // Last statistics output time
        public static long solutionsFound { get; private set; } = 0;

        public bool pause = true; // Flag to toggle miner activity
        private bool started = false;
        private bool shouldStop = false; // flag to signal shutdown of threads


        [ThreadStatic] private static IxianKeyPair activeKeyPair = null;
        [ThreadStatic] private static byte[] activeBlockChallenge = null;
        [ThreadStatic] private static ulong activeBlockChallengeBlockNum = 0;
        [ThreadStatic] private static int activeBlockChallengeHeaderLength = 0;

        [ThreadStatic] private static byte[] curNonce = null; // Used for random nonce


        SortedDictionary<ulong, SignerPowSolution> solutions = new();

        public SignerPowMiner()
        {
            lastStatTime = DateTime.UtcNow;

        }

        // Starts the mining threads
        public bool Start(int miningThreads)
        {
            if (started)
            {
                return false;
            }
            started = true;

            if (IxianHandler.isTestNet)
            {
                miningThreads = 1;
            }
            Logging.info("Starting SignerPowMiner with {0} threads on {1} logical processors.", miningThreads, Environment.ProcessorCount);

            shouldStop = false;

            // Start primary mining thread
            Thread manager_thread = new Thread(ThreadLoop);
            manager_thread.Name = "SignerPowMiner_Manager_Thread";
            manager_thread.IsBackground = true;
            manager_thread.Start();

            // Start secondary worker threads
            for (int i = 0; i < miningThreads; i++)
            {
                Thread worker_thread = new Thread(SecondaryThreadLoop);
                worker_thread.Name = "SignerPowMiner_Worker_Thread_#" + i.ToString();
                worker_thread.IsBackground = true;
                worker_thread.Start();
            }

            return true;
        }

        // Signals all the mining threads to stop
        public bool Stop()
        {
            shouldStop = true;
            started = false;
            return true;
        }

        private void ThreadLoop()
        {
            while (!shouldStop)
            {
                try
                {
                    UpdateActiveBlock();
                    UpdateStats();
                    RemoveExpiredSolutions();
                }
                catch (Exception e)
                {
                    Logging.error("Exception occured in SignerPowMiner.threadLoop(): " + e);
                }
                Thread.Sleep(5000);
            }
        }

        private void ResetStats()
        {
            lastStatTime = DateTime.UtcNow;
            lastHashRate = hashesPerSecond;
            hashesPerSecond = 0;
        }

        private void UpdateStats()
        {
            TimeSpan timeSinceLastStat = DateTime.UtcNow - lastStatTime;
            if (timeSinceLastStat.TotalSeconds > 5)
            {
                lastStatTime = DateTime.UtcNow;
                lastHashRate = hashesPerSecond / (ulong)timeSinceLastStat.TotalSeconds;
                hashesPerSecond = 0;
            }
        }

        private void SecondaryThreadLoop()
        {
            while (!shouldStop)
            {
                try
                {
                    if (currentBlockNum == 0)
                    {
                        Thread.Sleep(500);
                        continue;
                    }

                    CalculateHash();
                }
                catch (Exception e)
                {
                    Thread.Sleep(500);
                    Logging.error("Exception occured in SignerPowMiner.secondaryThreadLoop(): " + e);
                }
            }
        }

        private void UpdateActiveBlock()
        {
            if (pause)
            {
                currentBlockNum = 0;
                ResetStats();
                return;
            }

            Block candidateBlock = IxianHandler.getLastBlock();

            if (candidateBlock == null)
            {
                // No blocks, Not ready yet
                return;
            }

            ulong lastBlockHeight = candidateBlock.blockNum;
            ulong minCalculationBlockCount = ConsensusConfig.getPlPowMinCalculationBlockTime(IxianHandler.getLastBlockVersion());

            if (currentBlockNum > 0)
            {
                lock (solutions)
                {
                    // Check if we're mining for at least X blocks and that the blockchain isn't stuck
                    if ((solutions.Count > 0 && solutions.Keys.Max() >= startedSolvingBlockHeight)
                        && lastBlockHeight - startedSolvingBlockHeight >= minCalculationBlockCount
                        && IxianHandler.getTimeSinceLastBlock() < CoreConfig.blockSignaturePlCheckTimeout)
                    {
                        // Stop mining on all threads
                        currentBlockNum = 0;
                        ResetStats();
                        return;
                    }
                }
            }
            else
            {
                ulong calculationInterval = ConsensusConfig.getPlPowCalculationInterval();

                if (candidateBlock.blockNum + calculationInterval < IxianHandler.getHighestKnownNetworkBlockHeight())
                {
                    // Catching up to the network
                    return;
                }

                if (lastSignerPowSolution != null
                    && lastSignerPowSolution.blockNum + calculationInterval > lastBlockHeight
                    && IxianHandler.getTimeSinceLastBlock() < CoreConfig.blockSignaturePlCheckTimeout)
                {
                    // Cooldown
                    return;
                }
            }
            
            if (currentBlockNum == candidateBlock.blockNum
                && activeBlock.blockChecksum.SequenceEqual(candidateBlock.blockChecksum))
            {
                // already mining this block
                return;
            }

            if (keyPairGeneratedBlockHeight == 0
                || keyPairGeneratedBlockHeight + minCalculationBlockCount < lastBlockHeight)
            {
                currentKeyPair = CryptoManager.lib.generateKeys(2048, 2); // TODO move to config
                keyPairGeneratedBlockHeight = lastBlockHeight;
            }

            if (currentBlockNum == 0)
            {
                startedSolvingBlockHeight = lastBlockHeight;
            }

            activeBlock = candidateBlock;
            currentBlockNum = activeBlock.blockNum;

            solvingDifficulty = IxianHandler.getMinSignerPowDifficulty(IxianHandler.getLastBlockHeight() + 1, IxianHandler.getLastBlockVersion(), 0);

            if (solvingDifficulty < 0)
            {
                Logging.error("SignerPowMiner: Solving difficulty is negative.");
                currentBlockNum = 0;
            }

            lock (solutions)
            {
                foreach (var solution in solutions.ToList())
                {
                    if (solution.Key >= currentBlockNum)
                    {
                        solutions.Remove(solution.Key);
                    }
                }
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private byte[] RandomNonce(int length)
        {
            if (curNonce == null)
            {
                curNonce = new byte[length];
                using var rng = RandomNumberGenerator.Create();
                rng.GetBytes(curNonce);
            }
            bool inc_next = true;
            length = curNonce.Length;
            for (int pos = length - 1; inc_next == true && pos > 0; pos--)
            {
                if (curNonce[pos] < 0xFF)
                {
                    inc_next = false;
                    curNonce[pos]++;
                }
                else
                {
                    curNonce[pos] = 0;
                }
            }
            return curNonce;
        }

        private byte[] PrepareChallenge(Block block)
        {
            byte[] blockNumBytes = block.blockNum.GetIxiVarIntBytes();
            byte[] blockChecksum = block.blockChecksum;

            byte[] recipientAddress = IxianHandler.primaryWalletAddress.addressNoChecksum;
            activeKeyPair = currentKeyPair;
            byte[] activePubKeyHash;
            if (activeKeyPair.publicKeyBytes.Length > 64)
            {
                activePubKeyHash = CryptoManager.lib.sha3_512sq(activeKeyPair.publicKeyBytes);
            }
            else
            {
                activePubKeyHash = activeKeyPair.publicKeyBytes;
            }

            byte[] challenge = new byte[blockNumBytes.Length + blockChecksum.Length + recipientAddress.Length + activePubKeyHash.Length + nonceLength];
            Buffer.BlockCopy(blockNumBytes, 0, challenge, 0, blockNumBytes.Length);
            Buffer.BlockCopy(blockChecksum, 0, challenge, blockNumBytes.Length, blockChecksum.Length);
            Buffer.BlockCopy(recipientAddress, 0, challenge, blockNumBytes.Length + blockChecksum.Length, recipientAddress.Length);
            Buffer.BlockCopy(activePubKeyHash, 0, challenge, blockNumBytes.Length + blockChecksum.Length + recipientAddress.Length, activePubKeyHash.Length);

            return challenge;
        }

        // PoW = sha3_512sq(BlockNum + BlockChecksum + RecipientAddress + pubKeyHash + Nonce)
        public void CalculateHash(byte[] nonce = null)
        {
            if (currentBlockNum == 0)
            {
                return;
            }

            if (nonce == null)
            {
                nonce = RandomNonce(nonceLength);
            }

            var block = activeBlock;

            if (activeBlockChallengeBlockNum != block.blockNum)
            {
                activeBlockChallenge = PrepareChallenge(block);
                activeBlockChallengeBlockNum = block.blockNum;
                activeBlockChallengeHeaderLength = activeBlockChallenge.Length - nonceLength;
            }

            nonce.AsSpan().CopyTo(activeBlockChallenge.AsSpan(activeBlockChallengeHeaderLength, nonceLength));
            byte[] hash = CryptoManager.lib.sha3_512sq(activeBlockChallenge);

            hashesPerSecond++;

            ProcessSolution(hash, nonce);
        }

        // Process found solution and temporarily store it if valid
        private void ProcessSolution(byte[] hash, byte[] nonce)
        {
            // pre-validate hash
            if (hash[hash.Length - 1] != 0
                || hash[hash.Length - 2] != 0)
            {
                return;
            }

            IxiNumber hashDifficulty = SignerPowSolution.hashToDifficulty(hash);

            if (hashDifficulty < solvingDifficulty)
            {
                return;
            }

            // valid hash
            Logging.info("SOLUTION FOUND FOR BLOCK #{0} - {1} > {2} - {3}", activeBlockChallengeBlockNum, hashDifficulty, solvingDifficulty, Crypto.hashToString(hash));

            if (activeBlockChallengeBlockNum == currentBlockNum)
            {
                solvingDifficulty = hashDifficulty;
            }

            byte[] nonceCopy = GC.AllocateUninitializedArray<byte>(nonce.Length);
            nonce.AsSpan().CopyTo(nonceCopy);

            SignerPowSolution signerPow = new SignerPowSolution(IxianHandler.primaryWalletAddress)
            {
                blockNum = activeBlockChallengeBlockNum,
                solution = nonceCopy,
                keyPair = activeKeyPair,
                signingPubKey = activeKeyPair.publicKeyBytes
            };

            lock (solutions)
            {
                lastSignerPowSolution = signerPow;
                solutions[activeBlockChallengeBlockNum] = signerPow;
            }

            solutionsFound++;
        }

        private void RemoveExpiredSolutions()
        {
            lock (solutions)
            {
                var lastBlockVersion = IxianHandler.getLastBlockVersion();
                var lastBlockHeight = IxianHandler.getLastBlockHeight();
                foreach (var solution in solutions.ToList())
                {
                    if (solution.Key + ConsensusConfig.getPlPowBlocksValidity(lastBlockVersion) - 1 < lastBlockHeight)
                    {
                        solutions.Remove(solution.Key);
                    }
                }
            }
        }

        /// <summary>
        /// Retrieves all mined SignerPoW solutions within the specified block height range (exclusive).
        /// </summary>
        /// <param name="fromBlockHeight">
        /// Lower bound (exclusive). Only solutions with a block height greater than this value are included.
        /// </param>
        /// <param name="toBlockHeight">
        /// Upper bound (exclusive). Ony solutions with a block height less than this value are included.
        /// Specify 0 to include all solutions above <paramref name="fromBlockHeight"/> with no upper limit.
        /// </param>
        /// <returns>
        /// A list of <see cref="SignerPowSolution"/> objects matching the specified range.
        /// </returns>
        public IEnumerable<SignerPowSolution> GetSolutions(ulong fromBlockHeight, ulong toBlockHeight)
        {
            lock (solutions)
            {
                return solutions.Values
                    .Where(x => x.blockNum > fromBlockHeight && (toBlockHeight == 0 || x.blockNum < toBlockHeight))
                    .ToList();
            }
        }

        /// <summary>
        /// Retrieves the highest-difficulty SignerPoW solution within the specified block height range (exclusive).
        /// </summary>
        /// <param name="fromBlockHeight">
        /// Lower bound (exclusive). Only solutions with a block height greater than this value are included.
        /// </param>
        /// <param name="toBlockHeight">
        /// Upper bound (exclusive). Ony solutions with a block height less than this value are included.
        /// Specify 0 to include all solutions above <paramref name="fromBlockHeight"/> with no upper limit.
        /// </param>
        /// <returns>
        /// The <see cref="SignerPowSolution"/> with the highest difficulty within the range, or <c>null</c> if none exist.
        /// </returns>
        public SignerPowSolution? GetBestSolution(ulong fromBlockHeight, ulong toBlockHeight)
        {
            return GetSolutions(fromBlockHeight, toBlockHeight).OrderByDescending(x => x.difficulty).FirstOrDefault();
        }
    }
}
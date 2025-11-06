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
using System.Collections.Concurrent;
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
        private ulong currentBlockHeight = 0; // Mining block number
        private ulong lastFoundBlockHeight = 0;
        private ulong startedSolvingBlockHeight = 0; // Started solving time
        public IxiNumber solvingDifficulty { get; private set; } = 0;
        private IxiNumber activeSolvingDifficulty = 0;

        // Stats
        public ulong lastHashRate { get; private set; } = 0; // Last reported hash rate
        private ulong hashesPerSecond = 0; // Total number of hashes per second
        private DateTime lastStatTime; // Last statistics output time
        public long solutionsFound { get; private set; } = 0;

        public volatile bool pause = true; // Flag to toggle miner activity
        private volatile bool started = false;
        private volatile bool shouldStop = false; // flag to signal shutdown of threads

        ConcurrentDictionary<ulong, SignerPowSolution> solutions = new();

        private readonly object _stateLock = new();

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
                    Logging.error("Exception occurred in SignerPowMiner.ThreadLoop(): " + e);
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
            ulong blockHeight = 0;
            IxianKeyPair keyPair = null;
            byte[] challenge = null;
            while (!shouldStop)
            {
                try
                {
                    if (currentBlockHeight == 0)
                    {
                        Thread.Sleep(500);
                        continue;
                    }

                    if (blockHeight != currentBlockHeight)
                    {
                        lock (_stateLock)
                        {
                            var block = activeBlock;
                            keyPair = currentKeyPair;
                            challenge = PrepareChallenge(block.blockNum, block.blockChecksum, keyPair, RandomNonce(nonceLength));
                            blockHeight = block.blockNum;
                        }
                    }

                    CalculateHash(blockHeight, keyPair, challenge);
                }
                catch (Exception e)
                {
                    Thread.Sleep(500);
                    Logging.error("Exception occurred in SignerPowMiner.secondaryThreadLoop(): " + e);
                }
            }
        }

        private void UpdateActiveBlock()
        {
            if (pause)
            {
                currentBlockHeight = 0;
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

            if (currentBlockHeight > 0)
            {
                // Check if we're mining for at least X blocks and that the blockchain isn't stuck
                if ((lastFoundBlockHeight >= startedSolvingBlockHeight)
                    && lastBlockHeight - startedSolvingBlockHeight >= minCalculationBlockCount
                    && IxianHandler.getTimeSinceLastBlock() < CoreConfig.blockSignaturePlCheckTimeout)
                {
                    // Stop mining on all threads
                    currentBlockHeight = 0;
                    ResetStats();
                    return;
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

                if (lastBlockHeight > calculationInterval
                    && lastFoundBlockHeight + calculationInterval > lastBlockHeight
                    && IxianHandler.getTimeSinceLastBlock() < CoreConfig.blockSignaturePlCheckTimeout)
                {
                    // Cooldown
                    return;
                }
            }

            if (currentBlockHeight == candidateBlock.blockNum
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

            if (currentBlockHeight == 0)
            {
                startedSolvingBlockHeight = lastBlockHeight;
            }

            solvingDifficulty = IxianHandler.getMinSignerPowDifficulty(IxianHandler.getLastBlockHeight() + 1, IxianHandler.getLastBlockVersion(), 0);

            foreach (var solution in solutions)
            {
                if (solution.Key >= candidateBlock.blockNum)
                {
                    solutions.TryRemove(solution.Key, out _);
                }
            }

            lock (_stateLock)
            {
                solutions[candidateBlock.blockNum] = new SignerPowSolution(IxianHandler.primaryWalletAddress)
                {
                    blockNum = candidateBlock.blockNum,
                    solution = new byte[] { 0 },
                    keyPair = currentKeyPair,
                    signingPubKey = currentKeyPair.publicKeyBytes
                };

                activeBlock = candidateBlock;
                currentBlockHeight = candidateBlock.blockNum;
                activeSolvingDifficulty = solvingDifficulty;
            }

            if (solvingDifficulty < 0)
            {
                Logging.error("SignerPowMiner: Solving difficulty is negative.");
                currentBlockHeight = 0;
            }
        }

        private byte[] RandomNonce(int length)
        {
            byte[] nonce = new byte[length];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(nonce);
            return nonce;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void IncreaseNonce(byte[] challenge, int nonceLength)
        {
            bool inc_next = true;
            var length = challenge.Length;
            var headerLength = challenge.Length - nonceLength;
            for (int pos = length - 1; inc_next == true && pos > headerLength; pos--)
            {
                if (challenge[pos] < 0xFF)
                {
                    inc_next = false;
                    challenge[pos]++;
                }
                else
                {
                    challenge[pos] = 0;
                }
            }
        }

        private byte[] PrepareChallenge(ulong blockHeight, byte[] blockHash, IxianKeyPair keyPair, byte[] nonce)
        {
            byte[] blockNumBytes = blockHeight.GetIxiVarIntBytes();
            byte[] blockChecksum = blockHash;

            byte[] recipientAddress = IxianHandler.primaryWalletAddress.addressNoChecksum;

            byte[] activePubKeyHash;
            if (keyPair.publicKeyBytes.Length > 64)
            {
                activePubKeyHash = CryptoManager.lib.sha3_512sq(keyPair.publicKeyBytes);
            }
            else
            {
                activePubKeyHash = keyPair.publicKeyBytes;
            }

            byte[] challenge = new byte[blockNumBytes.Length + blockChecksum.Length + recipientAddress.Length + activePubKeyHash.Length + nonce.Length];
            Buffer.BlockCopy(blockNumBytes, 0, challenge, 0, blockNumBytes.Length);
            Buffer.BlockCopy(blockChecksum, 0, challenge, blockNumBytes.Length, blockChecksum.Length);
            Buffer.BlockCopy(recipientAddress, 0, challenge, blockNumBytes.Length + blockChecksum.Length, recipientAddress.Length);
            Buffer.BlockCopy(activePubKeyHash, 0, challenge, blockNumBytes.Length + blockChecksum.Length + recipientAddress.Length, activePubKeyHash.Length);
            Buffer.BlockCopy(nonce, 0, challenge, blockNumBytes.Length + blockChecksum.Length + recipientAddress.Length + activePubKeyHash.Length, nonce.Length);

            return challenge;
        }

        // PoW = sha3_512sq(BlockNum + BlockChecksum + RecipientAddress + pubKeyHash + Nonce)
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void CalculateHash(ulong blockHeight, IxianKeyPair keyPair, byte[] challenge)
        {
            IncreaseNonce(challenge, nonceLength);

            hashesPerSecond++;

            byte[] hash = CryptoManager.lib.sha3_512sq(challenge);
            var status = ProcessSolution(hash, challenge, nonceLength, activeSolvingDifficulty, blockHeight, keyPair);

            if (status.difficulty > activeSolvingDifficulty)
            {
                activeSolvingDifficulty = status.difficulty;
                lastFoundBlockHeight = blockHeight;
            }
        }

        // Process found solution and temporarily store it if valid
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private (IxiNumber difficulty, SignerPowSolution? solution) ProcessSolution(byte[] hash,
                                                                                    byte[] challengeWithNonce,
                                                                                    int nonceLen,
                                                                                    IxiNumber solvingDifficulty,
                                                                                    ulong challengeBlockNum,
                                                                                    IxianKeyPair keyPair)
        {
            // pre-validate hash
            if (hash[hash.Length - 1] != 0
                || hash[hash.Length - 2] != 0)
            {
                return (0, null);
            }

            IxiNumber hashDifficulty = SignerPowSolution.hashToDifficulty(hash);

            if (hashDifficulty < solvingDifficulty)
            {
                return (hashDifficulty, null);
            }

            // valid hash
            Logging.info("SOLUTION FOUND FOR BLOCK #{0} - {1} > {2} - {3}", challengeBlockNum, hashDifficulty, solvingDifficulty, Crypto.hashToString(hash));

            byte[] nonceCopy = GC.AllocateUninitializedArray<byte>(nonceLen);
            challengeWithNonce.AsSpan(challengeWithNonce.Length - nonceLen).CopyTo(nonceCopy);

            SignerPowSolution signerPow = new SignerPowSolution(IxianHandler.primaryWalletAddress)
            {
                blockNum = challengeBlockNum,
                solution = nonceCopy,
                keyPair = keyPair,
                signingPubKey = keyPair.publicKeyBytes
            };


            lock (_stateLock)
            {
                solutionsFound++;

                if (solutions.TryGetValue(challengeBlockNum, out var solution))
                {
                    if (solution.solution.Length > 1
                        && solution.difficulty >= hashDifficulty)
                    {
                        return (hashDifficulty, null);
                    }
                }

                solutions[challengeBlockNum] = signerPow;
            }

            return (hashDifficulty, signerPow);
        }

        private void RemoveExpiredSolutions()
        {
            var lastBlockVersion = IxianHandler.getLastBlockVersion();
            var lastBlockHeight = IxianHandler.getLastBlockHeight();
            foreach (var solution in solutions)
            {
                if (solution.Key + ConsensusConfig.getPlPowBlocksValidity(lastBlockVersion) - 1 < lastBlockHeight)
                {
                    solutions.TryRemove(solution.Key, out _);
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
            return solutions.Values
                .Where(x => x.solution.Length > 1 && x.blockNum > fromBlockHeight && (toBlockHeight == 0 || x.blockNum < toBlockHeight))
                .OrderBy(x => x.blockNum);
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

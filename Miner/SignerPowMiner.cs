// Copyright (C) 2017-2025 Ixian OU
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
using System.Linq;
using System.Security.Cryptography;
using System.Threading;

namespace IXICore.Miner
{
    class SignerPowMiner
    {
        public bool pause = false; // Flag to toggle miner activity

        IxianKeyPair currentKeyPair = null;
        Block activeBlock = null;
        private ulong currentBlockNum = 0; // Mining block number
        public SignerPowSolution lastSignerPowSolution { get; private set; } = null;
        private ulong startedSolvingBlockHeight = 0; // Started solving time
        private ulong previousSolutionBlockHeight = 0;
        private IxiNumber solvingDifficulty = 0;

        public ulong lastHashRate { get; private set; } = 0; // Last reported hash rate
        private ulong hashesPerSecond = 0; // Total number of hashes per second
        private DateTime lastStatTime; // Last statistics output time

        private bool started = false;
        private bool shouldStop = false; // flag to signal shutdown of threads


        bool blockReadyForMining = false;

        [ThreadStatic] private static IxianKeyPair activeKeyPair = null;
        [ThreadStatic] private static byte[] activeBlockChallenge = null;
        [ThreadStatic] private static ulong activeBlockChallengeBlockNum = 0;

        [ThreadStatic] private static byte[] curNonce = null; // Used for random nonce

        public static long solutionsFound { get; private set; } = 0;

        public SignerPowMiner()
        {
            lastStatTime = DateTime.UtcNow;

        }

        // Starts the mining threads
        public bool start(int miningThreads)
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
            Logging.info("Starting Presence List miner with {0} threads on {1} logical processors.", miningThreads, Environment.ProcessorCount);

            shouldStop = false;

            // Start primary mining thread
            Thread manager_thread = new Thread(threadLoop);
            manager_thread.Name = "PresenceListMiner_Manager_Thread";
            manager_thread.Start();

            // Start secondary worker threads
            for (int i = 0; i < miningThreads; i++)
            {
                Thread worker_thread = new Thread(secondaryThreadLoop);
                worker_thread.Name = "PresenceListMiner_Worker_Thread_#" + i.ToString();
                worker_thread.Start();
            }

            return true;
        }

        // Signals all the mining threads to stop
        public bool stop()
        {
            shouldStop = true;
            started = false;
            return true;
        }

        private void threadLoop()
        {
            while (!shouldStop)
            {
                try
                {
                    searchForBlock();

                    // Output mining stats
                    TimeSpan timeSinceLastStat = DateTime.UtcNow - lastStatTime;
                    if (timeSinceLastStat.TotalSeconds > 5)
                    {
                        lastStatTime = DateTime.UtcNow;
                        lastHashRate = hashesPerSecond / (ulong)timeSinceLastStat.TotalSeconds;
                        hashesPerSecond = 0;
                    }

                    sendFoundSolution();
                }
                catch (Exception e)
                {
                    Logging.error("Exception occured in SignerPowMiner.threadLoop(): " + e);
                }
                Thread.Sleep(5000);
            }
        }

        private void secondaryThreadLoop()
        {
            while (!shouldStop)
            {
                try
                {
                    if (blockReadyForMining == false)
                    {
                        Thread.Sleep(500);
                        continue;
                    }

                    calculatePow();
                }
                catch (Exception e)
                {
                    Thread.Sleep(500);
                    Logging.error("Exception occured in SignerPowMiner.secondaryThreadLoop(): " + e);
                }
            }
        }

        public void forceSearchForBlock()
        {
            blockReadyForMining = false;
            lastSignerPowSolution = null;
        }


        // Returns the most recent fully accepted block
        private void searchForBlock()
        {
            Block candidateBlock = IxianHandler.getLastBlock();

            if (candidateBlock == null)
            {
                // No blocks, Not ready yet
                return;
            }

            if (pause
                || PresenceList.myPresenceType == 'W'
                || candidateBlock.version < BlockVer.v10)
            {
                // paused or not synced/worker node or lower than v10
                blockReadyForMining = false;
                currentBlockNum = 0;
                lastStatTime = DateTime.UtcNow;
                lastHashRate = hashesPerSecond;
                hashesPerSecond = 0;
                return;
            }

            uint blockOffset = 7;

            if (candidateBlock.blockNum <= 14)
            {
                candidateBlock = IxianHandler.getBlockHeader(1);
            }
            else
            {
                candidateBlock = IxianHandler.getBlockHeader(candidateBlock.blockNum - blockOffset);
            }

            if (candidateBlock == null)
            {
                // Not ready yet
                return;
            }

            solvingDifficulty = IxianHandler.getMinSignerPowDifficulty(IxianHandler.getLastBlockHeight() + 1, IxianHandler.getLastBlockVersion(), 0);

            if (solvingDifficulty < 0)
            {
                Logging.error("SignerPowMiner: Solving difficulty is negative.");
                return;
            }

            if (blockReadyForMining
                && currentBlockNum == candidateBlock.blockNum
                && activeBlock.blockChecksum.SequenceEqual(candidateBlock.blockChecksum))
            {
                // already mining this block
                return;
            }

            activeBlock = candidateBlock;
            currentBlockNum = candidateBlock.blockNum;

            ulong calculationInterval = ConsensusConfig.getPlPowCalculationInterval(IxianHandler.getLastBlockVersion());

            ulong highestNetworkBlockHeight = IxianHandler.getHighestKnownNetworkBlockHeight();
            if (candidateBlock.blockNum + calculationInterval + blockOffset < highestNetworkBlockHeight)
            {
                // Catching up to the network
                return;
            }

            var submittedSolution = PresenceList.getPowSolution();

            if (lastSignerPowSolution != null)
            {
                if (IxianHandler.getTimeSinceLastBlock() < CoreConfig.blockSignaturePlCheckTimeout
                    && lastSignerPowSolution.blockNum + calculationInterval > highestNetworkBlockHeight
                    && (submittedSolution != null && solvingDifficulty <= submittedSolution.difficulty))
                {
                    // If the chain isn't stuck and we've already processed PoW within the interval
                    return;
                }

                if (previousSolutionBlockHeight == lastSignerPowSolution.blockNum)
                {
                    return;
                }

                previousSolutionBlockHeight = lastSignerPowSolution.blockNum;
            }

            startedSolvingBlockHeight = highestNetworkBlockHeight;

            currentKeyPair = CryptoManager.lib.generateKeys(2048, 2); // TODO move to config with v11
            activeBlock = candidateBlock;
            currentBlockNum = candidateBlock.blockNum;

            blockReadyForMining = true;

            return;
        }

        private byte[] randomNonce(int length)
        {
            if (curNonce == null)
            {
                curNonce = new byte[length];
                RandomNumberGenerator.Create().GetBytes(curNonce);
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

        private void calculatePow()
        {
            // PoW = sha3_512sq(BlockNum + BlockChecksum + RecipientAddress + pubKeyHash + Nonce)
            byte[] nonce = randomNonce(64);
            if (activeBlockChallengeBlockNum != currentBlockNum)
            {
                var block = activeBlock;
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
                activeBlockChallengeBlockNum = currentBlockNum;

                activeBlockChallenge = new byte[blockNumBytes.Length + blockChecksum.Length + recipientAddress.Length + activePubKeyHash.Length + 64];
                System.Buffer.BlockCopy(blockNumBytes, 0, activeBlockChallenge, 0, blockNumBytes.Length);
                System.Buffer.BlockCopy(blockChecksum, 0, activeBlockChallenge, blockNumBytes.Length, blockChecksum.Length);
                System.Buffer.BlockCopy(recipientAddress, 0, activeBlockChallenge, blockNumBytes.Length + blockChecksum.Length, recipientAddress.Length);
                System.Buffer.BlockCopy(activePubKeyHash, 0, activeBlockChallenge, blockNumBytes.Length + blockChecksum.Length + recipientAddress.Length, activePubKeyHash.Length);
            }
            System.Buffer.BlockCopy(nonce, 0, activeBlockChallenge, activeBlockChallenge.Length - 64, nonce.Length);
            byte[] hash = CryptoManager.lib.sha3_512sq(activeBlockChallenge);

            hashesPerSecond++;

            handleFoundSolution(hash, nonce);
        }

        // Process found solution and pass it to main thread for further processing
        private void handleFoundSolution(byte[] hash, byte[] nonce)
        {
            // pre-validate hash
            if (hash[hash.Length - 1] != 0
                || hash[hash.Length - 2] != 0)
            {
                return;
            }

            IxiNumber hashDifficulty = SignerPowSolution.hashToDifficulty(hash);

            if (hashDifficulty >= solvingDifficulty)
            {
                // valid hash
                var lastSolution = lastSignerPowSolution;
                if (lastSolution == null
                    || lastSolution.blockNum != activeBlockChallengeBlockNum
                    || (lastSolution.blockNum == activeBlockChallengeBlockNum && hashDifficulty > lastSolution.difficulty))
                {
                    Logging.info("SOLUTION FOUND FOR BLOCK #{0} - {1} > {2} - {3}", activeBlock.blockNum, hashDifficulty, solvingDifficulty, Crypto.hashToString(hash));

                    byte[] nonceCopy = new byte[nonce.Length];
                    Array.Copy(nonce, nonceCopy, nonce.Length);

                    SignerPowSolution signerPow = new SignerPowSolution(IxianHandler.primaryWalletAddress)
                    {
                        blockNum = activeBlockChallengeBlockNum,
                        solution = nonceCopy,
                        keyPair = activeKeyPair,
                        signingPubKey = activeKeyPair.publicKeyBytes
                    };

                    lastSignerPowSolution = signerPow;
                    solvingDifficulty = hashDifficulty;
                }
                solutionsFound++;
            }
        }

        // Broadcasts the solution to the network
        private void sendFoundSolution()
        {
            var newSolution = lastSignerPowSolution;
            if (newSolution == null)
            {
                return;
            }

            var solution = PresenceList.getPowSolution();
            if (solution != null)
            {
                if (newSolution.difficulty <= solution.difficulty
                    && solution.blockNum + ConsensusConfig.getPlPowBlocksValidity(IxianHandler.getLastBlockVersion()) - 1 > IxianHandler.getHighestKnownNetworkBlockHeight()
                    && solution.difficulty > IxianHandler.getMinSignerPowDifficulty(IxianHandler.getLastBlockHeight() + 1, IxianHandler.getLastBlockVersion(), 0))
                {
                    // If the new solution has a lower difficulty than the previously submitted solution and the previously submitted solution is still valid

                    // Check if we're mining for at least X minutes and that the blockchain isn't stuck
                    if (IxianHandler.getHighestKnownNetworkBlockHeight() - startedSolvingBlockHeight >= ConsensusConfig.getPlPowMinCalculationBlockTime(IxianHandler.getLastBlockVersion())
                        && previousSolutionBlockHeight != newSolution.blockNum
                        && IxianHandler.getTimeSinceLastBlock() < CoreConfig.blockSignaturePlCheckTimeout)
                    {
                        // Reset the blockReadyForMining, to stop mining on all threads
                        blockReadyForMining = false;
                        currentBlockNum = 0;
                    }
                    return;
                }
            }

            PresenceList.setPowSolution(newSolution);

            IxianHandler.onSignerSolutionFound();
        }
    }
}

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
using System.Numerics;
using System.Text;

namespace IXICore
{
    /// <summary>
    /// Basic Ixian (compile-time) configuration values.
    /// </summary>
    public class ConsensusConfig
    {
        /// <summary>
        ///  Target Block generation interval, in seconds.
        ///  Default value for Ixian DLT is 30.
        /// </summary>
        /// <remarks>
        ///  The DLT will strive to generate new Blocks according to this value.
        /// </remarks>
        public static readonly int blockGenerationInterval = 30;

        /// <summary>
        ///  Minimum valid time difference between previous and newly generated block, in seconds.
        ///  Default value for Ixian DLT is 30.
        /// </summary>
        public static readonly int minBlockTimeDifference = 30;

        /// <summary>
        ///  Maximum valid time difference between newly generated block and network time, in seconds.
        ///  Default value for Ixian DLT is 60.
        /// </summary>
        /// <remarks>
        ///  If block's time is higher than the Clock.getNetworkTimestamp() + maxBlockNetworkTimeDifference, the block will be invalid.
        /// </remarks>
        public static readonly int maxBlockNetworkTimeDifference = 60;

        /// <summary>
        ///  Number of blocks this particular is required to keep before discarding older blocks. Blocks older than the redaction window can be discarded.
        /// </summary>
        /// <remarks>
        ///  The redacted window, together with the block generation inverval specify that blocks should be kept for approximately 15 days.
        /// </remarks>
        public static ulong redactedWindowSize = 43200;
        /// <summary>
        ///  Number of blocks all Master Nodes are required to keep before discarding older blocks. Blocks older than the redaction window can be discarded.
        /// </summary>
        /// <remarks>
        ///  The redacted window, together with the block generation inverval specify that blocks should be kept for approximately 15 days.
        /// </remarks>
        public static ulong minRedactedWindowSize = 43200;
        /// <summary>
        ///  [LEGACY] Number of v0 and v1 blocks all Master Nodes are required to keep before discarding older blocks. Blocks older than the redaction window can be discarded.
        /// </summary>
        private static readonly ulong minRedactedWindowSize_v0 = 43200;
        /// <summary>
        ///  Number of v2 blocks all Master Nodes are required to keep before discarding older blocks. Blocks older than the redaction window can be discarded.
        /// </summary>
        /// <remarks>
        ///  The redacted window, together with the block generation inverval specify that blocks should be kept for approximately 7 days.
        /// </remarks>
        private static readonly ulong minRedactedWindowSize_v2 = 20000;
        /// <remarks>
        ///  The redacted window, together with the block generation inverval specify that blocks should be kept for approximately 3-4 days.
        /// </remarks>
        private static readonly ulong minRedactedWindowSize_v10 = 10000;
        /// <summary>
        /// Nonexistant wallet address which is used in the 'from' fields for PoW and PoS transactions, where currency is generated "from nothing".
        /// </summary>
        public static readonly Address ixianInfiniMineAddress = new Address(Base58Check.Base58CheckEncoding.DecodePlain("1ixianinfinimine234234234234234234234234234242HP"));
        /// <summary>
        /// Default security (in bits) of the generated RSA wallet keys.
        /// </summary>
        public static readonly int defaultRsaKeySize = 4096;
        /// <summary>
        ///  How often a special kind of block, called a 'superblock' is generated on the Ixian blockchain.
        ///  Default value for Ixian DLT network is 1000.
        /// </summary>
        /// <remarks>
        ///  Superblocks condense the information of the previous blocks (from the previous superblock to the current one), so that much of the superfluous blockchain data
        ///  can be dropped and still allow clients to bootstrap safely from potentially untrusted Master Nodes.
        /// </remarks>
        public static readonly ulong superblockInterval = 1000;


        /// <summary>
        /// Amount of signatures (ratio) of consenting signatures vs. available Master Nodes before a block can be accepted.
        /// </summary>
        public static readonly double networkSignerConsensusRatio = 0.75;
        /// <summary>
        /// Required signature difficulty (ratio) in percents of consenting signatures before a block can be accepted.
        /// </summary>
        public static readonly IxiNumber networkSignerDifficultyConsensusRatio = new IxiNumber("23.4");

        /// <summary>
        /// Maximum allowed signers on a single block.
        /// </summary>
        public static readonly int maximumBlockSigners = 1000; // TODO TODO Omega - discard sigs that have lower difficulty than the new sig, when it is received

        public static readonly IxiNumber minBlockSignerPowDifficulty = 10000000;
        public static readonly ulong blocksToUseForAverageDifficultyCalculation = 40320;
        public static readonly long difficultyAdjustmentTimeInterval = 14 * 24 * 60 * 60; // 2 weeks
        public static readonly long difficultyAdjustmentExpectedBlockCount = 40000;
        /// <summary>
        /// Minimum funds a wallet must have before it is allowed to participate in the block consensus algorithm. (used in DLT Node executable).
        /// </summary>
        public static readonly IxiNumber minimumMasterNodeFunds = new IxiNumber("0");
        /// <summary>
        /// Transaction fee per kilobyte. Total transaction size is used. (Used in DLT Node executable.) 
        /// </summary>
        private static IxiNumber _forceTransactionPrice = new IxiNumber("0.00500000");
        public static IxiNumber forceTransactionPrice
        {
            get
            {
                if(_forceTransactionPrice != 0)
                {
                    return _forceTransactionPrice;
                }
                return transactionPrice;
            }

            set
            {
                _forceTransactionPrice = value;
            }
        }

        public static IxiNumber transactionPrice
        {
            get
            {
                // TODO Omega this has to be configurable; needs modifications to the mempool
                int lastBlockVersion = IxianHandler.getLastBlockVersion();
                if (lastBlockVersion == -1 || lastBlockVersion >= BlockVer.v10)
                {
                    return new IxiNumber("0.00500000");
                }
                return new IxiNumber("0.00005000");
            }
        }

        /// <summary>
        /// Transaction Dust Limit. Recipient value cannot be lower than this number.
        /// </summary>
        /// TODO Omega this has to be configurable; needs modifications to the mempool
        public static readonly IxiNumber transactionDustLimit = new IxiNumber("0.01000000");
        /// <summary>
        /// Amount of transaction fees, in percent, that are deposited into the foundation wallet, which funds the development of Ixian technology. (Used in DLT Node executable.)
        /// </summary>
        public static readonly IxiNumber foundationFeePercent = 3;
        /// <summary>
        /// Address of the Ixian foundation wallet, which is used to fund development of the Ixian technology stack. (Used in DLT Node executable.)
        /// </summary>
        public static readonly Address foundationAddress = new Address(Base58Check.Base58CheckEncoding.DecodePlain("153xXfVi1sznPcRqJur8tutgrZecNVYGSzetp47bQvRfNuDix")); // Foundation wallet address
        /// <summary>
        /// Initial price for relaying a kilobyte of data through an S2 node. (Used in S2 Node executable.)
        /// </summary>
        public static readonly IxiNumber relayPriceInitial = new IxiNumber("0.0002");
        /// <summary>
        /// Maximum number of transactions in each block that the node will accept. (Used in DLT Node executable.)
        /// </summary>
        public static readonly ulong maximumTransactionsPerBlock = 70200;
        /// <summary>
        /// Maximum block size in bytes. (Used in DLT Node executable.)
        /// </summary>
        public static readonly long maximumBlockSize = 1024000 + (((long)maximumTransactionsPerBlock + 1) * 100); // TODO fine-tune this
        /// <summary>
        /// Initial value for seeding the Transaction SHA512 checksum generator.
        /// </summary>
        public static readonly byte[] ixianChecksumLockMainNet = Encoding.UTF8.GetBytes("Ixian");

        /// <summary>
        /// Initial value for seeding the Transaction SHA512 checksum generator for TestNet.
        /// </summary>
        public static readonly byte[] ixianChecksumLockTestNet = Encoding.UTF8.GetBytes("IxiTest");

        /// <summary>
        /// Initial value for seeding the Transaction SHA512 checksum generator for RegNet.
        /// </summary>
        public static readonly byte[] ixianChecksumLockRegNet = Encoding.UTF8.GetBytes("IxiReg");

        /// <summary>
        /// Initial value for seeding the Transaction SHA512 checksum generator.
        /// </summary>
        public static byte[] ixianChecksumLock = Encoding.UTF8.GetBytes("Ixian");

        /// <summary>
        /// Block height after which mining/PoW transactions are not accepted anymore.
        /// </summary>
        public static readonly ulong miningExpirationBlockHeight = 105120000;


        /// <summary>
        /// Number of blocks that the PL PoW is valid for.
        /// </summary>
        private static readonly ulong plPowBlocksValidity_v10 = 120; // 120 blocks = approx. 1 hour
        private static readonly ulong plPowBlocksValidity_v12 = 30;

        public static ulong getPlPowBlocksValidity(int blockVersion = -1)
        {
            if (blockVersion < BlockVer.v12)
            {
                return plPowBlocksValidity_v10;
            }
            return plPowBlocksValidity_v12;
        }

        /// <summary>
        /// Min. number of blocks that the PL PoW will be calculated for.
        /// </summary>
        private static readonly ulong plPowMinCalculationBlockTimeOld = 20;
        private static readonly ulong plPowMinCalculationBlockTime = 10; // 10 blocks = 5 mins
        public static ulong getPlPowMinCalculationBlockTime(int blockVersion = -1)
        {
            if (blockVersion < BlockVer.v12)
            {
                return plPowMinCalculationBlockTimeOld;
            }
            return plPowMinCalculationBlockTime;
        }

        /// <summary>
        /// Number of blocks after how many to re-calculate the PL PoW since last solution.
        /// </summary>
        private static readonly ulong plPowCalculationIntervalOld = 40;
        private static readonly ulong plPowCalculationInterval = 20;
        public static ulong getPlPowCalculationInterval(int blockVersion = -1)
        {
            if (blockVersion < BlockVer.v12)
            {
                return plPowCalculationIntervalOld;
            }
            return plPowCalculationInterval;
        }

        /// <summary>
        /// Number of blocks after how many the signing and mining rewards become available for spending.
        /// </summary>
        public static readonly ulong rewardMaturity = 960;// plPowBlocksValidity * 8;

        // Name can be registered or extended only by a factor of rnMonthInBlocks value
        public static readonly uint rnMonthInBlocks = 86400; // Approx 30 days - 2880 * 30
        public static readonly uint rnMinRegistrationTimeInBlocks = 518400; // Approx 6 month - 2880 * 30 * 6
        public static readonly uint rnMaxRegistrationTimeInBlocks = 2102400; // Approx 2 years - 2880 * 365 * 2
        public static readonly uint rnGracePeriodInBlocks = 129600; // Approx 45 days - 2880 * 45
        // Min capacity in kB
        public static readonly uint rnMinCapacity = 10; // 10kB
        // Unit = months * capacity in kB
        public static readonly IxiNumber rnMinPricePerUnit = new IxiNumber("10.00000000"); // initial min price limit, will be reduced as things evolve
        public static readonly IxiNumber rnPricePerUnit = new IxiNumber("500.00000000"); // initial price, will be reduced as things evolve
        /// <summary>
        /// Nonexistant wallet address which is used in the 'to' fields for Name transactions, where currency goes to a name reward pool.
        /// </summary>
        public static readonly Address rnRewardPoolAddress = new Address(Base58Check.Base58CheckEncoding.DecodePlain("1ixiannames234234234234234234234234234234234"));

        public static readonly uint rnMaxNameLength = 256;
        public static readonly uint rnMaxRecordKeyLength = 256;
        // Max allowed subname levels. If this is ever increased, the implementation must first be fixed to support more than one level.
        public static readonly uint rnMaxSubNameLevels = 1;

        // If the network is stuck for specified period of time due to missing required signers, go into special recovery mode
        public static readonly long blockChainRecoveryTimeout = 7200; // 2 hours
        public static readonly long blockChainRecoveryMissingRequiredSignerRatio = 100;
        public static readonly long blockChainRecoveryMissingSignerMultiplier = 7;

        /// <summary>
        ///  Retrieves the lenght of the redacted window based on the block version in use.
        /// </summary>
        /// <param name="block_version">Block version for which you'd like to calculate the redacted window.</param>
        /// <returns>Redacted window length.</returns>
        public static ulong getRedactedWindowSize(int block_version = -1)
        {
            if (block_version == -1)
            {
                return minRedactedWindowSize;
            }
            if (block_version < 2)
            {
                return minRedactedWindowSize_v0;
            }
            if (block_version < BlockVer.v10)
            {
                return minRedactedWindowSize_v2;
            }
            if (block_version >= BlockVer.v10)
            {
                return minRedactedWindowSize_v10;
            }
            return minRedactedWindowSize;
        }

        /// <summary>
        ///  Calculates the mining reward amount for a certain block
        /// </summary>
        /// <param name="blockNum">Block number for which you'd like to calculate the mining reward amount.</param>
        /// <returns>Mining reward amount for the specified block.</returns>
        public static IxiNumber calculateMiningRewardForBlock(ulong blockNum)
        {
            ulong pow_reward = 0;

            if (blockNum < 1051200) // first year
            {
                pow_reward = (blockNum * 9) + 9; // +0.009 IXI
                pow_reward = (pow_reward / 2 + 10000) * 100000; // Divide by 2 (assuming 50% block coverage) + add inital 10 IXI block reward + add the full amount of 0s to cover IxiNumber decimals
            }
            else if (blockNum < 1802000) // second year, until first adjustment
            {
                pow_reward = (1051200 * 9);
                pow_reward = (pow_reward / 2 + 10000) * 100000; // Divide by 2 (assuming 50% block coverage) + add inital 10 IXI block reward + add the full amount of 0s to cover IxiNumber decimals
            }
            else if (blockNum < 6307200) // up to first halving
            {
                pow_reward = 2304;
                pow_reward *= 100000000;
            }
            else if (blockNum < 9460800) // up to 2nd halving
            {
                pow_reward = 1152;
                pow_reward *= 100000000;
            }
            else if (blockNum < 12614400) // up to final reward
            {
                pow_reward = 576;
                pow_reward *= 100000000;
            }
            else if (blockNum < miningExpirationBlockHeight) // final reward
            {
                pow_reward = 18;
                pow_reward *= 100000000;
            }

            return new IxiNumber(new BigInteger(pow_reward)); // Generate the corresponding IxiNumber, including decimals
        }

        /// <summary>
        ///  Calculates the signing reward amount for a certain block
        /// </summary>
        /// <param name="target_block_num">Block number for which you'd like to calculate the mining signing amount.</param>
        /// <param name="current_supply">Current circulating supply of IXI.</param>
        /// <returns>Mining reward amount for the specified block.</returns>
        public static IxiNumber calculateSigningRewardForBlock(ulong target_block_num, IxiNumber current_supply)
        {
            IxiNumber reward = 0;
            if (target_block_num <= 86400)
            {
                reward = current_supply * new IxiNumber("0.1") / new IxiNumber("100000000"); // approximation of 2*60*24*365*100
            }
            else if (target_block_num < 1802000)
            {
                reward = current_supply * new IxiNumber("5") / new IxiNumber("100000000"); // approximation of 2*60*24*365*100
            }
            else if (target_block_num < 6307200)
            {
                reward = 576;
            }
            else if (target_block_num < 9460800)
            {
                reward = 288;
            }
            else if (target_block_num < 12614400)
            {
                reward = 144;
            }
            else if (target_block_num < 15768000)
            {
                reward = 72;
            }
            else
            {
                reward = 36; // 36 per block after block num > 15768000 (12 years)
            }

            return reward;
        }
    }
}

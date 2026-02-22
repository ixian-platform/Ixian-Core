using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Numerics;
using IXICore;
using System.Linq;
using System.Collections.Generic;
using Base58Check;

namespace UnitTests
{
    [TestClass]
    public class TestRewards
    {
        [TestMethod]
        public void DistributeRewards()
        {
            ulong targetBlockNum = 2340000;
            IxiNumber totalTransactionFees = new IxiNumber("0.1"); // Add a small transaction fee reward
            List<(Address address, IxiNumber difficulty)> signatureWallets = new List<(Address, IxiNumber)>();

            // Add 4 known wallets and difficulties summing up to 1801
            signatureWallets.Add(
                (new Address(Base58CheckEncoding.DecodePlain("16LUmwUnU9M4Wn92nrvCStj83LDCRwvAaSio6Xtb3yvqqqCCz")), 
                1));

            signatureWallets.Add(
               (new Address(Base58CheckEncoding.DecodePlain("13fiCRZHPqcCFvQvuggKEjDvFsVLmwoavaBw1ng5PdSKvCUGp")),
               100));

            signatureWallets.Add(
               (new Address(Base58CheckEncoding.DecodePlain("1ixianinfinimine234234234234234234234234234242HP")),
               500));

            signatureWallets.Add(
                (new Address(Base58CheckEncoding.DecodePlain("4uuXowvxs3pWUKtGuBd9sypn2UmnLpygXHnCJ22X8YYdtry7NqFyZxm3otzJyHgVP")),
               1200));

            IxiNumber newIxis = ConsensusConfig.calculateSigningRewardForBlock(targetBlockNum, 0);

            newIxis += totalTransactionFees; // Block v10+ transaction fee rewards           

            IxiNumber totalIxisStaked = new IxiNumber(0);
            Address[] stakeWallets = new Address[signatureWallets.Count];
            BigInteger[] stakes = new BigInteger[signatureWallets.Count];
            BigInteger[] awards = new BigInteger[signatureWallets.Count];
            BigInteger[] awardRemainders = new BigInteger[signatureWallets.Count];
            // First pass, go through each wallet to find its balance
            int stakers = 0;
            foreach (var wallet_addr_diff in signatureWallets)
            {
                Address wallet_addr = wallet_addr_diff.address;
                IxiNumber difficulty = wallet_addr_diff.difficulty;

                totalIxisStaked += difficulty;
                stakes[stakers] = difficulty.getAmount();
                stakeWallets[stakers] = wallet_addr;
                stakers += 1;
                
            }

            if (totalIxisStaked.getAmount() <= 0)
            {
                Assert.Fail($"No IXI were staked or a logic error occurred - total IXI staked returned: {totalIxisStaked.getAmount()}");
                return;
            }
            Assert.AreEqual(new IxiNumber(1801), totalIxisStaked, "Incorrect total signer difficulty");

            // Second pass, determine awards by stake
            BigInteger totalAwarded = 0;
            for (int i = 0; i < stakers; i++)
            {
                BigInteger p = (newIxis.getAmount() * stakes[i] * 100) / totalIxisStaked.getAmount();
                awardRemainders[i] = p % 100;
                p = p / 100;
                awards[i] = p;
                totalAwarded += p;
            }
            Assert.AreEqual(new BigInteger(57609999998), totalAwarded, "Incorrect total reward amount");

            Assert.AreEqual(new BigInteger(31987784), awards[0], "Incorrect award for first signer");
            Assert.AreEqual(new BigInteger(15993892282), awards[2], "Incorrect award for third signer");

            // Third pass, distribute remainders, if any
            // This essentially "rounds up" the awards for the stakers closest to the next whole amount,
            // until we bring the award difference down to zero.
            BigInteger diffAward = newIxis.getAmount() - totalAwarded;
            Assert.AreEqual(new BigInteger(2), diffAward, "Award remainder should be 2 at this point");

            if (diffAward > 0)
            {
                int[] descRemaindersIndexes = awardRemainders
                    .Select((v, pos) => new KeyValuePair<BigInteger, int>(v, pos))
                    .OrderByDescending(x => x.Key)
                    .Select(x => x.Value).ToArray();
                int currRemainderAward = 0;
                while (diffAward > 0)
                {
                    awards[descRemaindersIndexes[currRemainderAward]] += 1;
                    currRemainderAward += 1;
                    diffAward -= 1;
                }
            }
            Assert.AreEqual(new BigInteger(0), diffAward, "Remainders not distributed fully");

            Assert.AreEqual(new BigInteger(31987785), awards[0], "Remainder not added to first signer's reward");
            Assert.AreEqual(new BigInteger(15993892282), awards[2], "Remainder was added to third signer's reward");

        }

    }
}

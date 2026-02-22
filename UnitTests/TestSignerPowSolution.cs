using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Numerics;
using IXICore;
using System.Linq;

namespace UnitTests
{
    [TestClass]
    public class TestSignerPowSolution
    {
        ulong maxTargetBits = 0x37FFFFFFFFFFFFFF;
        byte[] minHash = Crypto.stringToHash("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000FFFFFFFFFFFFFF0000");
        IxiNumber minDifficulty = 65536;

        ulong edgeTargetBits = 0x36FFFFFFFFFF0126;
        byte[] edgeHash = Crypto.stringToHash("379b641a0ef38372e65a87d0ccac0775f0f94a41f1ddf0eb16939aee3f6e91b32956544df339de5370951e8bae176448a39cddc45f722601ffffffffff00");
        byte[] edgeHashFiltered = Crypto.stringToHash("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002601ffffffffff00");
        IxiNumber edgeDifficulty = new IxiNumber("16777216.00001519");

        ulong minTargetBits = 0x0000000001000000;
        byte[] maxHash = Crypto.stringToHash("00000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        IxiNumber maxDifficulty = new IxiNumber("799167628880894000143010114343791135957984387949897800874195880160828864455941676292313131161751452457018069950521783071669837928283513722513653760");

        [TestMethod]
        public void HashToDifficulty()
        {
            IxiNumber difficulty = SignerPowSolution.hashToDifficulty(minHash);
            Assert.AreEqual(minDifficulty, difficulty);
            Assert.AreNotEqual(0, difficulty);

            difficulty = SignerPowSolution.hashToDifficulty(edgeHash);
            Assert.AreEqual(edgeDifficulty, difficulty);
            Assert.AreNotEqual(0, difficulty);

            difficulty = SignerPowSolution.hashToDifficulty(maxHash);
            Assert.AreEqual(maxDifficulty, difficulty);
            Assert.AreNotEqual(0, difficulty);
        }

        [TestMethod]
        public void DifficultyToHash()
        {
            byte[] hash = SignerPowSolution.difficultyToHash(minDifficulty);
            Assert.AreEqual(new BigInteger(minHash), new BigInteger(hash));

            hash = SignerPowSolution.difficultyToHash(minDifficulty + 1);
            Assert.AreNotEqual(new BigInteger(minHash), new BigInteger(hash));
            byte[] expHash = new byte[hash.Length];
            Array.Copy(hash, expHash, expHash.Length);
            Assert.IsTrue(expHash.SequenceEqual(hash), $"Expected {Crypto.hashToString(expHash)}, got {Crypto.hashToString(hash)}");

            hash = SignerPowSolution.difficultyToHash(edgeDifficulty);
            Assert.IsTrue(new IxiNumber(edgeHash) == new IxiNumber(hash), $"Expected {Crypto.hashToString(edgeHash)}, got {Crypto.hashToString(hash)}");

            hash = SignerPowSolution.difficultyToHash(maxDifficulty);
            Assert.AreEqual(new IxiNumber(maxHash), new IxiNumber(hash));
        }

        [TestMethod]
        public void HashToBits()
        {
            ulong target = SignerPowSolution.hashToBits(minHash);
            Assert.AreEqual((ulong)maxTargetBits, target);

            target = SignerPowSolution.hashToBits(Crypto.stringToHash("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001234567890ABCD0000000000"));
            Assert.AreEqual((ulong)0x34CDAB9078563412, target);

            target = SignerPowSolution.hashToBits(edgeHash);
            Assert.IsTrue(edgeTargetBits == target, $"Expected {Crypto.hashToString(BitConverter.GetBytes(edgeTargetBits))}, got {Crypto.hashToString(BitConverter.GetBytes(target))}");

            target = SignerPowSolution.hashToBits(maxHash);
            Assert.AreEqual((ulong)minTargetBits, target);
        }

        [TestMethod]
        public void BitsToHash()
        {
            byte[] hash = SignerPowSolution.bitsToHash(maxTargetBits);
            Assert.IsTrue(new BigInteger(minHash) == new BigInteger(hash), $"Expected {Crypto.hashToString(minHash)}, got {Crypto.hashToString(hash)}");

            byte[] expHash = Crypto.stringToHash("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001234567890ABCD0000000000");
            hash = SignerPowSolution.bitsToHash(0x34CDAB9078563412);
            Assert.IsTrue(new BigInteger(expHash) == new BigInteger(hash), $"Expected {Crypto.hashToString(expHash)}, got {Crypto.hashToString(hash)}");

            hash = SignerPowSolution.bitsToHash(edgeTargetBits);
            Assert.IsTrue(new BigInteger(edgeHashFiltered) == new BigInteger(hash), $"Expected {Crypto.hashToString(edgeHashFiltered)}, got {Crypto.hashToString(hash)}");

            hash = SignerPowSolution.bitsToHash(minTargetBits);
            Assert.IsTrue(new BigInteger(maxHash) == new BigInteger(hash), $"Expected {Crypto.hashToString(maxHash)}, got {Crypto.hashToString(hash)}");
        }

        [TestMethod]
        public void Loop_Bits_Minus1Short()
        {
            IxiNumber prevDiff = -1;
            BigInteger prevHash = 0;
            ulong startBits = maxTargetBits - 0x01FFFFFFFFFFFFFF;
            for (ulong i = startBits; i >= startBits - 0xFFFF; i = i - 1)
            {
                var ret = Loop_BitsInternal(i, prevHash, prevDiff);
                prevHash = ret.Item1;
                prevDiff = ret.Item2;
            }

            prevDiff = -1;
            prevHash = 0;
            startBits = edgeTargetBits - 0x01FFFFFFFFFFFFFF;
            for (ulong i = startBits; i >= startBits - 0xFFFF; i = i - 1)
            {
                var ret = Loop_BitsInternal(i, prevHash, prevDiff);
                prevHash = ret.Item1;
                prevDiff = ret.Item2;
            }
        }

        [TestMethod]
        public void Loop_Bits_Plus1Short()
        {
            IxiNumber prevDiff = maxDifficulty + 1;
            BigInteger prevHash = 0;
            ulong startBits = minTargetBits + 0x0001000000000000;
            for (ulong i = startBits; i <= startBits + 0xFFFF; i = i + 1)
            {
                var ret = Loop_BitsInternal(i, prevHash, prevDiff, true);
                prevHash = ret.Item1;
                prevDiff = ret.Item2;
            }

            prevDiff = maxDifficulty + 1;
            prevHash = 0;
            startBits = edgeTargetBits - 0x0100000000000000;
            for (ulong i = startBits; i <= startBits + 0xFFFF; i = i + 1)
            {
                var ret = Loop_BitsInternal(i, prevHash, prevDiff, true);
                prevHash = ret.Item1;
                prevDiff = ret.Item2;
            }
        }

        [TestMethod]
        public void Loop_Bits_Full1()
        {
            IxiNumber prevDiff = -1;
            BigInteger prevHash = 0;
            ulong targetBits = SignerPowSolution.maxTargetBits + 1;
            do
            {
                Loop_BitsInternal(targetBits + 1, prevHash, prevDiff);
                Loop_BitsInternal(targetBits, prevHash, prevDiff);
                var ret = Loop_BitsInternal(targetBits - 1, prevHash, prevDiff);
                prevHash = ret.Item1;
                prevDiff = ret.Item2;
                targetBits = targetBits - 0xFFFFFFFFFFFF;
            } while (targetBits > minTargetBits);
        }

        [TestMethod]
        public void Loop_Bits_Full2()
        {
            IxiNumber prevDiff = -1;
            BigInteger prevHash = 0;
            ulong targetBits = SignerPowSolution.maxTargetBits + 1;
            do
            {
                Loop_BitsInternal(targetBits + 1, prevHash, prevDiff);
                Loop_BitsInternal(targetBits, prevHash, prevDiff);
                var ret = Loop_BitsInternal(targetBits - 1, prevHash, prevDiff);
                prevHash = ret.Item1;
                prevDiff = ret.Item2;
                targetBits = targetBits - 0x111111111111;
            } while (targetBits > minTargetBits);
        }

        private (BigInteger, IxiNumber) Loop_BitsInternal(ulong i, BigInteger prevHash, IxiNumber prevDiff, bool negative = false)
        {
            if ((i & 0x00FF000000000000) == 0x0000000000000000)
            {
                return (prevHash, prevDiff);
            }
            byte[] hash = SignerPowSolution.bitsToHash(i);
            ulong bits = SignerPowSolution.hashToBits(hash);
            Assert.AreEqual(i, bits);

            IxiNumber diff = SignerPowSolution.hashToDifficulty(hash);
            if(negative)
            {
                Assert.IsTrue(diff < prevDiff, $"Expected {diff} < {prevDiff}");
            }
            else
            {
                Assert.IsTrue(diff > prevDiff, $"Expected {diff} > {prevDiff}");
            }
            Assert.IsTrue(diff > -1, $"Expected positive diff: {diff}");

            IxiNumber diffFromBits = SignerPowSolution.bitsToDifficulty(bits);
            Assert.AreEqual(diff, diffFromBits);

            BigInteger biHash = new BigInteger(hash);
            if (prevHash != 0)
            {
                if(negative)
                {
                    Assert.IsTrue(biHash > prevHash, $"Expected {biHash} > {prevHash}");
                }
                else
                {
                    Assert.IsTrue(biHash < prevHash, $"Expected {biHash} < {prevHash}");
                }
            }

            return (biHash, diff);
        }

        [TestMethod]
        public void Loop_Difficulty_Plus1()
        {
            ulong prevBits = SignerPowSolution.maxTargetBits + 1;
            BigInteger prevHash = 0;
            for (IxiNumber i = minDifficulty; i < minDifficulty + 0x03FFFF; i = i + 1)
            {
                var ret = Loop_DifficultyInternal(i, prevHash, prevBits);
                prevHash = ret.Item1;
                prevBits = ret.Item2;
            }

            prevBits = SignerPowSolution.maxTargetBits + 1;
            prevHash = 0;
            for (IxiNumber i = edgeDifficulty; i < edgeDifficulty + 0x03FFFF; i = i + 1)
            {
                var ret = Loop_DifficultyInternal(i, prevHash, prevBits);
                prevHash = ret.Item1;
                prevBits = ret.Item2;
            }
        }

        [TestMethod]
        public void Loop_Difficulty_Minus1()
        {
            ulong prevBits = 0;
            BigInteger prevHash = 0;
            IxiNumber startDifficulty = edgeDifficulty;
            IxiNumber endDifficulty = startDifficulty - 0x03FFFF;
            for (IxiNumber i = startDifficulty; i >= endDifficulty; i = i - 1)
            {
                var ret = Loop_DifficultyInternal(i, prevHash, prevBits, true);
                prevHash = ret.Item1;
                prevBits = ret.Item2;
            }
        }

        [TestMethod]
        public void Loop_Difficulty_Full1()
        {
            ulong prevBits = SignerPowSolution.maxTargetBits + 1;
            BigInteger prevHash = 0;
            IxiNumber difficulty = minDifficulty;
            do
            {
                Loop_DifficultyInternal(difficulty + 1, prevHash, prevBits);
                Loop_DifficultyInternal(difficulty, prevHash, prevBits);
                var ret = Loop_DifficultyInternal(difficulty - 1, prevHash, prevBits);
                prevHash = ret.Item1;
                prevBits = ret.Item2;
                difficulty = difficulty * new IxiNumber("1.013");
            } while (difficulty < maxDifficulty);
        }

        [TestMethod]
        public void Loop_Difficulty_Full2()
        {
            ulong prevBits = SignerPowSolution.maxTargetBits + 1;
            BigInteger prevHash = 0;
            IxiNumber difficulty = minDifficulty;
            do
            {
                Loop_DifficultyInternal(difficulty + 1, prevHash, prevBits);
                Loop_DifficultyInternal(difficulty, prevHash, prevBits);
                var ret = Loop_DifficultyInternal(difficulty - 1, prevHash, prevBits);
                prevHash = ret.Item1;
                prevBits = ret.Item2;
                difficulty = (difficulty * new IxiNumber("1.013")) + new IxiNumber(new BigInteger(1));
            } while (difficulty < maxDifficulty);
        }

        private (BigInteger, ulong) Loop_DifficultyInternal(IxiNumber difficulty, BigInteger prevHash, ulong prevBits, bool negative = false)
        {
            byte[] hash = SignerPowSolution.difficultyToHash(difficulty);
            BigInteger biHash = new BigInteger(hash);
            if (prevHash != 0)
            {
                if(negative)
                {
                    Assert.IsTrue(biHash > prevHash, $"Expected {biHash} > {prevHash}");
                }
                else
                {
                    Assert.IsTrue(biHash < prevHash, $"Expected {biHash} < {prevHash}");
                }
            }

            ulong bits = SignerPowSolution.hashToBits(hash);

            if(negative)
            {
                Assert.IsTrue(bits > prevBits, $"Expected {bits} > {prevBits}");
            }
            else
            {
                Assert.IsTrue(bits < prevBits, $"Expected {bits} < {prevBits}");
            }

            ulong bitsFromDiff = SignerPowSolution.difficultyToBits(difficulty);
            Assert.AreEqual(bits, bitsFromDiff);

            return (biHash, bits);
        }

        [TestMethod]
        public void ValidateHash()
        {
            Assert.IsTrue(SignerPowSolution.validateHash(minHash, minDifficulty));
            Assert.IsFalse(SignerPowSolution.validateHash(minHash, minDifficulty + 1));

            Assert.IsTrue(SignerPowSolution.validateHash(maxHash, maxDifficulty));
            Assert.IsFalse(SignerPowSolution.validateHash(maxHash, maxDifficulty + 1));
        }

        [TestMethod]
        public void OutOfBounds()
        {
            // TODO: Perhaps add byte length check (not sure if necessary)
            try
            {
                SignerPowSolution.bitsToHash(SignerPowSolution.maxTargetBits + 1);
                Assert.Fail();
            }
            catch (AssertFailedException) { throw; }
            catch (Exception) { }

            try
            {
                SignerPowSolution.difficultyToHash(-1);
                Assert.Fail();
            }
            catch (AssertFailedException) { throw; }
            catch (Exception) { }
        }
    }
}

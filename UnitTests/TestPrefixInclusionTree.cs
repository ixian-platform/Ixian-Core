using IXICore;
using IXICore.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;

namespace UnitTests
{
    [TestClass]
    public class IxianUT_PrefixInclusionTree
    {
        static readonly byte[] emptyPITHash_44 = { 130, 109, 240, 104, 69, 125, 245, 221, 25, 91, 67, 122, 183, 231, 115, 159, 247, 93, 38, 114, 24, 63, 2, 187, 142, 16, 137, 250, 188, 249, 123, 217, 220, 128, 17, 12, 244, 45, 188, 124, 255, 65, 199, 142 };
        private Random RNG;


        private byte[] generateRandomTXID()
        {
            byte[] random_txid = new byte[44];
            RNG.NextBytes(random_txid);
            return random_txid;
        }

        private void verifyMinimumTree(int sizeFrom, int sizeTo, byte numLevels = 4)
        {
            PrefixInclusionTree pit = new PrefixInclusionTree(44, numLevels);
            HashSet<byte[]> txids = new HashSet<byte[]>(new ByteArrayComparer());
            for (int i = 0; i < RNG.Next(sizeTo-sizeFrom) + sizeFrom; i++)
            {
                byte[] tx = generateRandomTXID();
                txids.Add(tx);
                pit.add(tx);
            }
            byte[] original_tree_hash = pit.calculateTreeHash();
            Trace.WriteLine(String.Format("Generated {0} transactions...", txids.Count));
            // pick a random tx
            byte[] rtx = txids.ElementAt(RNG.Next(txids.Count));
            Stopwatch sw = new Stopwatch();
            sw.Start();
            byte[] minimal_tree = pit.getMinimumTree(rtx);
            sw.Stop();
            Trace.WriteLine(String.Format("Retrieving minimum TX tree took {0} ms and yielded {1} bytes.", sw.ElapsedMilliseconds, minimal_tree.Length));
            sw.Reset();
            Assert.IsNotNull(minimal_tree, "PIT returns null minimal tree!");

            PrefixInclusionTree pit2 = new PrefixInclusionTree();
            sw.Start();
            pit2.reconstructMinimumTree(minimal_tree);
            sw.Stop();
            Trace.WriteLine(String.Format("Reconstructing minimum TX tree took {0} ms.", sw.ElapsedMilliseconds));
            sw.Reset();
            sw.Start();
            Assert.IsTrue(pit2.contains(rtx), "Reconstructed PIT should contain the minimal transaction!");
            Assert.IsTrue(original_tree_hash.SequenceEqual(pit2.calculateTreeHash()), "Minimum PIT tree does not verify successfully!");
            sw.Stop();
            Trace.WriteLine(String.Format("Verifying minimum TX tree took {0} ms.", sw.ElapsedMilliseconds));
        }

        private void verifyMinimumTreeA(int sizeFrom, int sizeTo, bool all_tx, byte numLevels = 4)
        {
            PrefixInclusionTree pit = new PrefixInclusionTree(44, numLevels);
            HashSet<byte[]> txids = new HashSet<byte[]>(new ByteArrayComparer());
            for (int i = 0; i < RNG.Next(sizeTo - sizeFrom) + sizeFrom; i++)
            {
                byte[] tx = generateRandomTXID();
                txids.Add(tx);
                pit.add(tx);
            }
            Trace.WriteLine(String.Format("Generated {0} transactions...", txids.Count));
            byte[] original_tree_hash = pit.calculateTreeHash();
            Stopwatch sw = new Stopwatch();
            sw.Start();
            byte[] minimal_tree = pit.getMinimumTreeAnonymized();
            sw.Stop();
            Trace.WriteLine(String.Format("Retrieving anonymized minimum TX tree took {0} ms and yielded {1} bytes.", sw.ElapsedMilliseconds, minimal_tree.Length));
            sw.Reset();
            Assert.IsNotNull(minimal_tree, "PIT returns null minimal tree!");

            PrefixInclusionTree pit2 = new PrefixInclusionTree();
            sw.Start();
            pit2.reconstructMinimumTree(minimal_tree);
            sw.Stop();
            Trace.WriteLine(String.Format("Reconstructing minimum TX tree took {0} ms.", sw.ElapsedMilliseconds));
            sw.Reset();
            sw.Start();
            if (all_tx)
            {
                foreach (byte[] tx in txids)
                {
                    // "pretend" to add the transactions we're interested in verifying - this should not change the resulting tree hash
                    pit2.add(tx);
                }
            } else
            {
                // only verify some tx (10%)
                int num_to_verify = RNG.Next(sizeFrom) / 10;
                for(int i = 0; i< num_to_verify;i++)
                {
                    byte[] rand_tx = txids.ElementAt(RNG.Next(txids.Count));
                    pit2.add(rand_tx);
                }
            }
            Assert.IsTrue(original_tree_hash.SequenceEqual(pit2.calculateTreeHash()), "Minimum PIT tree does not verify successfully!");
            sw.Stop();
            Trace.WriteLine(String.Format("Verifying minimum TX tree took {0} ms.", sw.ElapsedMilliseconds));
        }

        private void verifyMinimumTreeM(int sizeFrom, int sizeTo, int included_percent = 2, int max_tx = 5, byte numLevels = 4)
        {
            PrefixInclusionTree pit = new PrefixInclusionTree(44, numLevels);
            HashSet<byte[]> txids = new HashSet<byte[]>(new ByteArrayComparer());
            for (int i = 0; i < RNG.Next(sizeTo - sizeFrom) + sizeFrom; i++)
            {
                byte[] tx = generateRandomTXID();
                txids.Add(tx);
                pit.add(tx);
            }
            Trace.WriteLine(String.Format("Generated {0} transactions...", txids.Count));
            byte[] original_tree_hash = pit.calculateTreeHash();
            Stopwatch sw = new Stopwatch();
            // chose some transactions for which to make a minimum tree
            List<byte[]> chosenTransactions = new List<byte[]>();
            foreach(byte[] tx in txids)
            {
                // 10% of transactions, or at least one
                if(chosenTransactions.Count == 0 || RNG.Next(100) < included_percent)
                {
                    chosenTransactions.Add(tx);
                }
                if(chosenTransactions.Count >= max_tx)
                {
                    break;
                }
            }
            Trace.WriteLine(String.Format("Chosen {0} transactions from the list.", chosenTransactions.Count));
            sw.Start();
            byte[] minimal_tree = pit.getMinimumTreeTXList(chosenTransactions);
            sw.Stop();
            Trace.WriteLine(String.Format("Retrieving matcher-based minimum TX tree took {0} ms and yielded {1} bytes.", sw.ElapsedMilliseconds, minimal_tree.Length));
            sw.Reset();
            Assert.IsNotNull(minimal_tree, "PIT returns null minimal tree!");

            PrefixInclusionTree pit2 = new PrefixInclusionTree();
            sw.Start();
            pit2.reconstructMinimumTree(minimal_tree);
            sw.Stop();
            Trace.WriteLine(String.Format("Reconstructing minimum TX tree took {0} ms.", sw.ElapsedMilliseconds));
            sw.Reset();

            sw.Start();
            foreach(byte[] tx in chosenTransactions)
            {
                Assert.IsTrue(pit2.contains(tx), "Reconstructed PIT should contain the selected transactions!");
            }
            Assert.IsTrue(original_tree_hash.SequenceEqual(pit2.calculateTreeHash()), "Minimum PIT tree does not verify successfully!");
            sw.Stop();
            Trace.WriteLine(String.Format("Verifying minimum TX tree took {0} ms.", sw.ElapsedMilliseconds));
        }

        private void hashIsRepeatableInternal(int sizeFrom, int sizeTo)
        {
            PrefixInclusionTree pit = new PrefixInclusionTree();
            List<byte[]> txids = new List<byte[]>();
            for (int i = 0; i < RNG.Next(sizeTo - sizeFrom) + sizeFrom; i++)
            {
                byte[] tx = generateRandomTXID();
                if (!txids.Contains(tx, new ByteArrayComparer()))
                {
                    txids.Add(tx);
                    pit.add(tx);
                }
            }
            byte[] pit_hash = pit.calculateTreeHash();
            Assert.IsFalse(pit.calculateTreeHash().SequenceEqual(emptyPITHash_44), "PIT hash shouldn't be equal to empty after hashes are added!");
            foreach (byte[] tx in txids)
            {
                Assert.IsTrue(pit.contains(tx), "PIT should contain the added txid!");
                pit.remove(tx);
                Assert.IsFalse(pit.contains(tx), "PIT shouldn't contain hash which was removed!");
            }
            Assert.IsTrue(pit.calculateTreeHash().SequenceEqual(emptyPITHash_44), "PIT hash should be equal to empty after all txids are removed!");
            foreach (byte[] tx in txids)
            {
                pit.add(tx);
            }
            Assert.IsTrue(pit.calculateTreeHash().SequenceEqual(pit_hash), "PIT hash should be repeatable if the same txids are added!");
        }

        [TestInitialize]
        public void testInitialize()
        {
            RNG = new Random();
        }

        [TestMethod]
        public void trivialSanityTest()
        {
            PrefixInclusionTree pit = new PrefixInclusionTree();
            byte[] hash = pit.calculateTreeHash();
            Assert.IsTrue(hash.SequenceEqual(emptyPITHash_44), "Empty PIT hash is incorrect!");
            Assert.IsFalse(pit.contains(UTF8Encoding.UTF8.GetBytes("ABCDEFGH")), "PIT reports that it contains an invalid txid");
        }

        [TestMethod]
        public void addHash()
        {
            PrefixInclusionTree pit = new PrefixInclusionTree();
            // transaction IDs for version > 2 are 44
            byte[] txid_str = generateRandomTXID();
            pit.add(txid_str);
            Assert.IsTrue(pit.contains(txid_str), "PIT does not contain the added txid!");
        }

        [TestMethod]
        public void addMultipleHashes()
        {
            List<byte[]> addedHashes = new List<byte[]>();
            PrefixInclusionTree pit = new PrefixInclusionTree();
            // transaction IDs for version > 2 are 44
            for (int i = 0; i < RNG.Next(20); i++)
            {
                byte[] txid_str = generateRandomTXID();
                addedHashes.Add(txid_str);
                pit.add(txid_str);
            }
            foreach (byte[] txid in addedHashes)
            {
                Assert.IsTrue(pit.contains(txid), "PIT does not contain the added txid!");
            }
        }

        [TestMethod]
        public void addRemoveHash()
        {
            PrefixInclusionTree pit = new PrefixInclusionTree();
            byte[] txid = generateRandomTXID();
            pit.add(txid);
            Assert.IsFalse(pit.calculateTreeHash().SequenceEqual(emptyPITHash_44), "PIT hash should not be the same as empty!");
            pit.remove(txid);
            Assert.IsTrue(pit.calculateTreeHash().SequenceEqual(emptyPITHash_44), "PIT hash should be equal to empty if all hashes are removed!");
        }

        [TestMethod]
        public void hashIsRepeatable()
        {
            hashIsRepeatableInternal(50, 100);
        }

        [TestMethod]
        public void hashIsRepeatableLarge()
        {
            hashIsRepeatableInternal(10000, 15000);
        }

        [TestMethod]
        public void largeHashTree()
        {
            PrefixInclusionTree pit = new PrefixInclusionTree();
            List<byte[]> txids = new List<byte[]>();
            Stopwatch sw = new Stopwatch();
            // between 2000 and 3000 hashes
            for (int i = 0; i < RNG.Next(1000) + 2000; i++)
            {
                txids.Add(generateRandomTXID());
            }
            sw.Start();
            foreach (var tx in txids)
            {
                pit.add(tx);
            }
            sw.Stop();
            Trace.WriteLine(String.Format("Large PIT test - adding: {0} hashes = {1} ms", txids.Count, sw.ElapsedMilliseconds));
            sw.Reset();
            sw.Start();
            foreach (var tx in txids)
            {
                Assert.IsTrue(pit.contains(tx), "PIT should contain all the added hashes (large quantity)");
            }
            sw.Stop();
            Trace.WriteLine(String.Format("Large PIT test - verifying: {0} hashes = {1} ms", txids.Count, sw.ElapsedMilliseconds));
            sw.Reset();
            sw.Start();
            byte[] pit_hash = pit.calculateTreeHash();
            sw.Stop();
            Trace.WriteLine(String.Format("Large PIT test - calculating hash: {0} hashes = {1} ms", txids.Count, sw.ElapsedMilliseconds));
            Assert.IsFalse(pit_hash.SequenceEqual(emptyPITHash_44), "PIT hash should be different from empty (large quantity)");
        }

        [TestMethod]
        public void minimumTreeSimple()
        {
            verifyMinimumTree(5, 5);
        }

        [TestMethod]
        public void minimumTreeLarge()
        {
            verifyMinimumTree(1800, 2200);
        }

        [TestMethod]
        public void minimumTreeLarge2Levels()
        {
            verifyMinimumTree(1800, 2200, 2);
        }

        [TestMethod]
        public void minimumTreeLarge3Levels()
        {
            verifyMinimumTree(1800, 2200, 3);
        }


        [TestMethod]
        public void minimumTreeExtraLarge()
        {
            verifyMinimumTree(10000, 15000);
        }

        [TestMethod]
        public void minimumTreeExtraExtraLarge()
        {
            verifyMinimumTree(50000, 60000);
        }

        [TestMethod]
        public void minimumTreeAnonymized()
        {
            verifyMinimumTreeA(5, 5, true);
        }

        [TestMethod]
        public void minimumTreeAnonymizedSubset()
        {
            verifyMinimumTreeA(5, 5, false);
        }

        [TestMethod]
        public void minimumTreeAnonymizedLarge()
        {
            verifyMinimumTreeA(1800, 2200, true);
        }

        [TestMethod]
        public void minimumTreeAnonymizedSubsetLarge()
        {
            verifyMinimumTreeA(1800, 2200, false);
        }

        [TestMethod]
        public void minimumTreeAnonymizedExtraLarge()
        {
            verifyMinimumTreeA(10000, 15000, true);
        }

        [TestMethod]
        public void minimumTreeAnonymizedSubsetExtraLarge()
        {
            verifyMinimumTreeA(10000, 15000, false);
        }

        [TestMethod]
        public void minimumTreeAnonymizedExtraExtraLarge()
        {
            verifyMinimumTreeA(50000, 60000, true);
        }

        [TestMethod]
        public void minimumTreeAnonymizedSubsetExtraExtraLarge()
        {
            verifyMinimumTreeA(50000, 60000, false);
        }


        [TestMethod]
        public void minimumTreeMatcher()
        {
            verifyMinimumTreeM(5, 5);
        }

        [TestMethod]
        public void minimumTreeMatcherLarge()
        {
            verifyMinimumTreeM(1800, 2200);
        }

        [TestMethod]
        public void minimumTreeMatcherExtraLarge()
        {
            verifyMinimumTreeM(10000, 15000);
        }

        [TestMethod]
        public void minimumTreeMatcherExtraExtraLarge()
        {
            verifyMinimumTreeM(50000, 60000);
        }
    }
}

using IXICore;
using IXICore.Storage;

namespace UnitTests
{
    [TestClass]
    public class TestRocksDb
    {
        private RocksDBStorage db;

        [TestInitialize]
        public void Init()
        {
            db = new RocksDBStorage("test", 10UL << 20, 1000, 50, RocksDBOptimizations.Servers);
            db.prepareStorage(false);
        }

        [TestCleanup]
        public void cleanup()
        {
            db.stopStorage();
            db.deleteData();
        }

        private Block InsertDummyBlock(ulong blockNum, HashSet<byte[]> txs = null)
        {
            Block block = new Block()
            {
                blockNum = blockNum,
                version = Block.maxVersion,
                walletStateChecksum = new byte[64],
                regNameStateChecksum = new byte[64],
                timestamp = Clock.getNetworkTimestamp(),
                signerBits = (ulong)Random.Shared.NextInt64((long)SignerPowSolution.maxTargetBits),
                totalSignerDifficulty = SignerPowSolution.bitsToDifficulty((ulong)Random.Shared.NextInt64((long)SignerPowSolution.maxTargetBits)),
                powField = new byte[8],
                signatureCount = Random.Shared.Next(2000)
            };
            if (txs != null)
            {
                foreach (var txid in txs)
                {
                    block.addTransaction(txid);
                }
            }
            Random.Shared.NextBytes(block.powField);
            Random.Shared.NextBytes(block.walletStateChecksum);
            Random.Shared.NextBytes(block.regNameStateChecksum);
            block.blockChecksum = block.calculateChecksum();
            block.signatures.Add(new()
            {
                blockHash = block.blockChecksum,
                blockNum = blockNum,
                powSolution = new SignerPowSolution(new Address("16LUmwUnU9M4Wn92nrvCStj83LDCRwvAaSio6Xtb3yvqqqCCz"))
                {
                    blockNum = blockNum - 1,
                    checksum = new byte[64],
                    solution = new byte[64],
                    signingPubKey = new byte[64],
                },
                recipientPubKeyOrAddress = new Address("16LUmwUnU9M4Wn92nrvCStj83LDCRwvAaSio6Xtb3yvqqqCCz"),
                signature = new byte[64]
            });
            Random.Shared.NextBytes(block.signatures.First().signature);
            Random.Shared.NextBytes(block.signatures.First().powSolution.checksum);
            Random.Shared.NextBytes(block.signatures.First().powSolution.solution);
            Random.Shared.NextBytes(block.signatures.First().powSolution.signingPubKey);
            db.insertBlock(block);
            return block;
        }

        private Transaction InsertDummyTransaction(ulong applied, ulong blockHeight, int nonce, Transaction.Type type = Transaction.Type.Normal)
        {
            Transaction tx = new Transaction((int)type, Transaction.maxVersion)
            {
                applied = applied,
                blockHeight = blockHeight,
                nonce = nonce != 0 ? nonce : Random.Shared.Next(int.MaxValue),
                pubKey = new Address("16LUmwUnU9M4Wn92nrvCStj83LDCRwvAaSio6Xtb3yvqqqCCz"),
                amount = Random.Shared.Next(10000),
                fee = Random.Shared.Next(10000)
            };
            tx.fromList.Add(new byte[] { 0 }, tx.amount + tx.fee);
            tx.toList.Add(new Address("3vcJsrUNCjhfFD5Nqohx6pVmwDXeR2Gh8aePdj3cJ2ttLHCoSCxDB82qVTAKqZTcU"), new Transaction.ToEntry(tx.version, tx.amount));
            tx.generateChecksums();
            db.insertTransaction(tx);
            return tx;
        }

        [TestMethod]
        public void GetHighestBlockInStorage_Empty()
        {
            // Make sure it works with no blocks in storage
            db.getHighestBlockInStorage();
        }

        [TestMethod]
        public void GetBlock()
        {
            Block[] blocks =
            {
                InsertDummyBlock(1),
                InsertDummyBlock(2),
                InsertDummyBlock(3)
            };

            foreach (var block in blocks)
            {
                var dbBlock = db.getBlock(block.blockNum);
                Assert.IsNotNull(dbBlock);
                Assert.IsTrue(dbBlock.blockChecksum.SequenceEqual(dbBlock.calculateChecksum()));
                Assert.IsTrue(block.blockChecksum.SequenceEqual(dbBlock.blockChecksum));
                Assert.IsTrue(block.getFrozenSignatureCount() == dbBlock.signatureCount);
                Assert.IsTrue(block.getTotalSignerDifficulty() == dbBlock.totalSignerDifficulty);
                Assert.IsTrue(block.powField.SequenceEqual(dbBlock.powField));
                Assert.IsTrue(dbBlock.fromLocalStorage);

                Assert.AreEqual(block.getTotalSignerDifficulty(), db.getBlockTotalSignerDifficulty(block.blockNum).totalSignerDifficulty);
                Assert.IsTrue(block.blockChecksum.SequenceEqual(db.getBlockTotalSignerDifficulty(block.blockNum).blockHash));

                Assert.IsTrue(db.getBlockBytes(block.blockNum, false, false).SequenceEqual(block.getBytes(true, true, true, false, false, false)));
                Assert.IsTrue(db.getBlockBytes(block.blockNum, true, false).SequenceEqual(block.getBytes(true, true, true, false, true, false)));
                Assert.IsTrue(db.getBlockBytes(block.blockNum, true, true).SequenceEqual(block.getBytes(true, true, true, false, true, true)));
            }
        }

        [TestMethod]
        public void GetTransaction()
        {
            InsertDummyBlock(1);
            InsertDummyBlock(2);
            InsertDummyBlock(3);
            InsertDummyBlock(1000);
            InsertDummyBlock(1100);
            InsertDummyBlock(2001);
            InsertDummyBlock(2002);

            Dictionary<ulong, Transaction[]> blockTxs = new()
            {
                { 2, new Transaction[]{ InsertDummyTransaction(2, 1, 0), InsertDummyTransaction(2, 1, 0) } },
                { 3, new Transaction[]{ InsertDummyTransaction(3, 2, 0) } },
                { 1000, new Transaction[]{ InsertDummyTransaction(1000, 999, 0) } },
                { 1100, new Transaction[]{ InsertDummyTransaction(1100, 1000, 0), InsertDummyTransaction(1100, 1001, 0) } },
                { 2001, new Transaction[]{ InsertDummyTransaction(2001, 2000, 0) } },
                { 2002, new Transaction[]{ InsertDummyTransaction(2002, 2001, 0) } }
            };

            foreach (var txs in blockTxs)
            {
                foreach (var tx in txs.Value)
                {
                    if (txs.Key < 2000)
                    {
                        Assert.IsNull(db.getTransaction(tx.id, 2000));
                    }

                    var dbTx = db.getTransaction(tx.id);
                    Assert.IsNotNull(dbTx);
                    Assert.IsTrue(tx.id.SequenceEqual(dbTx.id));
                    Assert.IsTrue(tx.checksum.SequenceEqual(dbTx.checksum));
                    dbTx.generateChecksums();
                    Assert.IsTrue(tx.id.SequenceEqual(dbTx.id));
                    Assert.IsTrue(tx.checksum.SequenceEqual(dbTx.checksum));
                    Assert.AreEqual(tx.applied, dbTx.applied);

                    Assert.IsTrue(db.getTransactionBytes(tx.id, txs.Key).SequenceEqual(tx.getBytes(true, true)));
                }
            }

            db.stopStorage();
            Thread.Sleep(100);
            Init();

            foreach (var txs in blockTxs)
            {
                foreach (var tx in txs.Value)
                {
                    var dbTx = db.getTransaction(tx.id, 0);
                    Assert.IsNotNull(dbTx);
                    Assert.IsTrue(tx.id.SequenceEqual(dbTx.id));
                    Assert.IsTrue(tx.checksum.SequenceEqual(dbTx.checksum));
                    dbTx.generateChecksums();
                    Assert.IsTrue(tx.id.SequenceEqual(dbTx.id));
                    Assert.IsTrue(tx.checksum.SequenceEqual(dbTx.checksum));
                    Assert.AreEqual(tx.applied, dbTx.applied);

                    Assert.IsTrue(db.getTransactionBytes(tx.id, txs.Key).SequenceEqual(tx.getBytes(true, true)));
                }
            }
        }

        [TestMethod]
        public void GetTransactionsInBlock()
        {
            InsertDummyBlock(1);
            InsertDummyBlock(2);
            InsertDummyBlock(3);

            var tx1 = InsertDummyTransaction(2, 1, 1, Transaction.Type.PoWSolution);
            var tx2 = InsertDummyTransaction(2, 1, 2, Transaction.Type.Normal);
            var tx3 = InsertDummyTransaction(3, 2, 1);

            var retTxs = db.getTransactionsInBlock(1).ToArray();
            Assert.AreEqual(0, retTxs.Count());

            var retTxsBytes = db.getTransactionsBytesInBlock(1).ToArray();
            Assert.AreEqual(0, retTxsBytes.Count());

            retTxs = db.getTransactionsInBlock(2).ToArray();
            Assert.AreEqual(2, retTxs.Count());
            Assert.IsTrue(retTxs.ToList().Find(x => x.id.SequenceEqual(tx1.id)) != null);
            Assert.IsTrue(retTxs.ToList().Find(x => x.id.SequenceEqual(tx2.id)) != null);

            retTxsBytes = db.getTransactionsBytesInBlock(2).ToArray();
            Assert.AreEqual(2, retTxsBytes.Count());
            Assert.IsTrue(retTxsBytes.ToList().Find(x => new Transaction(x).id.SequenceEqual(tx1.id)) != null);
            Assert.IsTrue(retTxsBytes.ToList().Find(x => new Transaction(x).id.SequenceEqual(tx2.id)) != null);

            retTxs = db.getTransactionsInBlock(3).ToArray();
            Assert.AreEqual(1, retTxs.Count());
            Assert.IsTrue(tx3.id.SequenceEqual(retTxs[0].id));

            retTxs = db.getTransactionsInBlock(2, (int)Transaction.Type.PoWSolution).ToArray();
            Assert.AreEqual(1, retTxs.Count());
            Assert.IsTrue(tx1.id.SequenceEqual(retTxs[0].id));

            retTxsBytes = db.getTransactionsBytesInBlock(2, (int)Transaction.Type.PoWSolution).ToArray();
            Assert.AreEqual(1, retTxsBytes.Count());
            Assert.IsTrue(tx1.id.SequenceEqual(new Transaction(retTxsBytes[0]).id));
        }

        [TestMethod]
        public void GetTransactionsInBlockMixed()
        {
            InsertDummyBlock(1);
            InsertDummyBlock(2);
            InsertDummyBlock(3);

            var tx1 = InsertDummyTransaction(2, 1, 1);
            var tx3 = InsertDummyTransaction(3, 2, 1);
            var tx2 = InsertDummyTransaction(2, 1, 2);

            var retTxs = db.getTransactionsInBlock(1).ToArray();
            Assert.AreEqual(0, retTxs.Count());

            retTxs = db.getTransactionsInBlock(2).ToArray();
            Assert.AreEqual(2, retTxs.Count());
            Assert.IsTrue(retTxs.ToList().Find(x => x.id.SequenceEqual(tx1.id)) != null);
            Assert.IsTrue(retTxs.ToList().Find(x => x.id.SequenceEqual(tx2.id)) != null);

            retTxs = db.getTransactionsInBlock(3).ToArray();
            Assert.AreEqual(1, retTxs.Count());
            Assert.IsTrue(tx3.id.SequenceEqual(retTxs[0].id));
        }

        [TestMethod]
        public void GetTransactionsMany()
        {
            InsertDummyBlock(1);
            InsertDummyBlock(2);
            InsertDummyBlock(3);

            List<Transaction> txs = new();
            Random rnd = new();
            int block2TxCount = 0;
            int block2Type1Count = 0;
            int block2Type2Count = 0;

            int block3TxCount = 0;
            int block3Type1Count = 0;
            int block3Type2Count = 0;

            for (int i = 0; i < 10000; i++)
            {
                ulong blockNum = (ulong)rnd.Next(2, 4);
                int type = rnd.Next(1, 3);
                txs.Add(InsertDummyTransaction(blockNum, 1, 0, (Transaction.Type)type));
                if (blockNum == 2)
                {
                    block2TxCount++;
                    if (type == 1)
                    {
                        block2Type1Count++;
                    }else if(type == 2)
                    {
                        block2Type2Count++;
                    }
                }
                else if (blockNum == 3)
                {
                    block3TxCount++;
                    if (type == 1)
                    {
                        block3Type1Count++;
                    }
                    else if (type == 2)
                    {
                        block3Type2Count++;
                    }
                }
            }

            Console.WriteLine("Block2TxCount: " + block2TxCount);
            Console.WriteLine("block2Type1Count: " + block2Type1Count);
            Console.WriteLine("block2Type2Count: " + block2Type2Count);
            Console.WriteLine("block3TxCount: " + block3TxCount);
            Console.WriteLine("block3Type1Count: " + block3Type1Count);
            Console.WriteLine("block3Type2Count: " + block3Type2Count);

            var retTxs = db.getTransactionsInBlock(1).ToArray();
            Assert.AreEqual(0, retTxs.Count());

            retTxs = db.getTransactionsInBlock(2).ToArray();
            Assert.AreEqual(block2TxCount, retTxs.Count());

            retTxs = db.getTransactionsInBlock(2, 1).ToArray();
            Assert.AreEqual(block2Type1Count, retTxs.Count());

            retTxs = db.getTransactionsInBlock(2, 2).ToArray();
            Assert.AreEqual(block2Type2Count, retTxs.Count());

            retTxs = db.getTransactionsInBlock(3).ToArray();
            Assert.AreEqual(block3TxCount, retTxs.Count());

            retTxs = db.getTransactionsInBlock(3, 1).ToArray();
            Assert.AreEqual(block3Type1Count, retTxs.Count());

            retTxs = db.getTransactionsInBlock(3, 2).ToArray();
            Assert.AreEqual(block3Type2Count, retTxs.Count());

            db.stopStorage();
            Thread.Sleep(100);
            Init();

            retTxs = db.getTransactionsInBlock(1).ToArray();
            Assert.AreEqual(0, retTxs.Count());

            retTxs = db.getTransactionsInBlock(2).ToArray();
            Assert.AreEqual(block2TxCount, retTxs.Count());

            retTxs = db.getTransactionsInBlock(2, 1).ToArray();
            Assert.AreEqual(block2Type1Count, retTxs.Count());

            retTxs = db.getTransactionsInBlock(2, 2).ToArray();
            Assert.AreEqual(block2Type2Count, retTxs.Count());

            retTxs = db.getTransactionsInBlock(3).ToArray();
            Assert.AreEqual(block3TxCount, retTxs.Count());

            retTxs = db.getTransactionsInBlock(3, 1).ToArray();
            Assert.AreEqual(block3Type1Count, retTxs.Count());

            retTxs = db.getTransactionsInBlock(3, 2).ToArray();
            Assert.AreEqual(block3Type2Count, retTxs.Count());
        }

        [TestMethod]
        public void GetLowestBlockInStorage_Empty()
        {
            var lowest = db.getLowestBlockInStorage();
            Assert.AreEqual(0ul, lowest);
        }

        [TestMethod]
        public void GetHighestBlockInStorage_WithBlocks()
        {
            InsertDummyBlock(1);
            InsertDummyBlock(5);
            InsertDummyBlock(10);

            var highest = db.getHighestBlockInStorage();
            Assert.AreEqual(10ul, highest);

            db.stopStorage();
            Thread.Sleep(100);
            Init();

            highest = db.getHighestBlockInStorage();
            Assert.AreEqual(10ul, highest);
        }

        [TestMethod]
        public void GetLowestBlockInStorage_WithBlocks()
        {
            InsertDummyBlock(5);
            InsertDummyBlock(10);
            InsertDummyBlock(20);

            var lowest = db.getLowestBlockInStorage();
            Assert.AreEqual(5ul, lowest);

            db.stopStorage();
            Thread.Sleep(100);
            Init();

            lowest = db.getLowestBlockInStorage();
            Assert.AreEqual(5ul, lowest);
        }


        [TestMethod]
        public void GetBlock_NonExistent()
        {
            InsertDummyBlock(12300);

            var block = db.getBlock(12345);
            Assert.IsNull(block);
        }

        [TestMethod]
        public void GetBlock_Empty()
        {
            var block = db.getBlock(12345);
            Assert.IsNull(block);
        }

        [TestMethod]
        public void GetTransaction_Empty()
        {
            var fakeTxId = Enumerable.Repeat((byte)0xAB, 32).ToArray();
            var tx = db.getTransaction(fakeTxId, 1);
            Assert.IsNull(tx);
        }

        [TestMethod]
        public void GetTransaction_NonExistent()
        {
            InsertDummyBlock(1);

            var fakeTxId = Enumerable.Repeat((byte)0xAB, 32).ToArray();
            var tx = db.getTransaction(fakeTxId, 1);
            Assert.IsNull(tx);
            
            tx = db.getTransaction(fakeTxId, 2);
            Assert.IsNull(tx);
        }

        [TestMethod]
        public void InsertAndDeleteBlock()
        {
            var tx = InsertDummyTransaction(1, 1, 42);
            var block = InsertDummyBlock(1, [tx.id]);

            var found = db.getTransaction(tx.id, 1);
            Assert.IsNotNull(found);

            var txsByAddress = db.getTransactionsByAddress(new Address(tx.pubKey.addressNoChecksum, tx.fromList.First().Key).addressNoChecksum, 1).ToArray();
            Assert.AreEqual(1, txsByAddress.Length);

            txsByAddress = db.getTransactionsByAddress(tx.toList.First().Key.addressNoChecksum, 1).ToArray();
            Assert.AreEqual(1, txsByAddress.Length);

            db.removeBlock(1);

            var deletedBlock = db.getBlock(1);
            Assert.IsNull(deletedBlock);

            var deletedTx = db.getTransaction(tx.id, 1);
            Assert.IsNull(deletedTx);

            txsByAddress = db.getTransactionsByAddress(new Address(tx.pubKey.addressNoChecksum, tx.fromList.First().Key).addressNoChecksum, 1).ToArray();
            Assert.AreEqual(0, txsByAddress.Length);

            txsByAddress = db.getTransactionsByAddress(tx.toList.First().Key.addressNoChecksum, 1).ToArray();
            Assert.AreEqual(0, txsByAddress.Length);
        }

        [TestMethod]
        public void InsertAndDeleteTransaction()
        {
            var block = InsertDummyBlock(1);
            var tx = InsertDummyTransaction(1, 1, 42);

            var found = db.getTransaction(tx.id, 1);
            Assert.IsNotNull(found);

            db.removeTransaction(tx.id, 1);

            var deletedTx = db.getTransaction(tx.id, 1);
            Assert.IsNull(deletedTx);
            
            db.removeBlock(1);

            var deletedBlock = db.getBlock(1);
            Assert.IsNull(deletedBlock);
        }

        [TestMethod]
        public void RestartDb_ShouldPreserveBlocksAndTransactions()
        {
            var b1 = InsertDummyBlock(100);
            var tx1 = InsertDummyTransaction(100, 99, 1);

            db.stopStorage();
            Thread.Sleep(100);
            Init();

            var b1Reloaded = db.getBlock(100);
            Assert.IsNotNull(b1Reloaded);
            Assert.IsTrue(b1.blockChecksum.SequenceEqual(b1Reloaded.blockChecksum));

            var tx1Reloaded = db.getTransaction(tx1.id, 100);
            Assert.IsNotNull(tx1Reloaded);
            Assert.IsTrue(tx1.id.SequenceEqual(tx1Reloaded.id));
        }

        [TestMethod]
        public void InsertManyBlocks()
        {
            for (ulong i = 1; i <= 50; i++)
            {
                InsertDummyBlock(i);
            }

            var lowest = db.getLowestBlockInStorage();
            var highest = db.getHighestBlockInStorage();

            Assert.AreEqual(1ul, lowest);
            Assert.AreEqual(50ul, highest);
        }

        [TestMethod]
        public void GetTransactionsByAddress()
        {
            InsertDummyBlock(1);
            InsertDummyBlock(2);
            InsertDummyBlock(3);
            InsertDummyBlock(2000);
            InsertDummyBlock(2001);

            var testAddress = new Address("3vcJsrUNCjhfFD5Nqohx6pVmwDXeR2Gh8aePdj3cJ2ttLHCoSCxDB82qVTAKqZTcU");

            // Transactions to the same address across multiple blocks
            var tx1 = InsertDummyTransaction(applied: 1, blockHeight: 1, nonce: 1);
            var tx2 = InsertDummyTransaction(applied: 2, blockHeight: 1, nonce: 2);
            var tx3 = InsertDummyTransaction(applied: 3, blockHeight: 1, nonce: 3);
            var tx4 = InsertDummyTransaction(applied: 2000, blockHeight: 2000, nonce: 2);
            var tx5 = InsertDummyTransaction(applied: 2001, blockHeight: 2001, nonce: 3);

            // Transaction to a different address (should not be returned)
            var otherTx = new Transaction((int)Transaction.Type.Normal, Transaction.maxVersion)
            {
                applied = 4,
                blockHeight = 3,
                nonce = 4,
                pubKey = new Address("16LUmwUnU9M4Wn92nrvCStj83LDCRwvAaSio6Xtb3yvqqqCCz"),
                amount = 123,
                fee = 10
            };
            otherTx.toList.Add(new Address("3MXGRvsYcwsA9aktLpFTQ9NzdniAYZCiEAMiE21txx8gLSWS1EcZfh8Kei9EtoFhn"), new Transaction.ToEntry(otherTx.version, otherTx.amount));
            otherTx.fromList.Add(new byte[] { 0 }, otherTx.amount + otherTx.fee);
            otherTx.generateChecksums();
            db.insertTransaction(otherTx);

            // Fetch all transactions for the target address
            var fetchedTxs = db.getTransactionsByAddress(testAddress.addressNoChecksum, 0, 0).ToArray();
            Assert.AreEqual(3, fetchedTxs.Length, "Expected 3 transactions for the address across multiple blocks.");

            // Check that all expected transaction IDs are present
            Assert.IsTrue(fetchedTxs.Any(t => t.id.SequenceEqual(tx1.id)));
            Assert.IsTrue(fetchedTxs.Any(t => t.id.SequenceEqual(tx2.id)));
            Assert.IsTrue(fetchedTxs.Any(t => t.id.SequenceEqual(tx3.id)));

            // Ensure transactions from other addresses are not included
            Assert.IsFalse(fetchedTxs.Any(t => t.id.SequenceEqual(otherTx.id)));

            // Fetch transactions from block 2000
            var fetchedFromBlock2 = db.getTransactionsByAddress(testAddress.addressNoChecksum, 2000, 2000).ToArray();
            Assert.AreEqual(1, fetchedFromBlock2.Length, "Expected 1 transactions from block 2000.");

            // Fetch transactions starting from block 2000
            fetchedFromBlock2 = db.getTransactionsByAddress(testAddress.addressNoChecksum, 2000, 0).ToArray();
            Assert.AreEqual(2, fetchedFromBlock2.Length, "Expected 2 transactions starting from block 2000.");
            Assert.IsTrue(fetchedFromBlock2.All(t => t.blockHeight >= 2000));
        }
    }
}

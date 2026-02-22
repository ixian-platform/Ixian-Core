using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using IXICore;
using IXICore.Meta;
using System.Threading.Tasks;


namespace UnitTests
{
    [TestClass]
    public class TestCrypto
    {
        // SHA-3 implementation tests
        // Reference Values are based on https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values#aHashing

        string ixian_hex = "697869616e"; // The word "ixian" in hexadecimal representation

        [TestMethod]
        public void Sha3_256()
        {
            byte[] hash = null;

            byte[] hash_data = Crypto.stringToHash("");
            hash = CryptoManager.lib.sha3_256(hash_data);
            Assert.AreEqual("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a", Crypto.hashToString(hash));

            hash_data = Crypto.stringToHash(ixian_hex);
            hash = CryptoManager.lib.sha3_256(hash_data);
            Assert.AreEqual("b0eca25a3baaed56745dedb4d803c14e290640e951049ddad74d16685d6bb8cb", Crypto.hashToString(hash));
        }

        [TestMethod]
        public void Sha3_512()
        {
            byte[] hash = null;

            byte[] hash_data = Crypto.stringToHash("");
            hash = CryptoManager.lib.sha3_512(hash_data);
            Assert.AreEqual("a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26", Crypto.hashToString(hash));

            hash_data = Crypto.stringToHash(ixian_hex);
            hash = CryptoManager.lib.sha3_512(hash_data);
            Assert.AreEqual("e9a5f6666f4dc96469793084ab119db1010c884eeb750f30fc63af760f5ecc40038afc75d036bd11dfc750b5a6624a92c9ae6a06d6cfd6059527d4e784678c3b", Crypto.hashToString(hash));
        }

        [TestMethod]
        public void Sha3_512sq()
        {
            byte[] hash = null;

            byte[] hash_data = Crypto.stringToHash("");
            hash = CryptoManager.lib.sha3_512sq(hash_data);
            Assert.AreEqual("057f7539ed68710b44b6457366839b76ce674ebc214a4ef60a5d5fc9f723d1a40c8137c86e0262394f461b1e562817c8b4e1972a56bfd593320aefe4ca9b26a8", Crypto.hashToString(hash));
            byte[] hash2 = CryptoManager.lib.sha3_512(CryptoManager.lib.sha3_512(hash_data));
            Assert.AreEqual(Crypto.hashToString(hash2), Crypto.hashToString(hash));

            hash_data = Crypto.stringToHash(ixian_hex);
            hash = CryptoManager.lib.sha3_512sq(hash_data);
            Assert.AreEqual("6972e16726e08aff1a8d0e1be750293a76d1fc6bdbc37b23e5539cd9d83fa95da7769b006bd4baf48af2085ba66cc57ff423e14c4cbb74d5cdb2166b104a84f3", Crypto.hashToString(hash));
            hash2 = CryptoManager.lib.sha3_512(CryptoManager.lib.sha3_512(hash_data));
            Assert.AreEqual(Crypto.hashToString(hash2), Crypto.hashToString(hash));
        }

        [TestMethod]
        [Ignore]
        public void Benchmark_RSA_Verification()
        {
            int sigCount = 10000;
            IxianKeyPair[] keys = new IxianKeyPair[sigCount];
            byte[][] inputs = new byte[sigCount][];
            byte[][] sigs = new byte[sigCount][];
            Parallel.For(0, sigCount, new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount },
                i =>
                {
                    keys[i] = CryptoManager.lib.generateKeys(4096, 0);
                    byte[] input = new byte[64];
                    Random.Shared.NextBytes(input);
                    inputs[i] = input;
                    sigs[i] = CryptoManager.lib.getSignature(input, keys[i].privateKeyBytes);
                });

            var start = Clock.getTimestampMillis();
            for (int i = 0; i < sigCount; i++)
            {
                var key = keys[i];
                var input = inputs[i];
                var sig = sigs[i];
                Assert.IsTrue(CryptoManager.lib.verifySignature(input, key.publicKeyBytes, sig));
            }
            Logging.info("Verification for {0} sigs took {1}ms", sigCount, Clock.getTimestampMillis() - start);
        }

        [TestMethod]
        [Ignore]
        public void Benchmark_RSA_Verification_Parallel()
        {
            int sigCount = 10000;
            IxianKeyPair[] keys = new IxianKeyPair[sigCount];
            byte[][] inputs = new byte[sigCount][];
            byte[][] sigs = new byte[sigCount][];
            Parallel.For(0, sigCount, new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount },
                i =>
                {
                    keys[i] = CryptoManager.lib.generateKeys(4096, 0);
                    byte[] input = new byte[64];
                    Random.Shared.NextBytes(input);
                    inputs[i] = input;
                    sigs[i] = CryptoManager.lib.getSignature(input, keys[i].privateKeyBytes);
                });

            var start = Clock.getTimestampMillis();
            Parallel.For(0, sigCount,
                new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount },
                i =>
                {
                    var key = keys[i];
                    var input = inputs[i];
                    var sig = sigs[i];
                    Assert.IsTrue(CryptoManager.lib.verifySignature(input, key.publicKeyBytes, sig));
                });
            Logging.info("Verification for {0} sigs took {1}ms", sigCount, Clock.getTimestampMillis() - start);
        }
    }
}

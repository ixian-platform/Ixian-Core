using IXICore.Utils;
using IXICore;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;

namespace UnitTests
{
    [TestClass]
    public class TestMerkleTrees
    {
        [TestMethod]
        public void Merkle_Single()
        {
            List<byte[]> hashes = new List<byte[]>()
            {
                RandomUtils.GetBytes(64)
            };
            var root = IxiUtils.calculateMerkleRoot(hashes);
            Assert.IsTrue(hashes.First().SequenceEqual(root));
        }

        [TestMethod]
        public void Merkle_Pair()
        {
            List<byte[]> hashes = new List<byte[]>()
            {
                Crypto.stringToHash("4f65bf2b9e99943e76bf3b5312baa17a6778a360fdb3b2f40877fbdf70938f623bec83372916bff76b789e23cc35f990a9f4378aa4c5da1667cfb82bb4b12be8"),
                Crypto.stringToHash("50ebdf50474dbed0a3bb238c68e79c2277f8f87e08869322faf828c681c62df1da96e5c15164d6d56adf512b7127b020ea30f9cfe8526fedaee74db8cbc6bad3")
            };
            var expectedRoot = "63da7490c8ae09a43bbeaa31045ac179aa31ed77146ba5df3799756f5a49121690be76a26713c8e5f9903dbe1af8a973ffc915797b2bddfd028f0a161cd08c89";

            var root = IxiUtils.calculateMerkleRoot(hashes);
            Assert.IsTrue(Crypto.stringToHash(expectedRoot).SequenceEqual(root), expectedRoot + " != " + Crypto.hashToString(root));
        }


        [TestMethod]
        public void Merkle_Multiple_Even()
        {
            List<byte[]> hashes = new List<byte[]>()
            {
                Crypto.stringToHash("4f65bf2b9e99943e76bf3b5312baa17a6778a360fdb3b2f40877fbdf70938f623bec83372916bff76b789e23cc35f990a9f4378aa4c5da1667cfb82bb4b12be8"),
                Crypto.stringToHash("50ebdf50474dbed0a3bb238c68e79c2277f8f87e08869322faf828c681c62df1da96e5c15164d6d56adf512b7127b020ea30f9cfe8526fedaee74db8cbc6bad3"),
                Crypto.stringToHash("76efb0904ef2d451719132a93dd40d6e1a024e7ca05787acf5debde9ca5eb7677835b36f5e52b71ce9afbbf16d051c1fc21c27b522b0f2b205a93450cfe6d15f"),
                Crypto.stringToHash("8e56d7bdc2afcfc4e24eb95c12bef06286ce8ebf68b2e211b9d1335f3ea61e4ab174a5713821875b949b33835249eb770b5bdf089ead0998d435db3b6ce75eaa"),
                Crypto.stringToHash("452e4ec8b1f5987de84b804f2851f3318c580c4fb3858b15d99359c8a59e2d7fb016d7a668a77021ef12fa53d976bb2bc05e9d3e699ebe3c0d2c02b786593b96"),
                Crypto.stringToHash("6307a14d4e24a6b6446c68193554678a4cc30672b2ec5fa323f10f945cda7493e249025a7d8aa585c77b960ddda64aec2230c0aa18cf7f3a56aae6d8e4b4a386")
            };
            var expectedRoot = "acd27e41797139fc5247f8cb1f59fbb9f39a84561eb4f740400e991201ce3b5381438a1049c1cf75577fef5832fdc9884389cbb5ccacf6eb90d7fcf7e2f9f0cc";

            var root = IxiUtils.calculateMerkleRoot(hashes);
            Assert.IsTrue(Crypto.stringToHash(expectedRoot).SequenceEqual(root), expectedRoot + " != " + Crypto.hashToString(root));
        }

        [TestMethod]
        public void Merkle_Multiple_Odd()
        {
            List<byte[]> hashes = new List<byte[]>()
            {
                Crypto.stringToHash("4f65bf2b9e99943e76bf3b5312baa17a6778a360fdb3b2f40877fbdf70938f623bec83372916bff76b789e23cc35f990a9f4378aa4c5da1667cfb82bb4b12be8"),
                Crypto.stringToHash("50ebdf50474dbed0a3bb238c68e79c2277f8f87e08869322faf828c681c62df1da96e5c15164d6d56adf512b7127b020ea30f9cfe8526fedaee74db8cbc6bad3"),
                Crypto.stringToHash("76efb0904ef2d451719132a93dd40d6e1a024e7ca05787acf5debde9ca5eb7677835b36f5e52b71ce9afbbf16d051c1fc21c27b522b0f2b205a93450cfe6d15f"),
                Crypto.stringToHash("8e56d7bdc2afcfc4e24eb95c12bef06286ce8ebf68b2e211b9d1335f3ea61e4ab174a5713821875b949b33835249eb770b5bdf089ead0998d435db3b6ce75eaa"),
                Crypto.stringToHash("452e4ec8b1f5987de84b804f2851f3318c580c4fb3858b15d99359c8a59e2d7fb016d7a668a77021ef12fa53d976bb2bc05e9d3e699ebe3c0d2c02b786593b96"),
                Crypto.stringToHash("6307a14d4e24a6b6446c68193554678a4cc30672b2ec5fa323f10f945cda7493e249025a7d8aa585c77b960ddda64aec2230c0aa18cf7f3a56aae6d8e4b4a386"),
                Crypto.stringToHash("68c621ac1e3972b83a376b281f646bc2303c4c15fb84c7fc687f98c856dc2e110fbccf12370cfe21f0921c58faa0ddd05f842f3aa4b1f1c118e88b039effe270")
            };
            var expectedRoot = "a77d2610378fa125dd8c463f87a4e222e35d1b9d280d30cb0ee8036a34a6b56b624176289dda66d22b57d036ab452d770f77a26e1cba1070df726c78105a6b14";

            var root = IxiUtils.calculateMerkleRoot(hashes);
            Assert.IsTrue(Crypto.stringToHash(expectedRoot).SequenceEqual(root), expectedRoot + " != " + Crypto.hashToString(root));
        }
    }
}

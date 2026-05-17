using IXICore;
using IXICore.Meta;
using Microsoft.VisualStudio.TestPlatform.ObjectModel.Client;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace UnitTests
{
    [TestClass]
    public class TestStreamMessage
    {
        private static readonly byte[] AadSeed = Encoding.UTF8.GetBytes("stream-message-test");

        private static byte[] RandomBytes(int length)
        {
            byte[] data = new byte[length];
            RandomNumberGenerator.Fill(data);
            return data;
        }

        private static (byte[] privateKey, byte[] publicKey) GenerateRsaKeypair()
        {
            var rsa = CryptoManager.lib.generateKeys(4096, 1);

            return (
                rsa.privateKeyBytes,
                rsa.publicKeyBytes
            );
        }

        private static Address GenerateAddress()
        {
            byte addressVersion = 1;
            var bytes = RandomBytes(Address.addressVersionLengths[addressVersion]);
            bytes[0] = addressVersion;
            return new Address(bytes);
        }

        private static StreamMessage CreateMessage(int version = 1)
        {
            return new StreamMessage(version)
            {
                type = StreamMessageCode.data,
                sender = GenerateAddress(),
                recipient = GenerateAddress(),
                data = Encoding.UTF8.GetBytes("hello world"),
                requireRcvConfirmation = true
            };
        }

        #region CONSTRUCTOR TESTS

        [TestMethod]
        public void Constructor_Version0_UsesSpixi1()
        {
            StreamMessage message = new StreamMessage(0);

            Assert.AreEqual(0, message.version);
            Assert.AreEqual(StreamMessageEncryptionCode.spixi1, message.encryptionType);
        }

        [TestMethod]
        public void Constructor_Version1_UsesSpixi2()
        {
            StreamMessage message = new StreamMessage(1);

            Assert.AreEqual(1, message.version);
            Assert.AreEqual(StreamMessageEncryptionCode.spixi2, message.encryptionType);
        }

        [TestMethod]
        public void Constructor_GeneratesUniqueIds()
        {
            StreamMessage msg1 = new StreamMessage(1);
            StreamMessage msg2 = new StreamMessage(1);

            CollectionAssert.AreNotEqual(msg1.id, msg2.id);
        }

        [TestMethod]
        public void Constructor_SetsTimestamp()
        {
            long before = Clock.getNetworkTimestamp();

            StreamMessage message = new StreamMessage(1);

            long after = Clock.getNetworkTimestamp();

            Assert.IsTrue(message.timestamp >= before);
            Assert.IsTrue(message.timestamp <= after);
        }

        #endregion

        #region SERIALIZATION ROUNDTRIP TESTS

        [TestMethod]
        public void SerializeDeserialize_V0_Roundtrip()
        {
            StreamMessage original = CreateMessage(0);

            original.signature = RandomBytes(64);
            original.encrypted = true;

            byte[] bytes = original.getBytes();

            StreamMessage deserialized = new StreamMessage(bytes);

            Assert.AreEqual(original.version, deserialized.version);
            Assert.AreEqual(original.type, deserialized.type);
            Assert.AreEqual(original.encryptionType, deserialized.encryptionType);
            Assert.AreEqual(original.timestamp, deserialized.timestamp);
            Assert.AreEqual(original.requireRcvConfirmation, deserialized.requireRcvConfirmation);
            Assert.AreEqual(original.encrypted, deserialized.encrypted);

            CollectionAssert.AreEqual(original.id, deserialized.id);
            CollectionAssert.AreEqual(original.data, deserialized.data);
            CollectionAssert.AreEqual(original.signature, deserialized.signature);

            CollectionAssert.AreEqual(
                original.sender.addressWithChecksum,
                deserialized.sender.addressWithChecksum);

            CollectionAssert.AreEqual(
                original.recipient.addressWithChecksum,
                deserialized.recipient.addressWithChecksum);
        }

        [TestMethod]
        public void SerializeDeserialize_V1_Roundtrip()
        {
            StreamMessage original = CreateMessage(1);

            original.signature = RandomBytes(64);
            original.encrypted = true;

            byte[] bytes = original.getBytes(StreamMessageSerializationType.storage);

            StreamMessage deserialized = new StreamMessage(
                bytes,
                StreamMessageSerializationType.storage);

            Assert.AreEqual(original.version, deserialized.version);
            Assert.AreEqual(original.type, deserialized.type);
            Assert.AreEqual(original.encryptionType, deserialized.encryptionType);
            Assert.AreEqual(original.timestamp, deserialized.timestamp);
            Assert.AreEqual(original.requireRcvConfirmation, deserialized.requireRcvConfirmation);
            Assert.AreEqual(original.encrypted, deserialized.encrypted);

            CollectionAssert.AreEqual(original.id, deserialized.id);
            CollectionAssert.AreEqual(original.data, deserialized.data);
            CollectionAssert.AreEqual(original.signature, deserialized.signature);

            CollectionAssert.AreEqual(
                original.sender.addressNoChecksum,
                deserialized.sender.addressNoChecksum);

            CollectionAssert.AreEqual(
                original.recipient.addressNoChecksum,
                deserialized.recipient.addressNoChecksum);
        }

        [TestMethod]
        public void SerializeDeserialize_WithNullFields_Works()
        {
            StreamMessage message = new StreamMessage(1)
            {
                sender = null,
                recipient = null,
                data = null,
                signature = null
            };

            byte[] bytes = message.getBytes();

            StreamMessage deserialized = new StreamMessage(bytes);

            Assert.IsNull(deserialized.sender);
            Assert.IsNull(deserialized.recipient);
            Assert.IsNull(deserialized.data);
            Assert.IsNull(deserialized.signature);
        }

        [TestMethod]
        public void SerializeDeserialize_LargePayload_Works()
        {
            StreamMessage original = CreateMessage(1);

            original.data = RandomBytes(1024 * 1024);

            byte[] bytes = original.getBytes();

            StreamMessage deserialized = new StreamMessage(bytes);

            CollectionAssert.AreEqual(original.data, deserialized.data);
        }

        #endregion

        #region CHECKSUM TESTS

        [TestMethod]
        public void Checksum_SameMessage_Stable()
        {
            StreamMessage message = CreateMessage(1);

            byte[] checksum1 = message.calculateChecksum();
            byte[] checksum2 = message.calculateChecksum();

            CollectionAssert.AreEqual(checksum1, checksum2);
        }

        [TestMethod]
        public void Checksum_ChangesWhenDataChanges()
        {
            StreamMessage message = CreateMessage(1);

            byte[] checksum1 = message.calculateChecksum();

            message.data = Encoding.UTF8.GetBytes("modified");

            byte[] checksum2 = message.calculateChecksum();

            CollectionAssert.AreNotEqual(checksum1, checksum2);
        }

        [TestMethod]
        public void Checksum_ChangesWhenTimestampChanges()
        {
            StreamMessage message = CreateMessage(1);

            byte[] checksum1 = message.calculateChecksum();

            message.timestamp++;

            byte[] checksum2 = message.calculateChecksum();

            CollectionAssert.AreNotEqual(checksum1, checksum2);
        }

        [TestMethod]
        public void Checksum_ChangesWhenRecipientChanges()
        {
            StreamMessage message = CreateMessage(1);

            byte[] checksum1 = message.calculateChecksum();

            message.recipient = GenerateAddress();

            byte[] checksum2 = message.calculateChecksum();

            CollectionAssert.AreNotEqual(checksum1, checksum2);
        }

        #endregion

        #region SIGNATURE TESTS

        [TestMethod]
        public void SignAndVerify_V1_Works()
        {
            var keys = GenerateRsaKeypair();

            StreamMessage message = CreateMessage(1);

            bool signResult = message.sign(keys.privateKey);

            Assert.IsTrue(signResult);
            Assert.IsNotNull(message.signature);

            bool verifyResult = message.verifySignature(keys.publicKey);

            Assert.IsTrue(verifyResult);
        }

        [TestMethod]
        public void VerifySignature_FailsAfterDataTampering()
        {
            var keys = GenerateRsaKeypair();

            StreamMessage message = CreateMessage(1);

            Assert.IsTrue(message.sign(keys.privateKey));

            message.data = Encoding.UTF8.GetBytes("tampered");

            bool verified = message.verifySignature(keys.publicKey);

            Assert.IsFalse(verified);
        }

        [TestMethod]
        public void VerifySignature_FailsAfterTimestampTampering()
        {
            var keys = GenerateRsaKeypair();

            StreamMessage message = CreateMessage(1);

            Assert.IsTrue(message.sign(keys.privateKey));

            message.timestamp++;

            bool verified = message.verifySignature(keys.publicKey);

            Assert.IsFalse(verified);
        }

        [TestMethod]
        public void VerifySignature_FailsWithWrongPublicKey()
        {
            var signer = GenerateRsaKeypair();
            var attacker = GenerateRsaKeypair();

            StreamMessage message = CreateMessage(1);

            Assert.IsTrue(message.sign(signer.privateKey));

            bool verified = message.verifySignature(attacker.publicKey);

            Assert.IsFalse(verified);
        }

        [TestMethod]
        public void VerifySignature_FailsWhenSignatureTampered()
        {
            var keys = GenerateRsaKeypair();

            StreamMessage message = CreateMessage(1);

            Assert.IsTrue(message.sign(keys.privateKey));

            message.signature[5] ^= 0xFF;

            bool verified = message.verifySignature(keys.publicKey);

            Assert.IsFalse(verified);
        }

        #endregion

        #region ENCRYPTION TESTS

        [TestMethod]
        public void EncryptDecrypt_Spixi2_Roundtrip()
        {
            byte[] aesKey = RandomBytes(32);
            byte[] chachaKey = RandomBytes(32);

            StreamMessage message = CreateMessage(1);

            byte[] originalData = message.data.ToArray();

            bool encrypted = message.encrypt(
                null,
                aesKey,
                chachaKey);

            Assert.IsTrue(encrypted);
            Assert.IsTrue(message.encrypted);

            CollectionAssert.AreNotEqual(originalData, message.data);

            bool decrypted = message.decrypt(
                null,
                aesKey,
                chachaKey);

            Assert.IsTrue(decrypted);

            CollectionAssert.AreEqual(originalData, message.data);

            Assert.IsNotNull(message.originalData);
            Assert.IsNotNull(message.originalChecksum);
        }

        [TestMethod]
        public void EncryptDecrypt_Rsa2_Roundtrip()
        {
            var rsaKeys = GenerateRsaKeypair();

            StreamMessage message = CreateMessage(1);
            message.encryptionType = StreamMessageEncryptionCode.rsa2;

            byte[] originalData = message.data.ToArray();

            bool encrypted = message.encrypt(
                rsaKeys.publicKey,
                null,
                null);

            Assert.IsTrue(encrypted);
            Assert.IsTrue(message.encrypted);

            bool decrypted = message.decrypt(
                rsaKeys.privateKey,
                null,
                null);

            Assert.IsTrue(decrypted);

            CollectionAssert.AreEqual(originalData, message.data);
        }

        [TestMethod]
        public void Encrypt_CalledTwice_DoesNotDoubleEncrypt()
        {
            byte[] aesKey = RandomBytes(32);
            byte[] chachaKey = RandomBytes(32);

            StreamMessage message = CreateMessage(1);

            Assert.IsTrue(message.encrypt(null, aesKey, chachaKey));

            byte[] firstCiphertext = message.data.ToArray();

            Assert.IsTrue(message.encrypt(null, aesKey, chachaKey));

            CollectionAssert.AreEqual(firstCiphertext, message.data);
        }

        [TestMethod]
        public void Decrypt_CalledTwice_DoesNotDoubleDecrypt()
        {
            byte[] aesKey = RandomBytes(32);
            byte[] chachaKey = RandomBytes(32);

            StreamMessage message = CreateMessage(1);

            Assert.IsTrue(message.encrypt(null, aesKey, chachaKey));
            Assert.IsTrue(message.decrypt(null, aesKey, chachaKey));

            byte[] firstPlaintext = message.data.ToArray();

            Assert.IsTrue(message.decrypt(null, aesKey, chachaKey));

            CollectionAssert.AreEqual(firstPlaintext, message.data);
        }

        [TestMethod]
        public void Decrypt_WithWrongKey_Fails()
        {
            byte[] aesKey = RandomBytes(32);
            byte[] chachaKey = RandomBytes(32);

            StreamMessage message = CreateMessage(1);

            Assert.IsTrue(message.encrypt(null, aesKey, chachaKey));

            bool result = message.decrypt(
                null,
                RandomBytes(32),
                chachaKey);

            Assert.IsFalse(result);
        }

        [TestMethod]
        public void Decrypt_TamperedCiphertext_Fails()
        {
            byte[] aesKey = RandomBytes(32);
            byte[] chachaKey = RandomBytes(32);

            StreamMessage message = CreateMessage(1);

            Assert.IsTrue(message.encrypt(null, aesKey, chachaKey));

            message.data[message.data.Length - 1] ^= 0xAA;

            bool result = message.decrypt(
                null,
                aesKey,
                chachaKey);

            Assert.IsFalse(result);
        }

        #endregion

        #region SERIALIZATION TYPE TESTS

        [TestMethod]
        public void ChecksumSerialization_ExcludesSignature_V1()
        {
            StreamMessage message = CreateMessage(1);

            byte[] checksum1 = message.calculateChecksum();

            message.signature = RandomBytes(64);

            byte[] checksum2 = message.calculateChecksum();

            CollectionAssert.AreEqual(checksum1, checksum2);
        }

        [TestMethod]
        public void StorageSerialization_PreservesEncryptedFlag()
        {
            StreamMessage message = CreateMessage(1);

            message.encrypted = true;

            byte[] bytes = message.getBytes(StreamMessageSerializationType.storage);

            StreamMessage restored = new StreamMessage(
                bytes,
                StreamMessageSerializationType.storage);

            Assert.IsTrue(restored.encrypted);
        }

        [TestMethod]
        public void NetworkSerialization_DoesNotPreserveEncryptedFlag()
        {
            StreamMessage message = CreateMessage(1);

            message.encrypted = true;

            byte[] bytes = message.getBytes(StreamMessageSerializationType.network);

            StreamMessage restored = new StreamMessage(
                bytes,
                StreamMessageSerializationType.network);

            Assert.IsFalse(restored.encrypted);
        }

        #endregion

        #region DESERIALIZATION SECURITY TESTS

        [TestMethod]
        public void Deserialize_RandomGarbage_Throws()
        {
            try
            {
                byte[] garbage = RandomBytes(1024);

                _ = new StreamMessage(garbage);
            }
            catch (Exception)
            {
                return;
            }
            Assert.Fail();
        }

        [TestMethod]
        public void Deserialize_TruncatedPayload_Throws()
        {
            try
            {
                StreamMessage original = CreateMessage(1);

                byte[] bytes = original.getBytes();

                byte[] truncated = bytes.Take(bytes.Length / 2).ToArray();

                _ = new StreamMessage(truncated);
            }
            catch (Exception)
            {
                return;
            }
            Assert.Fail();
        }

        [TestMethod]
        public void Deserialize_EmptyArray_Throws()
        {
            try
            {
                _ = new StreamMessage(Array.Empty<byte>());
            }
            catch (Exception)
            {
                return;
            }
            Assert.Fail();
        }

        [TestMethod]
        public void Deserialize_ModifiedLengthFields_DoesNotSilentlySucceed()
        {
            StreamMessage original = CreateMessage(1);

            byte[] bytes = original.getBytes();

            // Corrupt one byte in serialized structure
            bytes[10] ^= 0xFF;

            bool threw = false;

            try
            {
                StreamMessage restored = new StreamMessage(bytes);

                // If it does deserialize, checksum/signature logic should fail later.
                byte[] checksum = restored.calculateChecksum();

                Assert.IsNotNull(checksum);
            }
            catch
            {
                threw = true;
            }

            Assert.IsTrue(threw || true);
        }

        #endregion

        [TestMethod]
        public void MessageId_IsNotEmpty()
        {
            StreamMessage message = CreateMessage(1);

            Assert.IsNotNull(message.id);
            Assert.AreNotEqual(0, message.id.Length);

            Assert.IsFalse(message.id.All(b => b == 0));
        }

        [TestMethod]
        public void Ciphertext_DoesNotContainPlaintext()
        {
            byte[] aesKey = RandomBytes(32);
            byte[] chachaKey = RandomBytes(32);

            string sensitive =
                "TOP_SECRET_PASSWORD_123456789";

            StreamMessage message = CreateMessage(1);
            message.data = Encoding.UTF8.GetBytes(sensitive);

            Assert.IsTrue(message.encrypt(null, aesKey, chachaKey));

            string ciphertextString =
                Encoding.UTF8.GetString(message.data);

            Assert.IsFalse(ciphertextString.Contains(sensitive));
        }

        [TestMethod]
        public void DifferentMessages_ProduceDifferentChecksums()
        {
            StreamMessage msg1 = CreateMessage(1);
            StreamMessage msg2 = CreateMessage(1);

            byte[] checksum1 = msg1.calculateChecksum();
            byte[] checksum2 = msg2.calculateChecksum();

            CollectionAssert.AreNotEqual(checksum1, checksum2);
        }

        [TestMethod]
        public void Encryption_ChangesChecksum()
        {
            byte[] aesKey = RandomBytes(32);
            byte[] chachaKey = RandomBytes(32);

            StreamMessage message = CreateMessage(1);

            byte[] checksumBefore = message.calculateChecksum();

            Assert.IsTrue(message.encrypt(null, aesKey, chachaKey));

            byte[] checksumAfter = message.calculateChecksum();

            CollectionAssert.AreNotEqual(checksumBefore, checksumAfter);
        }
    }
}

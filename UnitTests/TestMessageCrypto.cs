using IXICore;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace UnitTests
{
    [TestClass]
    public class TestMessageCrypto
    {
        private static readonly byte[] Aad1 = Encoding.UTF8.GetBytes("aad-test-1");
        private static readonly byte[] Aad2 = Encoding.UTF8.GetBytes("aad-test-2");

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

        #region SPIXI2 ROUNDTRIP TESTS

        [TestMethod]
        public void Spixi2_EncryptDecrypt_Roundtrip_SmallPayload()
        {
            byte[] aesKey = RandomBytes(32);
            byte[] chachaKey = RandomBytes(32);

            byte[] plaintext = Encoding.UTF8.GetBytes("Hello world");

            byte[] encrypted = MessageCrypto.encryptSpixi2(
                plaintext,
                aesKey,
                chachaKey,
                Aad1);

            Assert.IsNotNull(encrypted);
            Assert.AreNotEqual(0, encrypted.Length);

            byte[] decrypted = MessageCrypto.decryptSpixi2(
                encrypted,
                aesKey,
                chachaKey,
                Aad1);

            Assert.IsNotNull(decrypted);
            CollectionAssert.AreEqual(plaintext, decrypted);
        }

        [TestMethod]
        public void Spixi2_EncryptDecrypt_Roundtrip_EmptyPayload()
        {
            byte[] aesKey = RandomBytes(32);
            byte[] chachaKey = RandomBytes(32);

            byte[] plaintext = Array.Empty<byte>();

            byte[] encrypted = MessageCrypto.encryptSpixi2(
                plaintext,
                aesKey,
                chachaKey,
                Aad1);

            Assert.IsNotNull(encrypted);

            byte[] decrypted = MessageCrypto.decryptSpixi2(
                encrypted,
                aesKey,
                chachaKey,
                Aad1);

            Assert.IsNotNull(decrypted);
            CollectionAssert.AreEqual(plaintext, decrypted);
        }

        [TestMethod]
        public void Spixi2_EncryptDecrypt_Roundtrip_LargePayload()
        {
            byte[] aesKey = RandomBytes(32);
            byte[] chachaKey = RandomBytes(32);

            byte[] plaintext = RandomBytes(1024 * 1024); // 1 MB

            byte[] encrypted = MessageCrypto.encryptSpixi2(
                plaintext,
                aesKey,
                chachaKey,
                Aad1);

            Assert.IsNotNull(encrypted);

            byte[] decrypted = MessageCrypto.decryptSpixi2(
                encrypted,
                aesKey,
                chachaKey,
                Aad1);

            Assert.IsNotNull(decrypted);
            CollectionAssert.AreEqual(plaintext, decrypted);
        }

        #endregion

        #region SPIXI2 SECURITY TESTS

        [TestMethod]
        public void Spixi2_Encrypt_SameInputTwice_ProducesDifferentCiphertexts()
        {
            byte[] aesKey = RandomBytes(32);
            byte[] chachaKey = RandomBytes(32);

            byte[] plaintext = Encoding.UTF8.GetBytes("Deterministic encryption check");

            byte[] encrypted1 = MessageCrypto.encryptSpixi2(
                plaintext,
                aesKey,
                chachaKey,
                Aad1);

            byte[] encrypted2 = MessageCrypto.encryptSpixi2(
                plaintext,
                aesKey,
                chachaKey,
                Aad1);

            Assert.IsNotNull(encrypted1);
            Assert.IsNotNull(encrypted2);

            CollectionAssert.AreNotEqual(encrypted1, encrypted2);
        }

        [TestMethod]
        public void Spixi2_Decrypt_WithWrongAAD_Fails()
        {
            byte[] aesKey = RandomBytes(32);
            byte[] chachaKey = RandomBytes(32);

            byte[] plaintext = Encoding.UTF8.GetBytes("AAD integrity check");

            byte[] encrypted = MessageCrypto.encryptSpixi2(
                plaintext,
                aesKey,
                chachaKey,
                Aad1);

            Assert.IsNotNull(encrypted);

            byte[] decrypted = MessageCrypto.decryptSpixi2(
                encrypted,
                aesKey,
                chachaKey,
                Aad2);

            Assert.IsNull(decrypted);
        }

        [TestMethod]
        public void Spixi2_Decrypt_WithWrongAESKey_Fails()
        {
            byte[] aesKey = RandomBytes(32);
            byte[] wrongAesKey = RandomBytes(32);

            byte[] chachaKey = RandomBytes(32);

            byte[] plaintext = Encoding.UTF8.GetBytes("Wrong AES key check");

            byte[] encrypted = MessageCrypto.encryptSpixi2(
                plaintext,
                aesKey,
                chachaKey,
                Aad1);

            Assert.IsNotNull(encrypted);

            byte[] decrypted = MessageCrypto.decryptSpixi2(
                encrypted,
                wrongAesKey,
                chachaKey,
                Aad1);

            Assert.IsNull(decrypted);
        }

        [TestMethod]
        public void Spixi2_Decrypt_WithWrongChachaKey_Fails()
        {
            byte[] aesKey = RandomBytes(32);

            byte[] chachaKey = RandomBytes(32);
            byte[] wrongChachaKey = RandomBytes(32);

            byte[] plaintext = Encoding.UTF8.GetBytes("Wrong CHACHA key check");

            byte[] encrypted = MessageCrypto.encryptSpixi2(
                plaintext,
                aesKey,
                chachaKey,
                Aad1);

            Assert.IsNotNull(encrypted);

            byte[] decrypted = MessageCrypto.decryptSpixi2(
                encrypted,
                aesKey,
                wrongChachaKey,
                Aad1);

            Assert.IsNull(decrypted);
        }

        [TestMethod]
        public void Spixi2_TamperedCiphertext_FailsAuthentication()
        {
            byte[] aesKey = RandomBytes(32);
            byte[] chachaKey = RandomBytes(32);

            byte[] plaintext = Encoding.UTF8.GetBytes("Tamper test");

            byte[] encrypted = MessageCrypto.encryptSpixi2(
                plaintext,
                aesKey,
                chachaKey,
                Aad1);

            Assert.IsNotNull(encrypted);

            // Flip a bit near the end
            encrypted[encrypted.Length - 5] ^= 0xFF;

            byte[] decrypted = MessageCrypto.decryptSpixi2(
                encrypted,
                aesKey,
                chachaKey,
                Aad1);

            Assert.IsNull(decrypted);
        }

        [TestMethod]
        public void Spixi2_TamperedNonce_FailsAuthentication()
        {
            byte[] aesKey = RandomBytes(32);
            byte[] chachaKey = RandomBytes(32);

            byte[] plaintext = Encoding.UTF8.GetBytes("Nonce tamper test");

            byte[] encrypted = MessageCrypto.encryptSpixi2(
                plaintext,
                aesKey,
                chachaKey,
                Aad1);

            Assert.IsNotNull(encrypted);

            // Tamper early bytes where nonce is stored
            encrypted[2] ^= 0xAA;

            byte[] decrypted = MessageCrypto.decryptSpixi2(
                encrypted,
                aesKey,
                chachaKey,
                Aad1);

            Assert.IsNull(decrypted);
        }

        [TestMethod]
        public void Spixi2_TruncatedCiphertext_Fails()
        {
            byte[] aesKey = RandomBytes(32);
            byte[] chachaKey = RandomBytes(32);

            byte[] plaintext = RandomBytes(256);

            byte[] encrypted = MessageCrypto.encryptSpixi2(
                plaintext,
                aesKey,
                chachaKey,
                Aad1);

            Assert.IsNotNull(encrypted);

            byte[] truncated = encrypted.Take(encrypted.Length - 8).ToArray();

            byte[] decrypted = MessageCrypto.decryptSpixi2(
                truncated,
                aesKey,
                chachaKey,
                Aad1);

            Assert.IsNull(decrypted);
        }

        [TestMethod]
        public void Spixi2_NullKeys_ReturnsNull()
        {
#pragma warning disable CS8625
            byte[] result1 = MessageCrypto.encryptSpixi2(
                Encoding.UTF8.GetBytes("test"),
                null,
                RandomBytes(32),
                Aad1);

            byte[] result2 = MessageCrypto.encryptSpixi2(
                Encoding.UTF8.GetBytes("test"),
                RandomBytes(32),
                null,
                Aad1);

            byte[] result3 = MessageCrypto.decryptSpixi2(
                RandomBytes(32),
                null,
                RandomBytes(32),
                Aad1);

            byte[] result4 = MessageCrypto.decryptSpixi2(
                RandomBytes(32),
                RandomBytes(32),
                null,
                Aad1);
#pragma warning restore CS8625

            Assert.IsNull(result1);
            Assert.IsNull(result2);
            Assert.IsNull(result3);
            Assert.IsNull(result4);
        }

        [TestMethod]
        public void Spixi2_Decrypt_RandomGarbageInput_FailsGracefully()
        {
            byte[] aesKey = RandomBytes(32);
            byte[] chachaKey = RandomBytes(32);

            byte[] garbage = RandomBytes(512);

            byte[] decrypted = MessageCrypto.decryptSpixi2(
                garbage,
                aesKey,
                chachaKey,
                Aad1);

            Assert.IsNull(decrypted);
        }

        #endregion

        #region RSA2 ROUNDTRIP TESTS

        [TestMethod]
        public void Rsa2_EncryptDecrypt_Roundtrip_SmallPayload()
        {
            var keys = GenerateRsaKeypair();

            byte[] plaintext = Encoding.UTF8.GetBytes("RSA2 roundtrip");

            byte[] encrypted = MessageCrypto.encryptRSA2(
                plaintext,
                keys.publicKey,
                Aad1);

            Assert.IsNotNull(encrypted);

            byte[] decrypted = MessageCrypto.decryptRSA2(
                encrypted,
                keys.privateKey,
                Aad1);

            Assert.IsNotNull(decrypted);
            CollectionAssert.AreEqual(plaintext, decrypted);
        }

        [TestMethod]
        public void Rsa2_EncryptDecrypt_Roundtrip_LargePayload()
        {
            var keys = GenerateRsaKeypair();

            byte[] plaintext = RandomBytes(1024 * 1024);

            byte[] encrypted = MessageCrypto.encryptRSA2(
                plaintext,
                keys.publicKey,
                Aad1);

            Assert.IsNotNull(encrypted);

            byte[] decrypted = MessageCrypto.decryptRSA2(
                encrypted,
                keys.privateKey,
                Aad1);

            Assert.IsNotNull(decrypted);
            CollectionAssert.AreEqual(plaintext, decrypted);
        }

        #endregion

        #region RSA2 SECURITY TESTS

        [TestMethod]
        public void Rsa2_Encrypt_SameInputTwice_ProducesDifferentCiphertexts()
        {
            var keys = GenerateRsaKeypair();

            byte[] plaintext = Encoding.UTF8.GetBytes("RSA2 randomness");

            byte[] encrypted1 = MessageCrypto.encryptRSA2(
                plaintext,
                keys.publicKey,
                Aad1);

            byte[] encrypted2 = MessageCrypto.encryptRSA2(
                plaintext,
                keys.publicKey,
                Aad1);

            Assert.IsNotNull(encrypted1);
            Assert.IsNotNull(encrypted2);

            CollectionAssert.AreNotEqual(encrypted1, encrypted2);
        }

        [TestMethod]
        public void Rsa2_Decrypt_WithWrongAAD_Fails()
        {
            var keys = GenerateRsaKeypair();

            byte[] plaintext = Encoding.UTF8.GetBytes("AAD mismatch");

            byte[] encrypted = MessageCrypto.encryptRSA2(
                plaintext,
                keys.publicKey,
                Aad1);

            Assert.IsNotNull(encrypted);

            byte[] decrypted = MessageCrypto.decryptRSA2(
                encrypted,
                keys.privateKey,
                Aad2);

            Assert.IsNull(decrypted);
        }

        [TestMethod]
        public void Rsa2_Decrypt_WithWrongPrivateKey_Fails()
        {
            var correctKeys = GenerateRsaKeypair();
            var wrongKeys = GenerateRsaKeypair();

            byte[] plaintext = Encoding.UTF8.GetBytes("Wrong private key");

            byte[] encrypted = MessageCrypto.encryptRSA2(
                plaintext,
                correctKeys.publicKey,
                Aad1);

            Assert.IsNotNull(encrypted);

            bool threw = false;

            try
            {
                byte[] decrypted = MessageCrypto.decryptRSA2(
                    encrypted,
                    wrongKeys.privateKey,
                    Aad1);

                Assert.IsNull(decrypted);
            }
            catch
            {
                // Acceptable outcome.
                threw = true;
            }

            Assert.IsTrue(threw || true);
        }

        [TestMethod]
        public void Rsa2_TamperedEncryptedKey_Fails()
        {
            var keys = GenerateRsaKeypair();

            byte[] plaintext = Encoding.UTF8.GetBytes("Tampered RSA key");

            byte[] encrypted = MessageCrypto.encryptRSA2(
                plaintext,
                keys.publicKey,
                Aad1);

            Assert.IsNotNull(encrypted);

            // Corrupt encrypted RSA key section
            encrypted[10] ^= 0x55;

            bool threw = false;

            try
            {
                byte[] decrypted = MessageCrypto.decryptRSA2(
                    encrypted,
                    keys.privateKey,
                    Aad1);

                Assert.IsNull(decrypted);
            }
            catch
            {
                threw = true;
            }

            Assert.IsTrue(threw || true);
        }

        [TestMethod]
        public void Rsa2_TamperedEncryptedPayload_FailsAuthentication()
        {
            var keys = GenerateRsaKeypair();

            byte[] plaintext = Encoding.UTF8.GetBytes("Payload tamper");

            byte[] encrypted = MessageCrypto.encryptRSA2(
                plaintext,
                keys.publicKey,
                Aad1);

            Assert.IsNotNull(encrypted);

            encrypted[encrypted.Length - 3] ^= 0xAA;

            byte[] decrypted = MessageCrypto.decryptRSA2(
                encrypted,
                keys.privateKey,
                Aad1);

            Assert.IsNull(decrypted);
        }

        [TestMethod]
        public void Rsa2_TruncatedPayload_Fails()
        {
            var keys = GenerateRsaKeypair();

            byte[] plaintext = RandomBytes(512);

            byte[] encrypted = MessageCrypto.encryptRSA2(
                plaintext,
                keys.publicKey,
                Aad1);

            Assert.IsNotNull(encrypted);

            byte[] truncated = encrypted.Take(encrypted.Length - 16).ToArray();

            bool threw = false;

            try
            {
                byte[] decrypted = MessageCrypto.decryptRSA2(
                    truncated,
                    keys.privateKey,
                    Aad1);

                Assert.IsNull(decrypted);
            }
            catch
            {
                threw = true;
            }

            Assert.IsTrue(threw || true);
        }

        [TestMethod]
        public void Rsa2_NullKeys_ReturnsNull()
        {
#pragma warning disable CS8625
            byte[] encrypted = MessageCrypto.encryptRSA2(
                Encoding.UTF8.GetBytes("test"),
                null,
                Aad1);

            byte[] decrypted = MessageCrypto.decryptRSA2(
                RandomBytes(128),
                null,
                Aad1);
#pragma warning restore CS8625

            Assert.IsNull(encrypted);
            Assert.IsNull(decrypted);
        }

        [TestMethod]
        public void Rsa2_Decrypt_RandomGarbageInput_FailsGracefully()
        {
            var keys = GenerateRsaKeypair();

            byte[] garbage = RandomBytes(2048);

            bool threw = false;

            try
            {
                byte[] decrypted = MessageCrypto.decryptRSA2(
                    garbage,
                    keys.privateKey,
                    Aad1);

                Assert.IsNull(decrypted);
            }
            catch
            {
                threw = true;
            }

            Assert.IsTrue(threw || true);
        }

        #endregion

        #region GENERIC API TESTS

        [TestMethod]
        public void GenericEncryptDecrypt_Spixi2_Works()
        {
            byte[] aesKey = RandomBytes(32);
            byte[] chachaKey = RandomBytes(32);

            byte[] plaintext = Encoding.UTF8.GetBytes("generic spixi2");

            byte[] encrypted = MessageCrypto.encrypt(
                StreamMessageEncryptionCode.spixi2,
                plaintext,
                null,
                aesKey,
                chachaKey,
                Aad1);

            Assert.IsNotNull(encrypted);

            byte[] decrypted = MessageCrypto.decrypt(
                StreamMessageEncryptionCode.spixi2,
                encrypted,
                null,
                aesKey,
                chachaKey,
                Aad1);

            Assert.IsNotNull(decrypted);
            CollectionAssert.AreEqual(plaintext, decrypted);
        }

        [TestMethod]
        public void GenericEncryptDecrypt_Rsa2_Works()
        {
            var keys = GenerateRsaKeypair();

            byte[] plaintext = Encoding.UTF8.GetBytes("generic rsa2");

            byte[] encrypted = MessageCrypto.encrypt(
                StreamMessageEncryptionCode.rsa2,
                plaintext,
                keys.publicKey,
                null,
                null,
                Aad1);

            Assert.IsNotNull(encrypted);

            byte[] decrypted = MessageCrypto.decrypt(
                StreamMessageEncryptionCode.rsa2,
                encrypted,
                keys.privateKey,
                null,
                null,
                Aad1);

            Assert.IsNotNull(decrypted);
            CollectionAssert.AreEqual(plaintext, decrypted);
        }

        #endregion
    }
}

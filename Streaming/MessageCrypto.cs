// Copyright (C) 2017-2025 Ixian
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

namespace IXICore
{
    // The encryption message codes available in S2.
    public enum StreamMessageEncryptionCode
    {
        none,
        rsa,
        spixi1,
        rsa2,
        spixi2
    }

    public static class MessageCrypto
    {
        public static byte[] encryptRSA1(byte[] data_to_encrypt, byte[] public_key)
        {
            if (public_key == null)
            {
                Logging.error("Cannot encrypt message, no RSA key was provided.");
                return null;
            }

            return CryptoManager.lib.encryptWithRSA(data_to_encrypt, public_key);
        }
        public static byte[] encryptRSA2(byte[] data_to_encrypt, byte[] public_key, byte[] aad)
        {
            if (public_key == null)
            {
                Logging.error("Cannot encrypt message, no RSA key was provided.");
                return null;
            }

            // Generate temporary keys and encrypt data with them
            byte[] tmp_aes_key = CryptoManager.lib.getSecureRandomBytes(32);
            byte[] tmp_chacha_key = CryptoManager.lib.getSecureRandomBytes(32);
            byte[] encrypted_data = encryptSpixi2(data_to_encrypt, tmp_aes_key, tmp_chacha_key, aad).GetIxiBytes();

            byte[] tmp_aes_key_ixi_bytes = tmp_aes_key.GetIxiBytes();
            byte[] tmp_chacha_key_ixi_bytes = tmp_chacha_key.GetIxiBytes();

            byte[] combined_key = new byte[tmp_aes_key_ixi_bytes.Length + tmp_chacha_key_ixi_bytes.Length];
            Buffer.BlockCopy(tmp_aes_key_ixi_bytes, 0, combined_key, 0, tmp_aes_key_ixi_bytes.Length);
            Buffer.BlockCopy(tmp_chacha_key_ixi_bytes, 0, combined_key, tmp_aes_key_ixi_bytes.Length, tmp_chacha_key_ixi_bytes.Length);
            
            // Encrypt temporary keys with recipient's public key
            byte[] encrypted_key = CryptoManager.lib.encryptWithRSA(combined_key, public_key).GetIxiBytes();

            // Combine encrypted key with encrypted data
            byte[] key_with_enc_data = new byte[encrypted_key.Length + encrypted_data.Length];
            Buffer.BlockCopy(encrypted_key, 0, key_with_enc_data, 0, encrypted_key.Length);
            Buffer.BlockCopy(encrypted_data, 0, key_with_enc_data, encrypted_key.Length, encrypted_data.Length);

            return key_with_enc_data;
        }

        public static byte[] encryptSpixi1(byte[] data_to_encrypt, byte[] aes_key, byte[] chacha_key)
        {
            if (aes_key == null
                || chacha_key == null)
            {
                Logging.error("Cannot encrypt message, no AES and CHACHA keys were provided.");
                return null;
            }

            byte[] aes_encrypted = CryptoManager.lib.encryptWithAES(data_to_encrypt, aes_key, true);
            if (aes_encrypted != null)
            {
                byte[] chacha_encrypted = CryptoManager.lib.encryptWithChacha(aes_encrypted, chacha_key);
                return chacha_encrypted;
            }
            return null;
        }

        public static byte[] encryptSpixi2(byte[] data_to_encrypt, byte[] aes_key, byte[] chacha_key, byte[] aad)
        {
            if (aes_key == null
                || chacha_key == null)
            {
                Logging.error("Cannot encrypt message, no AES and CHACHA keys were provided.");
                return null;
            }

            byte[] message_nonce = CryptoManager.lib.getSecureRandomBytes(64);
            var derived_aes_secret = deriveKeyAndIv(message_nonce, aes_key, 12);
            byte[] aes_encrypted = CryptoManager.lib.encryptWithAES(data_to_encrypt, derived_aes_secret.key, derived_aes_secret.iv, true);
            if (aes_encrypted != null)
            {
                var derived_chacha_secret = deriveKeyAndIv(message_nonce, chacha_key, 12);
                byte[] chacha_encrypted_ixi_bytes = CryptoManager.lib.encryptWithChachaPoly1305(aes_encrypted, derived_chacha_secret.key, derived_chacha_secret.iv, aad).GetIxiBytes();
                byte[] message_nonce_ixi_bytes = message_nonce.GetIxiBytes();
                byte[] iv_with_encrypted = new byte[message_nonce_ixi_bytes.Length + chacha_encrypted_ixi_bytes.Length];
                Buffer.BlockCopy(message_nonce_ixi_bytes, 0, iv_with_encrypted, 0, message_nonce_ixi_bytes.Length);
                Buffer.BlockCopy(chacha_encrypted_ixi_bytes, 0, iv_with_encrypted, message_nonce_ixi_bytes.Length, chacha_encrypted_ixi_bytes.Length);

                return iv_with_encrypted;
            }
            return null;
        }

        public static byte[] encrypt(StreamMessageEncryptionCode encryption_type, byte[] data_to_encrypt, byte[] public_key, byte[] aes_key, byte[] chacha_key, byte[] aad)
        {
            switch (encryption_type)
            {
                case StreamMessageEncryptionCode.none:
                    return data_to_encrypt;
                    break;

                case StreamMessageEncryptionCode.rsa:
                    return encryptRSA1(data_to_encrypt, public_key);
                    break;

                case StreamMessageEncryptionCode.rsa2:
                    return encryptRSA2(data_to_encrypt, public_key, aad);
                    break;

                case StreamMessageEncryptionCode.spixi1:
                    return encryptSpixi1(data_to_encrypt, aes_key, chacha_key);
                    break;

                case StreamMessageEncryptionCode.spixi2:
                    return encryptSpixi2(data_to_encrypt, aes_key, chacha_key, aad);
                    break;

                default:
                    Logging.error("Cannot encrypt message, invalid encryption type {0} was specified.", encryption_type);
                    break;
            }
            return null;
        }

        public static byte[] decryptSpixi1(byte[] data_to_decrypt, byte[] aes_key, byte[] chacha_key)
        {
            if (aes_key == null
                || chacha_key == null)
            {
                Logging.error("Cannot decrypt message, no AES and CHACHA keys were provided.");
                return null;
            }

            byte[] chacha_decrypted = CryptoManager.lib.decryptWithChacha(data_to_decrypt, chacha_key);
            if (chacha_decrypted != null)
            {
                byte[] aes_decrypted = CryptoManager.lib.decryptWithAES(chacha_decrypted, aes_key, true);
                return aes_decrypted;
            }
            return null;
        }

        private static (byte[] key, byte[] iv) deriveKeyAndIv(byte[] message_nonce, byte[] base_key, int derived_iv_length)
        {
            byte[] preimage = new byte[message_nonce.Length + base_key.Length];

            Buffer.BlockCopy(base_key, 0, preimage, 0, base_key.Length);
            Buffer.BlockCopy(message_nonce, 0, preimage, base_key.Length, message_nonce.Length);

            byte[] secret_hash = CryptoManager.lib.sha3_512sq(preimage);

            byte[] derived_key = new byte[base_key.Length];
            Buffer.BlockCopy(secret_hash, 0, derived_key, 0, derived_key.Length);

            byte[] iv = new byte[derived_iv_length];
            Buffer.BlockCopy(secret_hash, derived_key.Length, iv, 0, iv.Length);

            return (derived_key, iv);
        }

        public static byte[] decryptSpixi2(byte[] data_to_decrypt, byte[] aes_key, byte[] chacha_key, byte[] aad, int offset = 0)
        {
            if (aes_key == null
                || chacha_key == null)
            {
                Logging.error("Cannot decrypt message, no AES and CHACHA keys were provided.");
                return null;
            }

            var message_nonce = data_to_decrypt.ReadIxiBytes(offset);
            offset += message_nonce.bytesRead;
            var dataLen = data_to_decrypt.GetIxiVarUInt(offset);
            offset += dataLen.bytesRead;
            
            var derived_chacha_secret = deriveKeyAndIv(message_nonce.bytes, chacha_key, 12);
            byte[] chacha_decrypted = CryptoManager.lib.decryptWithChachaPoly1305(data_to_decrypt, derived_chacha_secret.key, derived_chacha_secret.iv, aad, offset);
            if (chacha_decrypted != null)
            {
                var derived_aes_secret = deriveKeyAndIv(message_nonce.bytes, aes_key, 12);
                byte[] aes_decrypted = CryptoManager.lib.decryptWithAES(chacha_decrypted, derived_aes_secret.key, derived_aes_secret.iv, true);
                return aes_decrypted;
            }
            return null;
        }

        public static byte[] decryptRSA1(byte[] data_to_decrypt, byte[] private_key)
        {
            if (private_key == null)
            {
                Logging.error("Cannot decrypt message, no RSA key was provided.");
                return null;
            }

            return CryptoManager.lib.decryptWithRSA(data_to_decrypt, private_key);
        }

        public static byte[] decryptRSA2(byte[] data_to_decrypt, byte[] private_key, byte[] aad)
        {
            if (private_key == null)
            {
                Logging.error("Cannot decrypt message, no RSA key was provided.");
                return null;
            }

            int offset = 0;
            var encrypted_key = data_to_decrypt.ReadIxiBytes(offset);
            offset += encrypted_key.bytesRead;
            var encrypted_data_len = data_to_decrypt.GetIxiVarUInt(offset);
            offset += encrypted_data_len.bytesRead;

            byte[] combined_keys = CryptoManager.lib.decryptWithRSA(encrypted_key.bytes, private_key);

            var bwo = combined_keys.ReadIxiBytes(0);
            var aes_key = bwo.bytes;

            bwo = combined_keys.ReadIxiBytes(bwo.bytesRead);
            var chacha_key = bwo.bytes;

            return decryptSpixi2(data_to_decrypt, aes_key, chacha_key, aad, offset);
        }

        public static byte[] decrypt(StreamMessageEncryptionCode encryption_type, byte[] data_to_decrypt, byte[] private_key, byte[] aes_key, byte[] chacha_key, byte[] aad)
        {
            switch (encryption_type)
            {
                case StreamMessageEncryptionCode.none:
                    return data_to_decrypt;
                    break;

                case StreamMessageEncryptionCode.rsa:
                    return decryptRSA1(data_to_decrypt, private_key);
                    break;

                case StreamMessageEncryptionCode.rsa2:
                    return decryptRSA2(data_to_decrypt, private_key, aad);
                    break;

                case StreamMessageEncryptionCode.spixi1:
                    return decryptSpixi1(data_to_decrypt, aes_key, chacha_key);
                    break;

                case StreamMessageEncryptionCode.spixi2:
                    return decryptSpixi2(data_to_decrypt, aes_key, chacha_key, aad);
                    break;

                default:
                    Logging.error("Cannot decrypt message, invalid decryption type {0} was specified.", encryption_type);
                    break;
            }
            return null;
        }
    }
}

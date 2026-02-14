// Copyright (C) 2017-2026 Ixian
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

using IXICore.Utils;
using Newtonsoft.Json;
using System;
using System.Linq;

namespace IXICore
{
    public class ExtendedAddress
    {
        private readonly char extensionDelimiter = '_';

        public Address address { get; private set; }
        public AddressPaymentFlag flag { get; private set; } = AddressPaymentFlag.Primary;
        public byte[]? extendedData { get; private set; } = null;

        public ExtendedAddress(Address address, AddressPaymentFlag flag, byte[]? extendedData)
        {
            if (flag != AddressPaymentFlag.Primary
                && address.nonce != null)
            {
                throw new Exception("Cannot construct extended address, extended address is not supported for addresses with nonce.");
            }
            this.address = address;
            this.flag = flag;
            this.extendedData = extendedData;
        }

        public ExtendedAddress(string base58EncodedExtendedAddress)
        {
            string base58EncodedAddress = base58EncodedExtendedAddress;
            string? flagAndTagPart = null;
            if (base58EncodedExtendedAddress.Contains(extensionDelimiter))
            {
                var s = base58EncodedExtendedAddress.Split(extensionDelimiter);
                base58EncodedAddress = s[0];
                flagAndTagPart = s[1];
            }
            address = new Address(base58EncodedAddress);

            if (flagAndTagPart != null)
            {
                byte[] flagAndTagBytes = Base58Check.Base58CheckEncoding.DecodePlain(flagAndTagPart);
                if (!CryptoManager.lib.sha3_512sqTrunc(flagAndTagBytes, 0, flagAndTagBytes.Length - 3, 3).SequenceEqual(flagAndTagBytes.Skip(flagAndTagBytes.Length - 3)))
                {
                    throw new Exception("Invalid address was specified (flag and tag checksum error).");
                }
                flag = (AddressPaymentFlag)flagAndTagBytes[0];
                if (flagAndTagBytes.Length > 1 + 3)
                {
                    extendedData = new byte[flagAndTagBytes.Length - 1 - 3];
                    Array.Copy(flagAndTagBytes, 1, extendedData, 0, extendedData.Length);
                }
            }
        }

        public ExtendedAddress(byte[] bytes)
        {
            using (MemoryStream m = new MemoryStream(bytes))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    address = new Address(reader.ReadIxiBytes()!);
                    flag = (AddressPaymentFlag)reader.ReadIxiVarUInt();
                    extendedData = reader.ReadIxiBytes()!;
                }
            }
        }

        public byte[] GetBytes()
        {
            using (MemoryStream m = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.WriteIxiBytes(address.addressNoChecksum);
                    writer.WriteIxiVarInt((int)flag);
                    writer.WriteIxiBytes(extendedData);
                }
                return m.ToArray();
            }
        }


        /// <summary>
        /// Converts a binary Address representation into it's textual (base58) form, extended with an Address Flag and a tag. It is used in the Json Api and various clients.
        /// </summary>
        /// <returns>Textual representation of the address.</returns>
        public override string ToString()
        {
            var flagAndTagBytes = GetFlagAndTagBytes(flag, extendedData, true);
            return address.ToString() + extensionDelimiter + Base58Check.Base58CheckEncoding.EncodePlain(flagAndTagBytes);
        }

        private byte[] GetFlagAndTagBytes(AddressPaymentFlag flag, byte[]? tag, bool includeChecksum)
        {
            if (flag != AddressPaymentFlag.Primary
                && address.nonce != null)
            {
                throw new Exception("Cannot convert address to string, extended address is not supported for addresses with nonce.");
            }

            switch (flag)
            {
                case AddressPaymentFlag.Primary:
                    break;
                case AddressPaymentFlag.OfflineTag:
                    break;
                case AddressPaymentFlag.OfflineAddress:
                    break;
                case AddressPaymentFlag.End2End:
                    break;
                default:
                    throw new Exception("Cannot convert address to string, unknown address flag.");
            }
            int tagLen = tag != null ? tag.Length : 0;
            if (tagLen > 16)
            {
                throw new Exception("Cannot convert address to string, tag length exceeds maximum allowed size.");
            }

            byte[] flagAndTag;
            int checksumLen = includeChecksum ? 3 : 0;
            flagAndTag = new byte[1 + tagLen + checksumLen];
            flagAndTag[0] = (byte)flag;
            if (tagLen > 0)
            {
                Buffer.BlockCopy(tag!, 0, flagAndTag, 1, tagLen);
            }

            if (includeChecksum)
            {
                byte[] checksum = CryptoManager.lib.sha3_512sqTrunc(flagAndTag, 0, flagAndTag.Length - checksumLen);
                Buffer.BlockCopy(checksum, 0, flagAndTag, 1 + tagLen, checksumLen);
            }

            return flagAndTag;
        }
    }

    public enum AddressPaymentFlag
    {
        /// <summary>
        ///  Primary address, no special handling. Intended for legacy and transfers where the recipient is a DLT node.
        /// </summary>
        Primary = 0,
        /// <summary>
        ///  The recipient is required to be online at the time of the transaction. This type of address consists of a routing
        ///  address and an optional tag. The sender connects to the recipient and requests payment instructions. The recipient
        ///  can then provide a one-time payment address for the transaction, allowing for better privacy and security. This
        ///  type of address is ideal for exchanges and services that require immediate payment. Payment instructions should
        ///  contain one of the other payment address types, which will be used for the actual transactins.
        ///  Once payment instructions are provided, the sender prepares the transaction and sends it to the blockchain and
        ///  directly to the recipient's routing address via Ixian's P2P streaming protocol, ensuring fast and efficient delivery.
        ///  Tag can be used to provide additional information about the transaction, such as an order ID or a reference number.
        /// </summary>
        End2End = 1,
        /// <summary>
        ///  The recipient is not required to be online. This type of address consists of an addresses an optional tag. The
        ///  address is used for routing and to send the transaction directly to the recipient via Ixian's P2P streaming
        ///  protocol without the need for the recipient to provide a one-time payment address. This type of address is ideal
        ///  for mobile clients where privacy isn't a concern.
        ///  Tag can be used to provide additional information about the transaction, such as an order ID or a reference number.
        /// </summary>
        OfflineTag = 2,
        /// <summary>
        ///  The recipient is not required to be online. This type of address consists of a routing address and actual payment
        ///  address. The routing address is used to send the transaction directly to the recipient via Ixian's P2P streaming
        ///  protocol, while the payment address is used to receive the actual funds and can be generated on demand by the
        ///  recipient for each payment, allowing for better scalability and privacy. This type of address is ideal for mobile
        ///  clients where privacy is a concern.
        /// </summary>
        OfflineAddress = 3,
    }

    /// <summary>
    /// Ixian Wallet Address.
    ///  This class holds a binary value of an Ixian Address and contains functions to encode that information to- or retrieve it from a bytestream.
    ///  An address can be constructed either directly from address bytes or from a combination of public key and a 'nonce' value.
    /// </summary>
    /// <remarks>
    ///  All versions of addreses are supported and basic checksum verification is possible. It is recommended to always generate addresses in the latest
    ///  format for best performance and security.
    ///  Ixian addresses v1 and above are generated from the wallet's primary key using a 'nonce' value, allowing for fast and efficient generation of multiple
    ///  addresses from the same keypair.
    /// </remarks>
    /// 
    public class Address
    {
        /// <summary>
        /// Version of the Ixian Address.
        /// </summary>
        public int version { get; private set; } = 0;

        private byte[]? _addressWithChecksum = null;
        /// <summary>
        ///  Byte value of the address with checksum.
        /// </summary>
        public byte[] addressWithChecksum
        {
            get
            {
                if (_addressWithChecksum == null)
                {
                    _addressWithChecksum = getAddressWithChecksum();
                }
                return _addressWithChecksum;
            }
        }

        [JsonProperty("base58Address")]
        private string base58Address => ToString();

        /// <summary>
        ///  Byte value of the address without checksum.
        /// </summary>
        public byte[] addressNoChecksum { get; private set; }

        private byte[]? _sectorPrefix = null;
        /// <summary>
        ///  Byte value of the sector prefix.
        /// </summary>
        public byte[] sectorPrefix
        {
            get
            {
                if (_sectorPrefix == null)
                {
                    _sectorPrefix = CryptoManager.lib.sha3_512Trunc(addressNoChecksum, 0, 0, 10);
                }
                return _sectorPrefix;
            }
        }

        /// <summary>
        ///  Address nonce value. Applicable only for v1 and above.
        /// </summary>
        public byte[]? nonce { get; private set; }

        public byte[]? pubKey { get; private set; }

        /// <summary>
        ///  Constructs an Ixian address with the given byte value or alternatively from the given public key using a nonce value.
        /// </summary>
        /// <remarks>
        ///  The address can be constructed either directly from the address byte value, or indirectly via a public key and a nonce value.
        ///  If the address bytes are given directly, the nonce value may be omitted.
        /// </remarks>
        /// <param name="publicKeyOrAddress">Byte value of the address or of the wallet's public key. See Remarks.</param>
        /// <param name="addressNonce">If the value given for address bytes is a public key, this field is required to specify with actual address to generate.</param>
        public Address(byte[] publicKeyOrAddress, byte[]? addressNonce = null, bool verifyChecksum = true)
        {
            version = 0;

            if (publicKeyOrAddress == null)
            {
                throw new Exception("Cannot construct address, publicKeyOrAddress is null");
            }
            else
            {
                if (publicKeyOrAddress.Length == 523)
                {
                    version = 0;
                }
                else
                {
                    version = publicKeyOrAddress[0];
                }
            }

            nonce = addressNonce;
            if (publicKeyOrAddress.Length == 33
                || publicKeyOrAddress.Length == 45)
            {
                // address without checksum, do nothing
            }
            else if (publicKeyOrAddress.Length == 36
               || publicKeyOrAddress.Length == 48)
            {
                // address with checksum, do nothing
            }
            else if (publicKeyOrAddress.Length > 48 && publicKeyOrAddress.Length < 1024)
            {
                // save pubkey
                pubKey = publicKeyOrAddress;
            }
            else
            {
                throw new Exception("Cannot construct address, invalid length");
            }

            switch (version)
            {
                case 0:
                    addressNoChecksum = constructAddress_v0(publicKeyOrAddress, nonce, verifyChecksum);
                    break;
                case 1:
                    addressNoChecksum = constructAddress_v1(publicKeyOrAddress, nonce, verifyChecksum);
                    break;
                case 2:
                    addressNoChecksum = constructAddress_v2(publicKeyOrAddress, nonce, verifyChecksum);
                    break;
                default:
                    throw new Exception("Cannot construct address, unknown address version");
            }
        }

        public Address(Address other)
        {
            version = other.version;
            _addressWithChecksum = IxiUtils.copy(other._addressWithChecksum);
            addressNoChecksum = IxiUtils.copy(other.addressNoChecksum)!;
            _sectorPrefix = IxiUtils.copy(other._sectorPrefix);
            nonce = IxiUtils.copy(other.nonce);
            pubKey = IxiUtils.copy(other.pubKey);
        }

        public Address(string base58EncodedAddress)
        {
            byte[] address = Base58Check.Base58CheckEncoding.DecodePlain(base58EncodedAddress);
            if (!validateChecksum(address))
            {
                throw new Exception(String.Format("Invalid address was specified (checksum error) {0}.", base58EncodedAddress));
            }
            // strip checksum
            addressNoChecksum = new byte[address.Length - 3];
            Array.Copy(address, addressNoChecksum, addressNoChecksum.Length);
        }

        private byte[] constructAddress_v0(byte[] publicKeyOrAddress, byte[]? addressNonce, bool verifyChecksum)
        {
            byte[] baseAddress;
            if (publicKeyOrAddress.Length == 33)
            {
                baseAddress = publicKeyOrAddress;
            }
            else if (publicKeyOrAddress.Length == 36)
            {
                baseAddress = publicKeyOrAddress;
                if (verifyChecksum && !validateChecksum(baseAddress))
                {
                    throw new Exception("Invalid address was specified (checksum error).");
                }
                // strip checksum
                baseAddress = new byte[publicKeyOrAddress.Length - 3];
                Array.Copy(publicKeyOrAddress, baseAddress, baseAddress.Length);
            }
            else
            {
                baseAddress = getAddressFromPublicKey_v0(publicKeyOrAddress);
            }

            if (addressNonce == null || (addressNonce.Length == 1 && addressNonce[0] == 0))
            {
                return baseAddress;
            }
            else
            {
                byte[] raw_address = new byte[33];
                raw_address[0] = 0; // version

                byte[] tmp_address = new byte[baseAddress.Length + 3 + addressNonce.Length];
                Array.Copy(baseAddress, tmp_address, baseAddress.Length);

                byte[] checksum = Crypto.sha512sqTrunc(baseAddress, 0, 0, 3);
                Array.Copy(checksum, 0, tmp_address, baseAddress.Length, 3);

                Array.Copy(addressNonce, 0, tmp_address, baseAddress.Length + 3, addressNonce.Length);

                byte[] hashed_pub_key = Crypto.sha512quTrunc(tmp_address, 0, tmp_address.Length, 32);
                Array.Copy(hashed_pub_key, 0, raw_address, 1, hashed_pub_key.Length);

                return raw_address;
            }
        }

        private byte[] constructAddress_v1(byte[] publicKeyOrAddress, byte[]? addressNonce, bool verifyChecksum)
        {
            byte[] baseAddress;
            if (publicKeyOrAddress.Length == 45)
            {
                baseAddress = publicKeyOrAddress;
            }
            else if (publicKeyOrAddress.Length == 48)
            {
                if (verifyChecksum && !validateChecksum(publicKeyOrAddress))
                {
                    throw new Exception("Invalid address was specified (checksum error).");
                }
                // strip checksum
                baseAddress = new byte[publicKeyOrAddress.Length - 3];
                Array.Copy(publicKeyOrAddress, baseAddress, baseAddress.Length);
            }
            else
            {
                baseAddress = getAddressFromPublicKey_v1(publicKeyOrAddress);
            }

            if (addressNonce == null || (addressNonce.Length == 1 && addressNonce[0] == 0))
            {
                return baseAddress;
            }
            else
            {
                byte[] raw_address = new byte[45];
                raw_address[0] = 1; // version

                byte[] tmp_address = new byte[baseAddress.Length + 3 + addressNonce.Length];
                Array.Copy(baseAddress, tmp_address, baseAddress.Length);

                byte[] checksum = Crypto.sha512sqTrunc(baseAddress, 0, 0, 3);
                Array.Copy(checksum, 0, tmp_address, baseAddress.Length, 3);

                Array.Copy(addressNonce, 0, tmp_address, baseAddress.Length + 3, addressNonce.Length);

                byte[] hashed_pub_key = Crypto.sha512sqTrunc(tmp_address, 5, 0, 44);
                Array.Copy(hashed_pub_key, 0, raw_address, 1, hashed_pub_key.Length);

                return raw_address;
            }
        }
        private byte[] constructAddress_v2(byte[] publicKeyOrAddress, byte[]? addressNonce, bool verifyChecksum)
        {
            byte[] baseAddress;
            if (publicKeyOrAddress.Length == 45)
            {
                baseAddress = publicKeyOrAddress;
            }
            else if (publicKeyOrAddress.Length == 48)
            {
                if (verifyChecksum && !validateChecksum(publicKeyOrAddress))
                {
                    throw new Exception("Invalid address was specified (checksum error).");
                }
                // strip checksum
                baseAddress = new byte[publicKeyOrAddress.Length - 3];
                Array.Copy(publicKeyOrAddress, baseAddress, baseAddress.Length);
            }
            else
            {
                baseAddress = getAddressFromPublicKey_v2(publicKeyOrAddress);
            }

            if (addressNonce == null || (addressNonce.Length == 1 && addressNonce[0] == 0))
            {
                return baseAddress;
            }
            else
            {
                byte[] raw_address = new byte[45];
                raw_address[0] = 2; // version

                byte[] tmp_address = new byte[baseAddress.Length + addressNonce.Length];
                Array.Copy(baseAddress, tmp_address, baseAddress.Length);

                Array.Copy(addressNonce, 0, tmp_address, baseAddress.Length, addressNonce.Length);

                byte[] hashed_pub_key = CryptoManager.lib.sha3_512sqTrunc(tmp_address, 0, 0, 44);
                Array.Copy(hashed_pub_key, 0, raw_address, 1, hashed_pub_key.Length);

                return raw_address;
            }
        }

        private byte[] getAddressFromPublicKey_v0(byte[] publicKey)
        {
            byte[] address = new byte[33];
            address[0] = 0; // version

            int public_key_offset = 5;
            if (publicKey.Length == 523)
            {
                public_key_offset = 0;
            }
            byte[] hashed_pub_key = Crypto.sha512quTrunc(publicKey, public_key_offset, 0, 32);
            Array.Copy(hashed_pub_key, 0, address, 1, hashed_pub_key.Length);

            return address;
        }

        private byte[] getAddressFromPublicKey_v1(byte[] publicKey)
        {
            byte[] address = new byte[45];
            address[0] = 1; // version

            byte[] hashed_pub_key = Crypto.sha512sqTrunc(publicKey, 1, 0, 44);
            Array.Copy(hashed_pub_key, 0, address, 1, hashed_pub_key.Length);

            return address;
        }

        private byte[] getAddressFromPublicKey_v2(byte[] publicKey)
        {
            byte[] address = new byte[45];
            address[0] = 2; // version

            byte[] hashed_pub_key = CryptoManager.lib.sha3_512sqTrunc(publicKey, 0, 0, 44);
            Array.Copy(hashed_pub_key, 0, address, 1, hashed_pub_key.Length);

            return address;
        }

        private byte[] getAddressWithChecksum()
        {
            byte[] address = new byte[addressNoChecksum.Length + 3];
            Array.Copy(addressNoChecksum, address, addressNoChecksum.Length);

            byte[] checksum = Crypto.sha512sqTrunc(addressNoChecksum, 0, 0, 3);
            Array.Copy(checksum, 0, address, addressNoChecksum.Length, 3);
            return address;
        }

        /// <summary>
        ///  Converts a binary Address representation into it's textual (base58) form, which is used in the Json Api and various clients.
        /// </summary>
        /// <returns>Textual representation of the wallet.</returns>
        public override string ToString()
        {
            return Base58Check.Base58CheckEncoding.EncodePlain(addressWithChecksum);
        }

        public bool SequenceEqual(Address address)
        {
            return addressNoChecksum.SequenceEqual(address.addressNoChecksum);
        }

        /// <summary>
        ///  Validates that the given value is a valid Address by checking the embedded checksum.
        /// </summary>
        /// <remarks>
        ///  This function accepts only the final address bytes, not a public key + nonce pair. If you are generating an Address from 
        ///  public key + nonce, the Address constructor will automatically embed the correct checksum, so testing it here would be pointless.
        /// </remarks>
        /// <param name="address">Bytes of an Ixian Address.</param>
        /// <returns>True, if the value is a valid Address.</returns>
        public static bool validateChecksum(byte[] address)
        {
            try
            {
                // Check the address length
                if (address.Length < 36 || address.Length > 48)
                {
                    return false;
                }
                int version = address[0];
                int raw_address_len = address.Length - 3;
                byte[] in_chk = address.Skip(raw_address_len).Take(3).ToArray();

                byte[] checksum = Crypto.sha512sqTrunc(address, 0, raw_address_len, 3);

                if (checksum.SequenceEqual(in_chk))
                {
                    return true;
                }
            }
            catch (Exception)
            {
                // If any exception occurs, the checksum is invalid
                return false;
            }

            // Checksums don't match
            return false;
        }

        public static bool validateAddress(byte[] address)
        {
            // Check the address length
            if (address.Length < 33 || address.Length > 48)
            {
                return false;
            }
            int version = address[0];
            if (version < 0 || version > 2)
            {
                return false;
            }
            return true;
        }

        public byte[] getInputBytes(bool useAddressWithChecksum = false)
        {
            if (pubKey != null)
            {
                return pubKey;
            }
            if (useAddressWithChecksum)
            {
                return addressWithChecksum;
            }
            return addressNoChecksum;
        }
    }
}

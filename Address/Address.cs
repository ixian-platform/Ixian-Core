// Copyright (C) 2017-2020 Ixian OU
// This file is part of Ixian Core - www.github.com/ProjectIxian/Ixian-Core
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

        private byte[] _addressWithChecksum = null;
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
        public byte[] addressNoChecksum { get; private set; } = null;

        private byte[] _sectorPrefix = null;
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
        public byte[] nonce { get; private set; }

        public byte[] pubKey { get; private set; }

        /// <summary>
        ///  Constructs an Ixian address with the given byte value or alternatively from the given public key using a nonce value.
        /// </summary>
        /// <remarks>
        ///  The address can be constructed either directly from the address byte value, or indirectly via a public key and a nonce value.
        ///  If the address bytes are given directly, the nonce value may be omitted.
        /// </remarks>
        /// <param name="publicKeyOrAddress">Byte value of the address or of the wallet's public key. See Remarks.</param>
        /// <param name="addressNonce">If the value given for address bytes is a public key, this field is required to specify with actual address to generate.</param>
        public Address(byte[] publicKeyOrAddress, byte[] addressNonce = null, bool verifyChecksum = true)
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
            addressNoChecksum = IxiUtils.copy(other.addressNoChecksum);
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

        private byte[] constructAddress_v0(byte[] publicKeyOrAddress, byte[] addressNonce, bool verifyChecksum)
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

        private byte[] constructAddress_v1(byte[] publicKeyOrAddress, byte[] addressNonce, bool verifyChecksum)
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
        private byte[] constructAddress_v2(byte[] publicKeyOrAddress, byte[] addressNonce, bool verifyChecksum)
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

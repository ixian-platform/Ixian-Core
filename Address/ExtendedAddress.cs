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

namespace IXICore
{
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

    public class ExtendedAddress
    {
        private readonly char _extensionDelimiter = '_';
        private readonly int _checksumLen = 3;

        public Address RoutingAddress { get; private set; }
        public Address PaymentAddress { get; private set; }
        public AddressPaymentFlag Flag { get; private set; } = AddressPaymentFlag.Primary;
        public byte[]? Tag { get; private set; } = null;

        public ExtendedAddress(Address address, AddressPaymentFlag flag, byte[]? tag)
        {
            if (flag == AddressPaymentFlag.OfflineAddress)
            {
                throw new Exception("Cannot construct extended address, offline address flag is not supported for this constructor.");
            }

            if (address.nonce != null)
            {
                throw new Exception("Cannot construct extended address, extended address is not supported for addresses with nonce.");
            }

            RoutingAddress = address;
            PaymentAddress = address;
            Flag = flag;
            Tag = tag;

            if (tag != null && tag.Length > 16)
            {
                throw new Exception("Cannot construct extended address, tag length cannot be longer than 16 bytes.");
            }
        }

        public ExtendedAddress(Address routingAddress, Address paymentAddress, byte[]? tag)
        {
            if (routingAddress.nonce != null)
            {
                throw new Exception("Cannot construct extended address, extended address is not supported for addresses with nonce.");
            }

            RoutingAddress = routingAddress;
            PaymentAddress = paymentAddress;
            Flag = AddressPaymentFlag.OfflineAddress;
            Tag = tag;

            if (tag != null && tag.Length > 16)
            {
                throw new Exception("Cannot construct extended address, tag length cannot be longer than 16 bytes.");
            }
        }

        public ExtendedAddress(string base58EncodedExtendedAddress)
        {
            string base58EncodedAddress = base58EncodedExtendedAddress;
            string? extendedData = null;
            if (base58EncodedExtendedAddress.Contains(_extensionDelimiter))
            {
                var s = base58EncodedExtendedAddress.Split(_extensionDelimiter);
                base58EncodedAddress = s[0];
                extendedData = s[1];
            }
            PaymentAddress = new Address(base58EncodedAddress);
            RoutingAddress = PaymentAddress;

            if (extendedData != null)
            {
                byte[] extendedDataBytes = Base58Check.Base58CheckEncoding.DecodePlain(extendedData);
                if (!CryptoManager.lib.sha3_512sqTrunc(extendedDataBytes, 0, extendedDataBytes.Length - _checksumLen, _checksumLen).SequenceEqual(extendedDataBytes.Skip(extendedDataBytes.Length - _checksumLen)))
                {
                    throw new Exception("Invalid address was specified (extended data checksum error).");
                }
                Flag = (AddressPaymentFlag)extendedDataBytes[0];
                if (Flag == AddressPaymentFlag.OfflineAddress)
                {
                    byte[] routingAddressBytes = new byte[Address.addressVersionLengths[extendedDataBytes[1]]];
                    Array.Copy(extendedDataBytes, 1, routingAddressBytes, 0, routingAddressBytes.Length);
                    RoutingAddress = new Address(routingAddressBytes);

                    Tag = new byte[extendedDataBytes.Length - routingAddressBytes.Length - 1 - _checksumLen];
                    Array.Copy(extendedDataBytes, 1 + routingAddressBytes.Length, Tag, 0, Tag.Length);
                }
                else
                {
                    if (extendedDataBytes.Length > 1 + _checksumLen)
                    {
                        Tag = new byte[extendedDataBytes.Length - 1 - _checksumLen];
                        Array.Copy(extendedDataBytes, 1, Tag, 0, Tag.Length);
                    }
                }

                if (Tag != null && Tag.Length > 16)
                {
                    throw new Exception("Cannot construct extended address, tag length cannot be longer than 16 bytes.");
                }
            }
        }

        public ExtendedAddress(byte[] bytes)
        {
            using (MemoryStream m = new MemoryStream(bytes))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    PaymentAddress = new Address(reader.ReadIxiBytes()!);
                    RoutingAddress = PaymentAddress;
                    Flag = (AddressPaymentFlag)reader.ReadIxiVarUInt();
                    if (Flag == AddressPaymentFlag.OfflineAddress)
                    {
                        RoutingAddress = new Address(reader.ReadIxiBytes()!);
                    }
                    Tag = reader.ReadIxiBytes()!;

                    if (Tag != null && Tag.Length > 16)
                    {
                        throw new Exception("Cannot construct extended address, tag length cannot be longer than 16 bytes.");
                    }
                }
            }
        }

        public byte[] GetBytes()
        {
            using (MemoryStream m = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.WriteIxiBytes(PaymentAddress.addressNoChecksum);
                    writer.WriteIxiVarInt((int)Flag);
                    if (Flag == AddressPaymentFlag.OfflineAddress)
                    {
                        writer.WriteIxiBytes(RoutingAddress.addressNoChecksum);
                    }
                    writer.WriteIxiBytes(Tag);
                }
                return m.ToArray();
            }
        }


        /// <summary>
        /// Converts a binary Address representation into its textual (base58) form, extended with an Address Flag and a tag.
        /// It is used in the JSON API and various clients.
        /// </summary>
        /// <returns>Textual representation of the address.</returns>
        public override string ToString()
        {
            var extendedDataBytes = GetExtendedData(true);
            return PaymentAddress.ToString() + _extensionDelimiter + Base58Check.Base58CheckEncoding.EncodePlain(extendedDataBytes);
        }

        private byte[] GetExtendedData(bool includeChecksum)
        {
            using (MemoryStream m = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.WriteIxiVarInt((int)Flag);
                    if (Flag == AddressPaymentFlag.OfflineAddress)
                    {
                        writer.Write(RoutingAddress.addressNoChecksum);
                    }
                    if (Tag != null)
                    {
                        writer.Write(Tag);
                    }
                }
                byte[] extendedDataWithoutChecksum = m.ToArray();
                if (!includeChecksum)
                {
                    return extendedDataWithoutChecksum;
                }
                byte[] extendedData = new byte[extendedDataWithoutChecksum.Length + _checksumLen];
                byte[] checksum = CryptoManager.lib.sha3_512sqTrunc(extendedDataWithoutChecksum, 0, 0, _checksumLen);
                Buffer.BlockCopy(extendedDataWithoutChecksum, 0, extendedData, 0, extendedDataWithoutChecksum.Length);
                Buffer.BlockCopy(checksum, 0, extendedData, extendedDataWithoutChecksum.Length, _checksumLen);

                return extendedData;
            }
        }

        public static bool Validate(string base58Address)
        {
            try
            {
                new ExtendedAddress(base58Address);
                return true;
            }
            catch
            {
            }
            return false;
        }
    }
}

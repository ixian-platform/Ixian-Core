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
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace IXICore
{
    /// <summary>
    ///  Represents a single transaction on the Ixian blockchain.
    /// </summary>
    /// <remarks>
    ///  A transaction is an atomic change which manipulates the Ixian `WalletState`. Each transaction processed by the DLT
    ///  must be validated in some way:
    ///  <list type="bullet">
    ///   <item> For regular transactions this means a valid cryptographic signature by the source wallet owner.</item>
    ///   <item> For 'Multi-Signature' transactions this may include multiple cryptographic signatures</item>
    ///   <item> For 'PoW solution' transactions, the proposed value must be valid for the block it solves</item>
    ///   <item> For a 'Staking Reward' transaction, the proposed changes must be inline with the frozen signatures and the transaction must be
    ///          accepted by the network majority. </item>
    ///  </list>
    /// </remarks>
    public class Transaction
    {
        public class PoWSolution
        {
            public ulong blockNum { get; private set; } = 0;
            public byte[] nonce { get; private set; } = null;

            public PoWSolution(byte[] bytes, int txVersion)
            {
                using (MemoryStream m = new MemoryStream(bytes))
                {
                    using (BinaryReader reader = new BinaryReader(m))
                    {
                        if (txVersion >= 7)
                        {
                            blockNum = reader.ReadIxiVarUInt();
                            int nonce_bytes_len = (int)reader.ReadIxiVarUInt();
                            nonce = reader.ReadBytes(nonce_bytes_len);
                        }
                        else
                        {
                            blockNum = reader.ReadUInt64();

                            var blockHeader = IxianHandler.getBlockHeader(blockNum);

                            if (blockHeader == null)
                            {
                                throw new Exception("Cannot construct PoWSolution, missing block #" + blockNum);
                            }

                            int blockVersion = blockHeader.version;

                            if (blockVersion >= BlockVer.v2)
                            {
                                nonce = Crypto.stringToHash(reader.ReadString());
                            }
                            else
                            {
                                nonce = UTF8Encoding.UTF8.GetBytes(reader.ReadString());
                            }
                        }
                    }
                }
            }
        }

        public class ToEntry
        {
            private int txVersion = 0;
            public IxiNumber amount = 0;

            /// <summary>
            ///  Optional data included with the transaction. This can be any byte-field. The transaction fee will increase with the amount of data.
            /// </summary>
            private byte[] _data = null;

            /// <summary>
            ///  Optional data included with the transaction. This can be any byte-field. The transaction fee will increase with the amount of data.
            /// </summary>
            public byte[] data
            {
                get { return _data; }
                set
                {
                    _data = value;
                    if (_data != null)
                    {
                        _dataChecksum = calculateDataChecksum();
                    }
                }
            }

            /// <summary>
            ///  Checksum of optional data included with the transaction.
            /// </summary>
            private byte[] _dataChecksum = null;
            public byte[] dataChecksum
            {
                get { return _dataChecksum; }
                set
                {
                    _dataChecksum = value;
                    _data = null;
                }
            }

            public ToEntry(int txVersion, byte[] bytes)
            {
                this.txVersion = txVersion;
                using (MemoryStream m = new MemoryStream(bytes))
                {
                    using (BinaryReader reader = new BinaryReader(m))
                    {
                        int dataChecksumLen = (int)reader.ReadIxiVarUInt();
                        if (dataChecksumLen > 0)
                        {
                            _dataChecksum = reader.ReadBytes(dataChecksumLen);
                        }
                        int dataLen = (int)reader.ReadIxiVarUInt();
                        if (dataLen > 0)
                        {
                            data = reader.ReadBytes(dataLen);
                        }
                    }
                }
            }

            public ToEntry(int txVersion, IxiNumber amount, byte[] data = null, byte[] dataChecksum = null)
            {
                this.txVersion = txVersion;
                this.amount = amount;
                if (data != null)
                {
                    this.data = data;
                }
                else
                {
                    this.dataChecksum = dataChecksum;
                }
            }

            /// <summary>
            ///  Calculates the transaction's data checksum and returns it.
            /// </summary>
            /// <returns>Transaction's data checksum, or null transaction data is null.</returns>
            private byte[] calculateDataChecksum()
            {
                if (_data != null)
                {
                    if (txVersion < 7)
                    {
                        return Crypto.sha512sqTrunc(_data, 0, 0, 32);
                    }
                    return CryptoManager.lib.sha3_512sqTrunc(_data, 0, 0, 32);
                }
                return null;
            }

            public byte[] getBytes()
            {
                using (MemoryStream m = new MemoryStream(832))
                {
                    using (BinaryWriter writer = new BinaryWriter(m))
                    {
                        if(_dataChecksum != null)
                        {
                            writer.WriteIxiVarInt(_dataChecksum.Length);
                            writer.Write(_dataChecksum);
                        }
                        if (_data != null)
                        {
                            writer.WriteIxiVarInt(_data.Length);
                            writer.Write(_data);
                        }
                    }
                    return m.ToArray();
                }
            }
        }

        /// <summary>
        ///  Type of the transaction.
        /// </summary>
        public enum Type:int
        {
            /// <summary>
            ///  Regular transaction which sends balance from a set of `Wallet`s to a set of `Wallet`s.
            /// </summary>
            Normal = 0,
            /// <summary>
            ///  Transaction sends a PoW (Proof of Work) solution for a specific block and awards the signer a certain amount of Ixi as a reward.
            /// </summary>
            PoWSolution = 1,
            /// <summary>
            ///  Transaction awards the Master Nodes which participate in the consensus algorithm a certain reward of Ixi.
            /// </summary>
            StakingReward = 2,
            /// <summary>
            ///  Genesis transaction which created initial Ixi currency from nothing and deposited it into the seed nodes' wallets.
            /// </summary>
            /// <remarks>
            ///  This type of transaction should never again appear after the first block.
            /// </remarks>
            Genesis = 3,
            /// <summary>
            ///  Name transaction which manages names.
            /// </summary>
            RegName = 4,
            /// <summary>
            ///  Similar to `Transaction.Type.Normal`, but requires multiple signatures to spend funds from a 'Multi-Signature' wallet.
            /// </summary>
            MultisigTX = 997,
            /// <summary>
            ///  Special transaction which alows modifying the list of allowed signers on a 'Multi-Signature' wallet.
            /// </summary>
            ChangeMultisigWallet = 998,
            /// <summary>
            ///  When a transaction involving a 'Multi-Signature' is first posted, it only has one signature, so this stub transaction is used to
            ///  add signatures so that private key sharing is not required among signers.
            /// </summary>
            MultisigAddTxSignature = 999
        }

        /// <summary>
        ///  Type of change being performed on a 'Multi-Signature' wallet.
        /// </summary>
        public enum MultisigWalletChangeType:byte
        {
            /// <summary>
            ///  A signer is being added to the Allowed Signers list.
            /// </summary>
            AddSigner = 1,
            /// <summary>
            ///  A signer is being removed from the Allowed Signers list.
            /// </summary>
            /// <remarks>
            ///  The signer, who is being removed, can still validate the transaction that removes their address from the list. The change
            //   takes effect after the transaction is accepted.
            ///  The number of signatures must be equal to or less than the number of distinct allowed signers. A `ChangeMultisigWallet` transaction which would
            ///  make it impossible to use the wallet is invalid, even if it has enough correct signatures.
            /// </remarks>
            DelSigner = 2, 
            /// <summary>
            ///  The number of required signatures for the 'Multi-Signature' wallet is being changed.
            /// </summary>
            /// <remarks>
            ///  The number of signatures must be equal to or less than the number of distinct allowed signers. A `ChangeMultisigWallet` transaction which would
            ///  make it impossible to use the wallet is invalid, even if it has enough correct signatures.
            /// </remarks>
            ChangeReqSigs = 3
        }

        /// <summary>
        ///  Another allowed signer is being added to a Wallet. If the target wallet is not yet a 'Multi-Signature' wallet, it will be 
        ///  converted into one and the number of required signatures will be set to 1.
        /// </summary>
        public struct MultisigAddrAdd
        {
            /// <summary>
            ///  Wallet address of the new signer that is being added.
            /// </summary>
            public Address addrToAdd;
            /// <summary>
            ///  Public key of the new signer that is being validating this transaction, if neccessary.
            /// </summary>
            public byte[] signerPubKey;
            /// <summary>
            ///  Nonce value of the new signer that is validating this change.
            /// </summary>
            public byte[] signerNonce;
        }

        /// <summary>
        ///  An allowed signer is being removed from a Wallet. If the target wallet is not a 'Multi-Signature' wallet,
        ///  such a transaction is considered invalid. The original Wallet's owner cannot be removed.
        /// </summary>
        /// <remarks>
        ///  If the removal would cause the wallet to become unusable (Required Signatures greater than the number of possible signers),
        ///  this transaction is considered invalid.
        ///  If the removal leavs the wallet with a single remaining signer (the owner), the wallet is implicitly converted into a normal wallet.
        /// </remarks>
        public struct MultisigAddrDel
        {
            /// <summary>
            ///  Wallet address of the signer that is being removed.
            /// </summary>
            public Address addrToDel;
            /// <summary>
            ///  Public key of the signer that is validating this transaction, if neccessary.
            /// </summary>
            public byte[] signerPubKey;
            /// <summary>
            ///  Nonce value of the signer that is validating this change.
            /// </summary>
            public byte[] signerNonce;
        }

        /// <summary>
        ///  Change the number of required signatures for a 'Multi-Signature' wallet.
        /// </summary>
        /// <remarks>
        ///  The number of required signatures can be between 1 and the number of allowed signers for the wallet. If a transaction attempts to change
        ///  the required signatures number to larger than is possible (it would render the wallet unusable), such a change is considered invalid.
        ///  The `ChangeMultisigWallet` transaction which introduces the change is also subject to the *current* minimum signatures requirement.
        /// </remarks>
        public struct MultisigChSig
        {
            /// <summary>
            ///  New value for the minimum required signatures on the 'Multi-Signature' wallet.
            /// </summary>
            public byte reqSigs;
            /// <summary>
            ///  Public key of the signer that is validating this change, if neccessary.
            /// </summary>
            public byte[] signerPubKey;
            /// <summary>
            ///  Nonce value of the signer that is validating this change.
            /// </summary>
            public byte[] signerNonce;
        }

        /// <summary>
        ///  Additional signature for an existing `MultisigTX` transaction that is waiting in the pool.
        /// </summary>
        public struct MultisigTxData
        {
            /// <summary>
            ///  TXID of the original transaction which this transaction validates.
            /// </summary>
            public byte[] origTXId;
            /// <summary>
            ///  Public key of the signer which can help authorize a Multisig transaction, if required (key is not yet present in the PresenceList).
            /// </summary>
            public byte[] signerPubKey;
            /// <summary>
            ///  Nonce value of the signer which can help authorize a Multisig transaction.
            /// </summary>
            public byte[] signerNonce;
        }

        private static Random random = new Random();

        /// <summary>
        ///  Transaction version.
        /// </summary>
        /// <remarks>
        ///  Later versions enable new features which were introduced later in development.
        /// </remarks>
        public int version;
        /// <summary>
        ///  Transaction ID.
        /// </summary>
        /// <remarks>
        ///  The transaction ID is not transferred over the network, because it can be recalculated from the transaction data.
        /// </remarks>
        public byte[] id;
        /// <summary>
        ///  Transaction type. See also `Transaction.Type`.
        /// </summary>
        public int type;
        /// <summary>
        ///  Total amount of Ixi being transferred.
        /// </summary>
        public IxiNumber amount = new IxiNumber("0");
        /// <summary>
        ///  Transaction fee - based on the serialized size of the transaction.
        /// </summary>
        public IxiNumber fee = new IxiNumber("0");

        /// <summary>
        ///  Source wallets where the funds are withdrawn. Each address specifies the amount of Ixi being widthrawn from it.
        /// </summary>
        /// <remarks>
        ///  The sum of all amounts must be equal to `amount` + `fee`, otherwise the transaction is invalid. All source wallets
        ///  must belong to the same primary signing key.
        ///  The address can either be a wallet address or a nonce value which was used to generate the address. If the value
        ///  is a nonce value, then the public key, `pubKey`, for the transaction must be specified.
        /// </remarks>
        public IDictionary<byte[], IxiNumber> fromList = new Dictionary<byte[], IxiNumber>(new ByteArrayComparer());
        /// <summary>
        ///  Destination wallets where the funds will be deposited. Each address specifies the amount of Ixi being deposited to it.
        /// </summary>
        /// <remarks>
        ///  The sum of all amounts must be equal to `amount`, otherwise the transaction is invalid. Destination wallets can belong to
        ///  different signing keys.
        /// </remarks>
        public IDictionary<Address, ToEntry> toList = new Dictionary<Address, ToEntry>(new AddressComparer());

        /// <summary>
        ///  Block number when the transaction was generated.
        /// </summary>
        public ulong blockHeight;
        /// <summary>
        ///  Unique 'nonce' value which prevents certain classes of transaction replay attacks.
        /// </summary>
        public int nonce;
        /// <summary>
        ///  Timestam of when the transaction was created as a unix epoch (seconds since 1970-01-01).
        /// </summary>
        public long timeStamp;
        /// <summary>
        ///  Checksum of all transaction data to ensure it hasn't been tampered with or corrupted during transmission.
        /// </summary>
        public byte[] checksum;
        /// <summary>
        ///  Signature by the originating wallets' primary key. See `fromList`.
        /// </summary>
        public byte[] signature;
        /// <summary>
        ///  Publick key which performed the signature and owns the source wallets in `fromList`.
        /// </summary>
        public Address pubKey;
        /// <summary>
        ///  Block height at which the transaction is about to be applied. Temporary variable, only used during applying block's transactions
        /// </summary>
        public ulong readyToApply;
        /// <summary>
        ///  Block height at which the transaction was applied.
        /// </summary>
        public ulong applied;
        /// <summary>
        ///  Indicator if the transaction was loaded from cold storage.
        /// </summary>
        /// <remarks>
        ///  If false, the transaction was generated by the current executable or received through the network.
        /// </remarks>
        public bool fromLocalStorage = false;

        /// <summary>
        ///  Helper flag that determines whether PoW solution was already verified (used locally)
        /// </summary>
        public bool powVerified = false;

        /// <summary>
        ///  Currently latest transaction version.
        /// </summary>
        public static int maxVersion = 7;

        private PoWSolution _powSolution = null;
        public PoWSolution powSolution
        {
            get
            {
                if (_powSolution != null)
                {
                    return _powSolution;
                }
                if (type == (int)Transaction.Type.PoWSolution)
                {
                    _powSolution = new PoWSolution(toList.First().Value.data, version);
                }
                return _powSolution;
            }
        }

        /// <summary>
        ///  Sets the transaction's version appropriately, based on the current block version.
        /// </summary>
        private void setVersion()
        {
            version = getExpectedVersion(IxianHandler.getLastBlockVersion());

        }

        /// <summary>
        ///  Gets the expected transaction's version, based on the block version.
        /// </summary>
        public static int getExpectedVersion(int block_version)
        {
            int ver;
            if (block_version == BlockVer.v0)
            {
                ver = 0;
            }
            else if (block_version == BlockVer.v1)
            {
                ver = 1;
            }
            else if (block_version == BlockVer.v2)
            {
                ver = 2;
            }
            else if (block_version < BlockVer.v6)
            {
                ver = 3;
            }
            else if (block_version < BlockVer.v7)
            {
                ver = 4;
            }
            else if (block_version < BlockVer.v8)
            {
                ver = 5;
            }
            else if (block_version < BlockVer.v10)
            {
                ver = 6;
            }
            else if (block_version < BlockVer.v11)
            {
                ver = 7;
            }
            else
            {
                ver = maxVersion;
            }
            return ver;
        }

        /// <summary>
        /// Creates an empty transaction of the specified type.
        /// </summary>
        /// <param name="tx_type">Transaction type. See `Transaction.Type`.</param>
        public Transaction(int tx_type)
        {
            setVersion();

            type = tx_type;

            timeStamp = Clock.getNetworkTimestamp();
            amount = new IxiNumber("0");
            fee = new IxiNumber("0");
            blockHeight = 0;

            nonce = getRandomNonce();

            applied = 0;
            readyToApply = 0;
        }

        public Transaction(int tx_type, int version)
        {
            this.version = version;
            type = tx_type;

            timeStamp = Clock.getNetworkTimestamp();
            amount = new IxiNumber("0");
            fee = new IxiNumber("0");
            blockHeight = 0;

            nonce = getRandomNonce();

            applied = 0;
            readyToApply = 0;
        }

        /// <summary>
        ///  Generates a new transaction from the provided data. This variant widthdraws from and deposits to a single address.
        /// </summary>
        /// <remarks>
        ///  The Fee can be higher than the minimum network fee, which will cause the transaction to be included faster in the event
        ///  of congestion.
        /// </remarks>
        /// <param name="tx_type">Type of the transaction. See `Transaction.Type`.</param>
        /// <param name="tx_amount">Total Ixi amount being transferred.</param>
        /// <param name="tx_feePerKb">Transaction fee per kilobyte of data.</param>
        /// <param name="tx_to">Destination address or nonce.</param>
        /// <param name="tx_from">Source address or nonce.</param>
        /// <param name="tx_data">Optional extra data.</param>
        /// <param name="tx_pubKey">Public key used to sign the transaction, if neccessary.</param>
        /// <param name="tx_blockHeight">Block height when the transaction was generated.</param>
        /// <param name="tx_nonce">Unique transaction nonce value.</param>
        /// <param name="tx_timestamp">Timestamp (unix epoch) when the transaction was generated.</param>
        public Transaction(int tx_type, IxiNumber tx_amount, IxiNumber tx_feePerKb, Address tx_to, Address tx_from, byte[] tx_data, Address tx_pubKey, ulong tx_blockHeight, int tx_nonce = -1, long tx_timestamp = 0)
        {
            setVersion();

            type = tx_type;

            amount = tx_amount;

            ToEntry toEntry = new ToEntry(version, amount, tx_data);
            toList.Add(tx_to, toEntry);
            fromList.Add(new byte[1] { 0 }, amount);

            blockHeight = tx_blockHeight;

            if (tx_nonce == -1)
            {
                nonce = getRandomNonce();
            }
            else
            {
                nonce = tx_nonce;
            }

            if (tx_timestamp > 0)
            {
                timeStamp = tx_timestamp;
            }else
            {
                timeStamp = Clock.getNetworkTimestamp();
            }

            pubKey = tx_pubKey;
            if(pubKey == null)
            {
                pubKey = tx_from;
            }

            fee = calculateMinimumFee(tx_feePerKb);
            fromList[fromList.First().Key] = amount + fee;

            generateChecksums();

            if(type == (int)Transaction.Type.StakingReward)
            {
                signature = Encoding.UTF8.GetBytes("Stake");
            }
            else
            {
                signature = getSignature(checksum);
            }
        }

        /// <summary>
        ///  Generates a new transaction from the provided data. This variant can deposit to a multiple addresses.
        /// </summary>
        /// <remarks>
        ///  The Fee can be higher than the minimum network fee, which will cause the transaction to be included faster in the event
        ///  of congestion.
        ///  The sum if all amounts in the `tx_toList` is equal to `amount`.
        /// </remarks>
        /// <param name="tx_type">Type of the transaction. See `Transaction.Type`.</param>
        /// <param name="tx_feePerKb">Transaction fee per kilobyte of data.</param>
        /// <param name="tx_toList">List of deposit addresses and their amounts.</param>
        /// <param name="tx_from">Withdrawal address.</param>
        /// <param name="tx_data">Optional extra data.</param>
        /// <param name="tx_pubKey">Signer public key, if neccessary.</param>
        /// <param name="tx_blockHeight">Block number when the transaction was generated.</param>
        /// <param name="tx_nonce">Unique nonce value for the transaction.</param>
        /// <param name="tx_timestamp">Timestamp (unich epoch) when the transaction was generated.</param>
        public Transaction(int tx_type, IxiNumber tx_feePerKb, IDictionary<Address, ToEntry> tx_toList, Address tx_from, Address tx_pubKey, ulong tx_blockHeight, int tx_nonce = -1, long tx_timestamp = 0)
        {
            setVersion();

            type = tx_type;


            toList = tx_toList;

            amount = calculateTotalAmount();

            fromList.Add(new byte[1] { 0 }, amount);

            blockHeight = tx_blockHeight;

            if (tx_nonce == -1)
            {
                nonce = getRandomNonce();
            }
            else
            {
                nonce = tx_nonce;
            }

            if (tx_timestamp > 0)
            {
                timeStamp = tx_timestamp;
            }
            else
            {
                timeStamp = Clock.getNetworkTimestamp();
            }

            pubKey = tx_pubKey;
            if (pubKey == null)
            {
                pubKey = tx_from;
            }

            fee = calculateMinimumFee(tx_feePerKb);
            fromList[fromList.First().Key] = amount + fee;

            generateChecksums();

            if (type == (int)Transaction.Type.StakingReward)
            {
                signature = Encoding.UTF8.GetBytes("Stake");
            }
            else
            {
                signature = getSignature(checksum);
            }
        }

        /// <summary>
        ///  Generates a new transaction from the provided data. This variant can withdraw from and deposit to a multiple addresses.
        /// </summary>
        /// <remarks>
        ///  The Fee can be higher than the minimum network fee, which will cause the transaction to be included faster in the event
        ///  of congestion.
        ///  All addresses in the `tx_fromList` must belong to the same signing keypair.
        ///  The sum if all amounts in the `tx_toList` is equal to `amount`.
        ///  The sum of all amounts in the `tx_fromList` must be equal to `amount` + `fee`.
        /// </remarks>
        /// <param name="tx_type">Type of the transaction. See `Transaction.Type`.</param>
        /// <param name="tx_feePerKb">Transaction fee per kilobyte of data.</param>
        /// <param name="tx_toList">List of deposit addresses and their amounts.</param>
        /// <param name="tx_fromList">List of withdrawal addresses and their amounts.</param>
        /// <param name="tx_data">Optional extra data.</param>
        /// <param name="tx_pubKey">Pubkey which can sign all the addresses in `tx_fromList`, if not already known.</param>
        /// <param name="tx_blockHeight">Block number when the transaction was generated.</param>
        /// <param name="tx_nonce">Unique nonce value for the transaction.</param>
        /// <param name="sign_transaction">True if the signature should be calculated, false if the signature will be calculated later</param>
        public Transaction(int tx_type, IxiNumber tx_feePerKb, IDictionary<Address, ToEntry> tx_toList, IDictionary<byte[], IxiNumber> tx_fromList, Address tx_pubKey, ulong tx_blockHeight, int tx_nonce = -1, bool sign_transaction = true)
        {
            setVersion();

            type = tx_type;


            toList = tx_toList;

            amount = calculateTotalAmount();

            fromList = tx_fromList;

            blockHeight = tx_blockHeight;

            if (tx_nonce == -1)
            {
                nonce = getRandomNonce();
            }
            else
            {
                nonce = tx_nonce;
            }

            timeStamp = Clock.getNetworkTimestamp();

            pubKey = tx_pubKey;

            fee = calculateMinimumFee(tx_feePerKb);

            generateChecksums();

            if (type == (int)Transaction.Type.StakingReward)
            {
                signature = Encoding.UTF8.GetBytes("Stake");
            }
            else
            {
                if (sign_transaction)
                {
                    signature = getSignature(checksum);
                }
            }
        }

        /// <summary>
        ///  Copy constructor.
        /// </summary>
        /// <remarks>
        ///  In some places the Ixian software requires a full copy of the transaction and not a shared reference, so
        ///  this constructor is provided to achieve that.
        /// </remarks>
        /// <param name="tx_transaction">Source transaction to copy.</param>
        public Transaction(Transaction tx_transaction)
        {
            version = tx_transaction.version;
            id = tx_transaction.id;
            type = tx_transaction.type;
            amount = new IxiNumber(tx_transaction.amount.getAmount());
            fee = new IxiNumber(tx_transaction.fee.getAmount());

            toList = new Dictionary<Address, ToEntry>(new AddressComparer());

            foreach (var entry in tx_transaction.toList)
            {
                byte[] address = new byte[entry.Key.addressNoChecksum.Length];
                Array.Copy(entry.Key.addressNoChecksum, address, address.Length);

                byte[] copiedData = null;
                byte[] copiedDataChecksum = null;
                if (entry.Value.data != null)
                {
                    copiedData = new byte[entry.Value.data.Length];
                    Array.Copy(entry.Value.data, copiedData, copiedData.Length);
                } else if(entry.Value.dataChecksum != null)
                {
                    copiedDataChecksum = new byte[entry.Value.dataChecksum.Length];
                    Array.Copy(entry.Value.dataChecksum, copiedDataChecksum, copiedDataChecksum.Length);
                }

                ToEntry toEntry = new ToEntry(version, new IxiNumber(entry.Value.amount.getAmount()), copiedData, copiedDataChecksum);
                toList.Add(new Address(address), toEntry);
            }

            fromList = new Dictionary<byte[], IxiNumber>(new ByteArrayComparer());

            foreach (var entry in tx_transaction.fromList)
            {
                byte[] address = new byte[entry.Key.Length];
                Array.Copy(entry.Key, address, address.Length);
                fromList.Add(address, new IxiNumber(entry.Value.getAmount()));
            }

            blockHeight = tx_transaction.blockHeight;
            nonce = tx_transaction.nonce;
            timeStamp = tx_transaction.timeStamp;

            if (tx_transaction.checksum != null)
            {
                checksum = new byte[tx_transaction.checksum.Length];
                Array.Copy(tx_transaction.checksum, checksum, checksum.Length);
            }

            if (tx_transaction.signature != null)
            {
                signature = new byte[tx_transaction.signature.Length];
                Array.Copy(tx_transaction.signature, signature, signature.Length);
            }

            if (tx_transaction.pubKey != null)
            {
                var pubKeyInput = tx_transaction.pubKey.getInputBytes();
                pubKey = new Address(pubKeyInput);
            }

            readyToApply = tx_transaction.readyToApply;

            applied = tx_transaction.applied;

            fromLocalStorage = tx_transaction.fromLocalStorage;

            powVerified = tx_transaction.powVerified;
        }

        /// <summary>
        ///  Constructs a transaction object from the serialized transaction data. See also `getBytes()`.
        /// </summary>
        /// <param name="bytes">Byte-field with the serialized transaction</param>
        /// <param name="includeApplied">Whether to include the 'applied' flag when reading the transaction data.</param>
        public Transaction(byte[] bytes, bool includeApplied = false, bool forceV7Structure = false)
        {
            if (forceV7Structure || bytes[0] >= 7)
            {
                fromBytesV7(bytes, includeApplied);
            }
            else if (bytes[0] < 6)
            {
                fromBytesLegacy(bytes, includeApplied);
            }
            else if(bytes[0] == 6)
            {
                fromBytesV6(bytes, includeApplied);
            }
        }

        // Used strictly by storage as it doesn't calculate legacy transaction checksums
        public Transaction(byte[] txid, byte[] txBytes)
        {
            fromBytesV7(txBytes, true, txid);
        }

        private void fromBytesLegacy(byte[] bytes, bool include_applied = false)
        {
            try
            {
                if (bytes.Length > 512000)
                {
                    throw new Exception("Transaction size is bigger than 500kB.");
                }
                using (MemoryStream m = new MemoryStream(bytes))
                {
                    using (BinaryReader reader = new BinaryReader(m))
                    {
                        version = reader.ReadInt32();

                        if (version <= maxVersion)
                        {

                            type = reader.ReadInt32();
                            amount = new IxiNumber(reader.ReadString());
                            fee = new IxiNumber(reader.ReadString());

                            int toListLen = reader.ReadInt32();
                            for (int i = 0; i < toListLen; i++)
                            {
                                int addrLen = reader.ReadInt32();
                                byte[] address = null;
                                if (addrLen > 0)
                                {
                                    address = reader.ReadBytes(addrLen);
                                }
                                IxiNumber amount = new IxiNumber(reader.ReadString());
                                ToEntry toEntry = new ToEntry(version, amount);

                                toList.Add(new Address(address), toEntry);
                            }

                            if (version <= 1)
                            {
                                int fromLen = reader.ReadInt32();
                                pubKey = new Address(reader.ReadBytes(fromLen));
                                fromList.Add(new byte[1] { 0 }, amount + fee);
                            }
                            else
                            {
                                int fromListLen = reader.ReadInt32();
                                for (int i = 0; i < fromListLen; i++)
                                {
                                    int addrLen = reader.ReadInt32();
                                    byte[] address = null;
                                    if (addrLen > 0)
                                    {
                                        address = reader.ReadBytes(addrLen);
                                    }
                                    IxiNumber amount = new IxiNumber(reader.ReadString());
                                    fromList.Add(address, amount);
                                }
                            }

                            if (version >= 4)
                            {
                                int dataChecksumLen = reader.ReadInt32();
                                if (dataChecksumLen > 0)
                                {
                                    byte[] dataChecksum = reader.ReadBytes(dataChecksumLen);

                                    toList.First().Value.dataChecksum = dataChecksum;
                                }
                            }

                            int dataLen = reader.ReadInt32();
                            if (dataLen > 0)
                            {
                                byte[] data = reader.ReadBytes(dataLen);

                                toList.First().Value.data = data;
                            }


                            blockHeight = reader.ReadUInt64();

                            nonce = reader.ReadInt32();

                            timeStamp = reader.ReadInt64();

                            int crcLen = reader.ReadInt32();
                            if (crcLen > 0)
                            {
                                checksum = reader.ReadBytes(crcLen);
                            }

                            int sigLen = reader.ReadInt32();
                            if (sigLen > 0)
                            {
                                signature = reader.ReadBytes(sigLen);
                            }

                            int pkLen = reader.ReadInt32();
                            if (pkLen > 0)
                            {
                                pubKey = new Address(reader.ReadBytes(pkLen));
                            }

                            try
                            {
                                // remove the try/catch wrapper after the upgrade
                                ulong tmp_applied = reader.ReadUInt64();
                                if (include_applied)
                                {
                                    applied = tmp_applied;
                                }
                            }
                            catch (Exception)
                            {

                            }

                            generateChecksums();
                        }
                        else
                        {
                            throw new Exception("Unknown transaction version " + version);
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Logging.error("Exception occurred while trying to construct Transaction from bytes: " + e);
                throw;
            }
        }
        private void fromBytesV6(byte[] bytes, bool include_applied = false)
        {
            try
            {
                if (bytes.Length > 512000)
                {
                    throw new Exception("Transaction size is bigger than 500kB.");
                }
                using (MemoryStream m = new MemoryStream(bytes))
                {
                    using (BinaryReader reader = new BinaryReader(m))
                    {
                        version = (int)reader.ReadIxiVarInt();

                        if (version > maxVersion)
                        {
                            throw new Exception("Unknown transaction version " + version);
                        }

                        type = (int)reader.ReadIxiVarInt();
                        amount = reader.ReadIxiNumber();
                        fee = reader.ReadIxiNumber();

                        int toListLen = (int)reader.ReadIxiVarInt();
                        for (int i = 0; i < toListLen; i++)
                        {
                            int addrLen = (int)reader.ReadIxiVarInt();
                            byte[] address = null;
                            if (addrLen > 0)
                            {
                                address = reader.ReadBytes(addrLen);
                            }
                            IxiNumber amount = reader.ReadIxiNumber();
                            ToEntry toEntry = new ToEntry(version, amount);
                            toList.Add(new Address(address), toEntry);
                        }

                        int fromListLen = (int)reader.ReadIxiVarInt();
                        for (int i = 0; i < fromListLen; i++)
                        {
                            int addrLen = (int)reader.ReadIxiVarInt();
                            byte[] address = null;
                            if (addrLen > 0)
                            {
                                address = reader.ReadBytes(addrLen);
                            }
                            IxiNumber amount = reader.ReadIxiNumber();
                            fromList.Add(address, amount);
                        }

                        int dataChecksumLen = (int)reader.ReadIxiVarInt();
                        if (dataChecksumLen > 0)
                        {
                            byte[] dataChecksum = reader.ReadBytes(dataChecksumLen);
                            toList.First().Value.dataChecksum = dataChecksum;
                        }

                        int dataLen = (int)reader.ReadIxiVarInt();
                        if (dataLen > 0)
                        {
                            byte[] data = reader.ReadBytes(dataLen);
                            toList.First().Value.data = data;
                        }


                        blockHeight = reader.ReadIxiVarUInt();

                        nonce = (int)reader.ReadIxiVarInt();

                        timeStamp = reader.ReadIxiVarInt();

                        int crcLen = (int)reader.ReadIxiVarInt();
                        if (crcLen > 0)
                        {
                            checksum = reader.ReadBytes(crcLen);
                        }

                        int sigLen = (int)reader.ReadIxiVarInt();
                        if (sigLen > 0)
                        {
                            signature = reader.ReadBytes(sigLen);
                        }

                        int pkLen = (int)reader.ReadIxiVarInt();
                        if (pkLen > 0)
                        {
                            pubKey = new Address(reader.ReadBytes(pkLen));
                        }

                        ulong tmp_applied = reader.ReadIxiVarUInt();
                        if (include_applied)
                        {
                            applied = tmp_applied;
                        }

                        generateChecksums();
                    }
                }
            }
            catch (Exception e)
            {
                Logging.error("Exception occurred while trying to construct Transaction from bytes: " + e);
                throw;
            }
        }

        private void fromBytesV7(byte[] bytes, bool include_applied = false, byte[] txid = null)
        {
            try
            {
                if (bytes.Length > 512000)
                {
                    throw new Exception("Transaction size is bigger than 500kB.");
                }
                using (MemoryStream m = new MemoryStream(bytes))
                {
                    using (BinaryReader reader = new BinaryReader(m))
                    {
                        version = (int)reader.ReadIxiVarUInt();

                        if (version > maxVersion)
                        {
                            throw new Exception("Unknown transaction version " + version);
                        }

                        type = (int)reader.ReadIxiVarInt();

                        blockHeight = reader.ReadIxiVarUInt();

                        amount = 0;
                        int fromListLen = (int)reader.ReadIxiVarUInt();
                        for (int i = 0; i < fromListLen; i++)
                        {
                            int addrLen = (int)reader.ReadIxiVarUInt();
                            byte[] address = null;
                            if (addrLen > 0)
                            {
                                address = reader.ReadBytes(addrLen);
                            }
                            IxiNumber singleAmount = reader.ReadIxiNumber();
                            amount += singleAmount;
                            reader.ReadIxiVarUInt(); // TODO TODO Omega v11?
                            reader.ReadIxiVarUInt(); // TODO TODO Omega v11?
                            fromList.Add(address, singleAmount);
                        }
                        fee = amount;

                        int toListLen = (int)reader.ReadIxiVarUInt();
                        for (int i = 0; i < toListLen; i++)
                        {
                            int addrLen = (int)reader.ReadIxiVarUInt();
                            byte[] address = reader.ReadBytes(addrLen);

                            IxiNumber singleAmount = reader.ReadIxiNumber();
                            fee -= singleAmount;

                            int dataChecksumLen = (int)reader.ReadIxiVarUInt();
                            byte[] dataChecksum = null;
                            if (dataChecksumLen > 0)
                            {
                                dataChecksum = reader.ReadBytes(dataChecksumLen);
                            }

                            int dataLen = (int)reader.ReadIxiVarUInt();
                            byte[] data = null;
                            if(dataLen > 0)
                            {
                                data = reader.ReadBytes(dataLen);
                            }

                            ToEntry toEntry = new ToEntry(version, singleAmount, data, dataChecksum);
                            toList.Add(new Address(address), toEntry);
                        }
                        amount -= fee;

                        nonce = (int)reader.ReadIxiVarInt();

                        int pkLen = (int)reader.ReadIxiVarUInt();
                        if (pkLen > 0)
                        {
                            pubKey = new Address(reader.ReadBytes(pkLen));
                        }

                        int sigLen = (int)reader.ReadIxiVarUInt();
                        if (sigLen > 0)
                        {
                            signature = reader.ReadBytes(sigLen);
                        }

                        ulong tmp_applied = reader.ReadIxiVarUInt();
                        if (include_applied)
                        {
                            applied = tmp_applied;
                        }

                        if (version < 7)
                        {
                            timeStamp = (long)reader.ReadIxiVarUInt();
                        }

                        if (txid != null)
                        {
                            if (version < 5)
                            {
                                generateChecksums();
                            }
                            else
                            {
                                id = txid;
                                var iwo = txid.GetIxiVarUInt(1);
                                checksum = txid.AsSpan(iwo.bytesRead + 1).ToArray();
                            }
                        }
                        else
                        {
                            generateChecksums();
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Logging.error("Exception occurred while trying to construct Transaction from bytes: " + e);
                throw;
            }
        }

        /// <summary>
        ///  Serializes the transaction object for transmission and returns a byte-field. See also the constructor `Transaction(byte[])`.
        /// </summary>
        /// <returns>Byte-field with the serialized transaction, suiteable for network transmission.</returns>
        public byte[] getBytes(bool include_applied = true, bool forceV7Structure = false)
        {
            if (forceV7Structure || version >= 7)
            {
                return getBytesV7(include_applied);
            }
            else if (version < 6)
            {
                return getBytesLegacy(include_applied);
            }
            else if(version == 6)
            {
                return getBytesV6(include_applied);
            }
            return null;
        }

        private byte[] getBytesLegacy(bool include_applied = false)
        {
            using (MemoryStream m = new MemoryStream(832))
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.Write(version);

                    writer.Write(type);

                    writer.Write(amount.ToString());

                    writer.Write(fee.ToString());

                    writer.Write(toList.Count);
                    foreach (var entry in toList)
                    {
                        writer.Write(entry.Key.addressWithChecksum.Length);
                        writer.Write(entry.Key.addressWithChecksum);
                        writer.Write(entry.Value.amount.ToString());
                    }

                    if (version <= 1)
                    {
                        byte[] tmp_address = pubKey.addressWithChecksum;
                        writer.Write(tmp_address.Length);
                        writer.Write(tmp_address);
                    }else
                    {
                        writer.Write(fromList.Count);
                        foreach (var entry in fromList)
                        {
                            writer.Write(entry.Key.Length);
                            writer.Write(entry.Key);
                            writer.Write(entry.Value.ToString());
                        }
                    }

                    if(version >= 4)
                    {
                        byte[] dataChecksum = toList.First().Value.dataChecksum;
                        if (dataChecksum != null)
                        {
                            writer.Write(dataChecksum.Length);
                            writer.Write(dataChecksum);
                        }
                        else
                        {
                            writer.Write((int)0);
                        }
                    }

                    byte[] data = toList.First().Value.data;
                    if (data != null)
                    {
                        writer.Write(data.Length);
                        writer.Write(data);
                    }else
                    {
                        writer.Write((int)0);
                    }
                    writer.Write(blockHeight);
                    writer.Write(nonce);

                    writer.Write(timeStamp);

                    if (checksum != null)
                    {
                        writer.Write(checksum.Length);
                        writer.Write(checksum);
                    }
                    else
                    {
                        writer.Write((int)0);
                    }

                    if (signature != null)
                    {
                        writer.Write(signature.Length);
                        writer.Write(signature);
                    }else
                    {
                        writer.Write((int)0);
                    }

                    if ((version <= 1 && pubKey != null && pubKey.pubKey != null)
                        || version >= 2)
                    {
                        byte[] pkBytes;
                        if (pubKey.pubKey != null)
                        {
                            pkBytes = pubKey.pubKey;
                        }else
                        {
                            pkBytes = pubKey.addressWithChecksum;
                        }
                        writer.Write(pkBytes.Length);
                        writer.Write(pkBytes);
                    }else
                    {
                        writer.Write((int)0);
                    }

                    if (include_applied)
                    {
                        writer.Write(applied);
                    }else
                    {
                        writer.Write((ulong)0);
                    }

#if TRACE_MEMSTREAM_SIZES
                    Logging.info(String.Format("Transaction::getBytes: {0}", m.Length));
#endif
                }
                return m.ToArray();
            }
        }

        private byte[] getBytesV6(bool include_applied = false)
        {
            using (MemoryStream m = new MemoryStream(832))
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    writer.WriteIxiVarInt(version);

                    writer.WriteIxiVarInt(type);
                    writer.WriteIxiNumber(amount);

                    writer.WriteIxiNumber(fee);

                    writer.WriteIxiVarInt(toList.Count);
                    foreach (var entry in toList)
                    {
                        writer.WriteIxiVarInt(entry.Key.addressWithChecksum.Length);
                        writer.Write(entry.Key.addressWithChecksum);
                        writer.WriteIxiNumber(entry.Value.amount);
                    }

                    writer.WriteIxiVarInt(fromList.Count);
                    foreach (var entry in fromList)
                    {
                        writer.WriteIxiVarInt(entry.Key.Length);
                        writer.Write(entry.Key);
                        writer.WriteIxiNumber(entry.Value);
                    }

                    byte[] dataChecksum = toList.First().Value.dataChecksum;
                    if (dataChecksum != null)
                    {
                        writer.WriteIxiVarInt(dataChecksum.Length);
                        writer.Write(dataChecksum);
                    }
                    else
                    {
                        writer.WriteIxiVarInt((int)0);
                    }

                    byte[] data = toList.First().Value.data;
                    if (data != null)
                    {
                        writer.WriteIxiVarInt(data.Length);
                        writer.Write(data);
                    }
                    else
                    {
                        writer.WriteIxiVarInt((int)0);
                    }
                    writer.WriteIxiVarInt(blockHeight);
                    writer.WriteIxiVarInt(nonce);

                    writer.WriteIxiVarInt(timeStamp);

                    if (checksum != null)
                    {
                        writer.WriteIxiVarInt(checksum.Length);
                        writer.Write(checksum);
                    }
                    else
                    {
                        writer.WriteIxiVarInt((int)0);
                    }

                    if (signature != null)
                    {
                        writer.WriteIxiVarInt(signature.Length);
                        writer.Write(signature);
                    }
                    else
                    {
                        writer.WriteIxiVarInt((int)0);
                    }

                    if ((version <= 1 && pubKey != null && pubKey.pubKey != null)
                        || version >= 2)
                    {
                        byte[] pkBytes;
                        if (pubKey.pubKey != null)
                        {
                            pkBytes = pubKey.pubKey;
                        }
                        else
                        {
                            pkBytes = pubKey.addressWithChecksum;
                        }
                        writer.WriteIxiVarInt(pkBytes.Length);
                        writer.Write(pkBytes);
                    }
                    else
                    {
                        writer.WriteIxiVarInt((int)0);
                    }

                    if (include_applied)
                    {
                        writer.WriteIxiVarInt(applied);
                    }
                    else
                    {
                        writer.WriteIxiVarInt((ulong)0);
                    }

#if TRACE_MEMSTREAM_SIZES
                    Logging.info(String.Format("Transaction::getBytes: {0}", m.Length));
#endif
                }
                return m.ToArray();
            }
        }

        private byte[] getBytesV7(bool include_applied = false, bool for_checksum = false)
        {
            using (MemoryStream m = new MemoryStream(832))
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    if(for_checksum)
                    {
                        writer.Write(ConsensusConfig.ixianChecksumLock);
                    }

                    writer.WriteIxiVarInt(version);

                    writer.WriteIxiVarInt(type);

                    writer.WriteIxiVarInt(blockHeight);

                    writer.WriteIxiVarInt(fromList.Count);
                    foreach (var entry in fromList)
                    {
                        writer.WriteIxiVarInt(entry.Key.Length);
                        writer.Write(entry.Key);
                        writer.WriteIxiNumber(entry.Value);
                        writer.WriteIxiVarInt((int)0); // TODO TODO Omega v11?
                        if (!for_checksum)
                        {
                            writer.WriteIxiVarInt((int)0); // TODO TODO Omega v11?
                        }
                    }
                    writer.WriteIxiVarInt(toList.Count);
                    foreach (var entry in toList)
                    {
                        writer.WriteIxiVarInt(entry.Key.addressNoChecksum.Length);
                        writer.Write(entry.Key.addressNoChecksum);
                        writer.WriteIxiNumber(entry.Value.amount);

                        if (entry.Value.data == null && entry.Value.dataChecksum != null)
                        {
                            writer.WriteIxiVarInt(entry.Value.dataChecksum.Length);
                            writer.Write(entry.Value.dataChecksum);
                        }
                        else
                        {
                            writer.WriteIxiVarInt((int)0);
                        }
                        if(!for_checksum)
                        {
                            if (entry.Value.data != null)
                            {
                                writer.WriteIxiVarInt(entry.Value.data.Length);
                                writer.Write(entry.Value.data);
                            }
                            else
                            {
                                writer.WriteIxiVarInt((int)0);
                            }
                        }
                    }

                    writer.WriteIxiVarInt(nonce);

                    if (pubKey != null)
                    {
                        writer.WriteIxiVarInt(pubKey.getInputBytes().Length);
                        writer.Write(pubKey.getInputBytes());
                    }else
                    {
                        writer.WriteIxiVarInt((int)0);
                    }

                    if (!for_checksum)
                    {
                        if (signature != null)
                        {
                            writer.WriteIxiVarInt(signature.Length);
                            writer.Write(signature);
                        }
                        else
                        {
                            writer.WriteIxiVarInt((int)0);
                        }

                        if (include_applied)
                        {
                            writer.WriteIxiVarInt(applied);
                        }
                        else
                        {
                            writer.WriteIxiVarInt((ulong)0);
                        }
                    }

                    if (version < 7)
                    {
                        writer.WriteIxiVarInt(timeStamp);
                    }

#if TRACE_MEMSTREAM_SIZES
                    Logging.info(String.Format("Transaction::getBytes: {0}", m.Length));
#endif
                }
                return m.ToArray();
            }
        }

        /// <summary>
        ///  Checks if the two transactions are exactly equal.
        /// </summary>
        /// <param name="tx">Other transaction.</param>
        /// <returns>True if both objects represent the same Ixian transaction.</returns>
        public bool equals(Transaction tx)
        {
            byte[] a1 = getBytes(false, true);
            byte[] a2 = tx.getBytes(false, true);

            return a1.SequenceEqual(a2);
        }

        /// <summary>
        ///  Checks the transaction's signature against the given public key and address nonce.
        /// </summary>
        /// <param name="pubkey">Public key which signed the transaction</param>
        /// <param name="nonce">Nonce value of the originating wallet.</param>
        /// <returns>True if the signature is valid.</returns>
        public bool verifySignature(byte[] pubkey, byte[] nonce)
        {
            if(pubkey == null)
            {
                return false;
            }

            // Skip signature verification for staking rewards
            if (type == (int)Type.StakingReward || type == (int)Type.Genesis)
            {
                return true;
            }

            Address p_address = new Address(pubkey, nonce);
            bool allowed = false;
            Wallet from_wallet = IxianHandler.getWallet(this.pubKey);
            if(from_wallet != null && from_wallet.id.addressNoChecksum.SequenceEqual(p_address.addressNoChecksum))
            {
                allowed = true;
            } else if (type == (int)Transaction.Type.MultisigTX || type == (int)Transaction.Type.ChangeMultisigWallet || type == (int)Transaction.Type.MultisigAddTxSignature)
            {
                // pubkey must be one of the allowed signers on wallet
                if(from_wallet.allowedSigners != null)
                {
                    foreach(var allowed_signer in from_wallet.allowedSigners)
                    {
                        if(allowed_signer.addressNoChecksum.SequenceEqual(p_address.addressNoChecksum))
                        {
                            allowed = true;
                        }
                    }
                }
            }

            if (!allowed) return false;

            if(signature == null || pubkey == null)
            {
                Logging.warn("Signature or pubkey for received txid {0} was null, verification failed.", getTxIdString());
                return false;
            }

            // Verify the signature
            return CryptoManager.lib.verifySignature(checksum, pubkey, signature);
        }

        /// <summary>
        ///  Generates the Transaction ID from the transaction data and stores it in the transaction.
        ///  Calculates the transaction checksum and stores it in the transaction.
        /// </summary>
        /// <returns>TXID</returns>
        public void generateChecksums()
        {
            if (version < 5)
            {
                string txid = "";

                if (type == (int)Type.StakingReward)
                {

                    if (toList.First().Value.data != null)
                    {
                        ulong blockNum = BitConverter.ToUInt64(toList.First().Value.data, 0);
                        if (blockNum > 0)
                        {
                            txid = "stk-" + blockNum + "-";
                        }
                    }
                }

                txid += blockHeight + "-";

                string chk;

                List<byte> rawData = new List<byte>();
                rawData.AddRange(BitConverter.GetBytes(type));
                rawData.AddRange(Encoding.UTF8.GetBytes(amount.ToString()));
                rawData.AddRange(Encoding.UTF8.GetBytes(fee.ToString()));

                if (toList.Count == 1)
                {
                    rawData.AddRange(toList.ToArray()[0].Key.addressWithChecksum);
                }
                else
                {
                    foreach (var entry in toList)
                    {
                        rawData.AddRange(entry.Key.addressWithChecksum);
                        rawData.AddRange(entry.Value.amount.getAmount().ToByteArray());
                    }
                }

                if (fromList.Count == 1)
                {
                    rawData.AddRange(pubKey.addressWithChecksum);
                }
                else
                {
                    foreach (var entry in fromList)
                    {
                        rawData.AddRange(entry.Key);
                        rawData.AddRange(entry.Value.getAmount().ToByteArray());
                    }
                    rawData.AddRange(pubKey.addressWithChecksum);
                }

                rawData.AddRange(BitConverter.GetBytes(blockHeight));
                rawData.AddRange(BitConverter.GetBytes(nonce));
                rawData.AddRange(BitConverter.GetBytes((int)0));
                if (version <= 2)
                {
                    chk = Base58Check.Base58CheckEncoding.EncodePlain(Crypto.sha512quTrunc(rawData.ToArray()));
                }
                else
                {
                    chk = Base58Check.Base58CheckEncoding.EncodePlain(Crypto.sha512sqTrunc(rawData.ToArray()));
                }
                txid += chk;

                id = txIdLegacyToV8(txid);
                checksum = calculateChecksum(this);
            }
            else
            {
                byte[] b_bh = IxiVarInt.GetIxiVarIntBytes(blockHeight);
                byte[] b_tx_hash = calculateChecksum(this);
                byte[] tx_type;
                if (type == (int)Transaction.Type.StakingReward)
                {
                    tx_type = b_type0;
                }
                else
                {
                    tx_type = b_type1;
                }
                byte[] b_txid = new byte[tx_type.Length + b_bh.Length + b_tx_hash.Length];
                Array.Copy(tx_type, 0, b_txid, 0, tx_type.Length);
                Array.Copy(b_bh, 0, b_txid, tx_type.Length, b_bh.Length);
                Array.Copy(b_tx_hash, 0, b_txid, tx_type.Length + b_bh.Length, b_tx_hash.Length);

                checksum = b_tx_hash;
                id = b_txid;
            }
        }

        /// <summary>
        ///  Calculates the transaction's checksum.
        /// </summary>
        /// <param name="transaction">Transaction to calculate the checksum from.</param>
        /// <returns>Byte-field with the checksum value.</returns>
        public static byte[] calculateChecksum(Transaction transaction)
        {
            if(transaction.version < 6)
            {
                return calculateChecksumLegacy(transaction);
            }else if(transaction.version == 6)
            {
                return calculateChecksum_v6(transaction);
            }else
            {
                return CryptoManager.lib.sha3_512sqTrunc(transaction.getBytesV7(false, true));
            }
        }

        public static byte[] calculateChecksumLegacy(Transaction transaction)
        {
            List<byte> rawData = new List<byte>();
            rawData.AddRange(ConsensusConfig.ixianChecksumLock);
            if (transaction.version < 5)
            {
                rawData.AddRange(Encoding.UTF8.GetBytes(transaction.getTxIdString()));
            }
            rawData.AddRange(BitConverter.GetBytes(transaction.type));
            rawData.AddRange(Encoding.UTF8.GetBytes(transaction.amount.ToString()));
            rawData.AddRange(Encoding.UTF8.GetBytes(transaction.fee.ToString()));
            if (transaction.toList.Count == 1)
            {
                rawData.AddRange(transaction.toList.ToArray()[0].Key.addressWithChecksum);
            }
            else
            {
                foreach (var entry in transaction.toList)
                {
                    rawData.AddRange(entry.Key.addressWithChecksum);
                    rawData.AddRange(entry.Value.amount.getAmount().ToByteArray());
                }
            }

            if (transaction.fromList.Count == 1)
            {
                rawData.AddRange(transaction.pubKey.addressWithChecksum);
            }
            else
            {
                foreach (var entry in transaction.fromList)
                {
                    rawData.AddRange(entry.Key);
                    rawData.AddRange(entry.Value.getAmount().ToByteArray());
                }
            }

            if (transaction.version < 4)
            {
                if (transaction.toList.First().Value.data != null)
                {
                    rawData.AddRange(transaction.toList.First().Value.data);
                }
            }
            else
            {
                if (transaction.toList.First().Value.dataChecksum != null)
                {
                    rawData.AddRange(transaction.toList.First().Value.dataChecksum);
                }
            }

            rawData.AddRange(BitConverter.GetBytes(transaction.blockHeight));
            rawData.AddRange(BitConverter.GetBytes(transaction.nonce));
            if (transaction.version < 5 || transaction.type != (int)Transaction.Type.StakingReward)
            {
                rawData.AddRange(BitConverter.GetBytes(transaction.timeStamp));
            }
            rawData.AddRange(BitConverter.GetBytes(transaction.version));
            if ((transaction.version <= 1 && transaction.pubKey != null && transaction.pubKey.pubKey != null)
                || transaction.version >= 2)
            {
                byte[] pkBytes;
                if (transaction.pubKey.pubKey != null)
                {
                    pkBytes = transaction.pubKey.pubKey;
                }
                else
                {
                    pkBytes = transaction.pubKey.addressWithChecksum;
                }
                rawData.AddRange(pkBytes);
            }
            if (transaction.version <= 2)
            {
                return Crypto.sha512quTrunc(rawData.ToArray());
            }
            else
            {
                return Crypto.sha512sqTrunc(rawData.ToArray());
            }
        }

        public static byte[] calculateChecksum_v6(Transaction transaction)
        {
            List<byte> rawData = new List<byte>();
            rawData.AddRange(ConsensusConfig.ixianChecksumLock);
            rawData.AddRange(BitConverter.GetBytes(transaction.type));
            rawData.AddRange(transaction.amount.getBytes());
            rawData.AddRange(transaction.fee.getBytes());
            foreach (var entry in transaction.toList)
            {
                rawData.AddRange(entry.Key.addressWithChecksum);
                rawData.AddRange(entry.Value.amount.getBytes());
            }

            foreach (var entry in transaction.fromList)
            {
                rawData.AddRange(entry.Key);
                rawData.AddRange(entry.Value.getBytes());
            }

            if (transaction.toList.First().Value.dataChecksum != null)
            {
                rawData.AddRange(transaction.toList.First().Value.dataChecksum);
            }

            rawData.AddRange(BitConverter.GetBytes(transaction.blockHeight));
            rawData.AddRange(BitConverter.GetBytes(transaction.nonce));
            if (transaction.type != (int)Transaction.Type.StakingReward)
            {
                rawData.AddRange(BitConverter.GetBytes(transaction.timeStamp));
            }
            rawData.AddRange(BitConverter.GetBytes(transaction.version));
            if (transaction.pubKey.pubKey != null)
            {
                rawData.AddRange(transaction.pubKey.pubKey);
            }
            else
            {
                rawData.AddRange(transaction.pubKey.addressWithChecksum);
            }
            return Crypto.sha512sqTrunc(rawData.ToArray());
        }

        /// <summary>
        ///  Calculates the signature for the transaction.
        /// </summary>
        /// <param name="checksum">Transaction checksum.</param>
        /// <param name="private_key">Private key with which to sign the transaction, or null if the primary key should be used.</param>
        /// <returns>Transaction signature in a byte-field.</returns>
        public byte[] getSignature(byte[] checksum, byte[] private_key = null)
        {
            if(private_key != null)
            {
                return CryptoManager.lib.getSignature(checksum, private_key);
            }

            Address address = pubKey;

            WalletStorage ws = IxianHandler.getWalletStorageBySecondaryAddress(address);
            if(ws != null)
            {
                IxianKeyPair kp = ws.getKeyPair(address);
                if (kp != null)
                {
                    return CryptoManager.lib.getSignature(checksum, kp.privateKeyBytes);
                }
            }
            return null;
        }

        /// <summary>
        ///  Calculates the total transaction amount, without fee.
        /// </summary>
        /// <returns>Sum of all deposits in the transaction's `toList`.</returns>
        public IxiNumber calculateTotalAmount()
        {
            IxiNumber total = new IxiNumber(0);
            foreach(var entry in toList)
            {
                total += entry.Value.amount;
            }
            return total;
        }

        /// <summary>
        ///  Calculates the lowest possible transaction fee based on the size of the transaction.
        /// </summary>
        /// <param name="pricePerKb">Price per kilobyte of data.</param>
        /// <returns>Minimum fee given the specified price per kilobyte.</returns>
        public IxiNumber calculateMinimumFee(IxiNumber pricePerKb)
        {
            int bytesLen = getBytes(false).Length;
            // TODO Omega checksum can be removed
            if (checksum == null)
            {
                bytesLen += 44;
            }
            if (signature == null)
            {
                bytesLen += 512;
            }
            IxiNumber expectedFee = pricePerKb * (ulong)Math.Ceiling((double)bytesLen / 1000); // TODO TODO Omega
            return expectedFee;
        }

        /// <summary>
        ///  Appends a signature for the given multisig transaction.
        /// </summary>
        /// <param name="orig_txid">Original multisig transaction's ID.</param>
        /// <param name="signer_pub_key">Public key of the additional signer.</param>
        /// <param name="signer_nonce">Nonce value of the wallet which is allowed to sign `orig_txid` and can be signed with the `signer_pub_key`.</param>
        private void AddMultisigOrig(byte[] orig_txid, byte[] signer_pub_key, byte[] signer_nonce)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                using (BinaryWriter bw = new BinaryWriter(ms))
                {
                    if (orig_txid == null)
                    {
                        bw.WriteIxiVarInt((int)0);
                    }
                    else
                    {
                        bw.WriteIxiVarInt(orig_txid.Length);
                        bw.Write(orig_txid);
                    }

                    bw.WriteIxiVarInt(signer_pub_key.Length);
                    bw.Write(signer_pub_key);

                    bw.WriteIxiVarInt(signer_nonce.Length);
                    bw.Write(signer_nonce);
#if TRACE_MEMSTREAM_SIZES
                        Logging.info(String.Format("Transaction::AddMultisigOrig: {0}", ms.Length));
#endif
                }
                toList.First().Value.data = ms.ToArray();
            }
        }

        /// <summary>
        ///  Encodes information to add or delete an allowed signer from a multisig wallet.
        /// </summary>
        /// <param name="addr">Address to add or remove.</param>
        /// <param name="change_type">Operation - add or remove.</param>
        /// <param name="signer_pub_key">Signer, who is already on the multisig wallet's allowed list.</param>
        /// <param name="signer_nonce">Nonce value of the wallet which is allowed to make changes to the multisig wallet and can be signed with the `signer_pub_key`.</param>
        private void AddMultisigChWallet(Address addr, MultisigWalletChangeType change_type, byte[] signer_pub_key, byte[] signer_nonce)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                using (BinaryWriter bw = new BinaryWriter(ms))
                {
                    bw.Write((byte)change_type);

                    bw.WriteIxiVarInt(addr.addressNoChecksum.Length);
                    bw.Write(addr.addressNoChecksum);

                    bw.WriteIxiVarInt(signer_pub_key.Length);
                    bw.Write(signer_pub_key);

                    bw.WriteIxiVarInt(signer_nonce.Length);
                    bw.Write(signer_nonce);
#if TRACE_MEMSTREAM_SIZES
                        Logging.info(String.Format("Transaction::AddMultisigChWallet: {0}", ms.Length));
#endif
                }
                toList.First().Value.data = ms.ToArray();
            }
        }

        /// <summary>
        ///  Encodes information to change the number of required signatures on a multisig wallet.
        /// </summary>
        /// <param name="addr">New number of signatures.</param>
        /// <param name="signer_pub_key">Signer, who is on the multisig wallet's allowed list.</param>
        /// <param name="signer_nonce">Nonce value of the wallet which is allowed to make changes to the multisig wallet and can be signed with the `signer_pub_key`.</param>
        private void AddMultisigChReqSigs(byte num_sigs, byte[] signer_pub_key, byte[] signer_nonce)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                using (BinaryWriter bw = new BinaryWriter(ms))
                {
                    bw.Write((byte)MultisigWalletChangeType.ChangeReqSigs);

                    bw.WriteIxiVarInt(num_sigs);

                    bw.WriteIxiVarInt(signer_pub_key.Length);
                    bw.Write(signer_pub_key);

                    bw.WriteIxiVarInt(signer_nonce.Length);
                    bw.Write(signer_nonce);
#if TRACE_MEMSTREAM_SIZES
                        Logging.info(String.Format("Transaction::AddMultisigChReqSigs: {0}", ms.Length));
#endif
                }
                toList.First().Value.data = ms.ToArray();
            }
        }

        /// <summary>
        ///  Reads the transaction's optional data and attempts to parse it as a multisig transaction data.
        /// </summary>
        /// <returns>Multisig transaction data, or null if no valid object was found.</returns>
        private object getMultisigTxData()
        {
            byte[] data = toList.First().Value.data;
            if (data == null || data.Length < 6)
            {
                return null;
            }
            using (MemoryStream ms = new MemoryStream(data))
            {
                using (BinaryReader rd = new BinaryReader(ms))
                {
                    try
                    {
                        int orig_tx_len = (int)rd.ReadIxiVarUInt();
                        if (orig_tx_len < 0 || orig_tx_len > 100)
                        {
                            Logging.warn(String.Format("Multisig transaction: Invalid origin TXID length stored in data: {0}", orig_tx_len));
                            return null;
                        }
                        byte[] orig_txid = null;
                        if (orig_tx_len > 0)
                        {
                            orig_txid = rd.ReadBytes(orig_tx_len);
                            if (orig_txid == null || orig_txid.Length < orig_tx_len)
                            {
                                Logging.warn(String.Format("Multisig transaction: Invalid or missing origin txid!"));
                                return null;
                            }
                        }

                        int signer_pub_key_len = (int)rd.ReadIxiVarUInt();
                        if (signer_pub_key_len < 36 || signer_pub_key_len > 2500)
                        {
                            Logging.warn(String.Format("Multisig transaction: Invalid signer pub key length stored in data: {0}", signer_pub_key_len));
                            return null;
                        }
                        byte[] signer_pub_key = rd.ReadBytes(signer_pub_key_len);
                        if (signer_pub_key == null || signer_pub_key.Length < signer_pub_key_len)
                        {
                            Logging.warn(String.Format("Multisig transaction: Invalid or missing signer pub key!"));
                            return null;
                        }

                        int signer_nonce_len = (int)rd.ReadIxiVarUInt();
                        if (signer_nonce_len > 16)
                        {
                            Logging.warn(String.Format("Multisig transaction: Invalid signer nonce length stored in data: {0}", signer_nonce_len));
                            return null;
                        }
                        byte[] signer_nonce = rd.ReadBytes(signer_nonce_len);

                        return new MultisigTxData
                        {
                            origTXId = orig_txid,
                            signerPubKey = signer_pub_key,
                            signerNonce = signer_nonce
                        };
                    }
                    catch (Exception)
                    {
                        // early EOF or some strange data error
                        return null;
                    }
                }
            }
        }

        /// <summary>
        ///  Reads the transaction's optional data and attempts to parse it as a multisig change data.
        /// </summary>
        /// <returns>One of the multisig change data objects, or null if no valid object was found.</returns>
        private object getChangeMultisigWalletData()
        {
            byte[] data = toList.First().Value.data;
            if (data == null || data.Length < 6)
            {
                return null;
            }
            using (MemoryStream ms = new MemoryStream(data))
            {
                using (BinaryReader rd = new BinaryReader(ms))
                {
                    try
                    {
                        // multisig change type
                        MultisigWalletChangeType change_type = (MultisigWalletChangeType)rd.ReadByte();
                        switch (change_type)
                        {
                            case MultisigWalletChangeType.AddSigner:
                                int ch_addr_len = (int)rd.ReadIxiVarUInt();
                                if (ch_addr_len < 36 || ch_addr_len > 128)
                                {
                                    Logging.warn("Multisig change transaction: Adding signer, but the data does not contain a valid address!");
                                    return null;
                                }
                                byte[] ch_addr = rd.ReadBytes(ch_addr_len);
                                if (ch_addr == null || ch_addr.Length < ch_addr_len)
                                {
                                    Logging.warn("Multisig change transaction: Adding signer, but the address data was corrupted.");
                                    return null;
                                }

                                int signer_pub_key_len = (int)rd.ReadIxiVarUInt();
                                if (signer_pub_key_len < 36 || signer_pub_key_len > 2500)
                                {
                                    Logging.warn(String.Format("Multisig transaction: Invalid signer pub key length stored in data: {0}", signer_pub_key_len));
                                    return null;
                                }
                                if (signer_pub_key_len == 0)
                                {
                                    return null;
                                }
                                byte[] signer_pub_key = rd.ReadBytes(signer_pub_key_len);

                                int signer_nonce_len = (int)rd.ReadIxiVarUInt();
                                if (signer_nonce_len > 16)
                                {
                                    Logging.warn(String.Format("Multisig transaction: Invalid signer nonce length stored in data: {0}", signer_nonce_len));
                                    return null;
                                }
                                byte[] signer_nonce = rd.ReadBytes(signer_nonce_len);

                                return new MultisigAddrAdd
                                {
                                    addrToAdd = new Address(ch_addr),
                                    signerPubKey = signer_pub_key,
                                    signerNonce = signer_nonce
                                };
                            case MultisigWalletChangeType.DelSigner:
                                ch_addr_len = (int)rd.ReadIxiVarUInt();
                                if (ch_addr_len < 36 || ch_addr_len > 128)
                                {
                                    Logging.warn("Multisig change transaction: Deleting signer, but the data does not contain a valid address!");
                                    return null;
                                }
                                ch_addr = rd.ReadBytes(ch_addr_len);
                                if (ch_addr == null || ch_addr.Length < ch_addr_len)
                                {
                                    Logging.warn("Multisig change transaction: Deleting signer, but the address data was corrupted.");
                                    return null;
                                }

                                signer_pub_key_len = (int)rd.ReadIxiVarUInt();
                                if (signer_pub_key_len < 36 || signer_pub_key_len > 2500)
                                {
                                    Logging.warn(String.Format("Multisig transaction: Invalid signer pub key length stored in data: {0}", signer_pub_key_len));
                                    return null;
                                }
                                if (signer_pub_key_len == 0)
                                {
                                    return null;
                                }
                                signer_pub_key = rd.ReadBytes(signer_pub_key_len);

                                signer_nonce_len = (int)rd.ReadIxiVarUInt();
                                if (signer_nonce_len > 16)
                                {
                                    Logging.warn(String.Format("Multisig transaction: Invalid signer nonce length stored in data: {0}", signer_nonce_len));
                                    return null;
                                }
                                signer_nonce = rd.ReadBytes(signer_nonce_len);

                                return new MultisigAddrDel
                                {
                                    addrToDel = new Address(ch_addr),
                                    signerPubKey = signer_pub_key,
                                    signerNonce = signer_nonce
                                };
                            case MultisigWalletChangeType.ChangeReqSigs:
                                byte new_req_sigs = rd.ReadByte();

                                signer_pub_key_len = (int)rd.ReadIxiVarUInt();
                                if (signer_pub_key_len < 36 || signer_pub_key_len > 2500)
                                {
                                    Logging.warn(String.Format("Multisig transaction: Invalid signer pub key length stored in data: {0}", signer_pub_key_len));
                                    return null;
                                }
                                if (signer_pub_key_len == 0)
                                {
                                    return null;
                                }
                                signer_pub_key = rd.ReadBytes(signer_pub_key_len);

                                signer_nonce_len = (int)rd.ReadIxiVarUInt();
                                if (signer_nonce_len > 16)
                                {
                                    Logging.warn("Multisig transaction: Invalid signer nonce length stored in data: {0}", signer_nonce_len);
                                    return null;
                                }
                                signer_nonce = rd.ReadBytes(signer_nonce_len);

                                return new MultisigChSig
                                {
                                    reqSigs = new_req_sigs,
                                    signerPubKey = signer_pub_key,
                                    signerNonce = signer_nonce
                                };
                            default:
                                Logging.warn("Invalid MultisigWalletChangeType for a multisig change transaction {{ {0} }}.", getTxIdString());
                                return null;
                        }
                    }
                    catch (Exception e)
                    {
                        // early EOL or strange data error
                        Logging.error("Exception occurred in getChangeMultisigWalletData for txid {0}: {1}", getTxIdString(), e);
                        return null;
                    }
                }
            }
        }

        /// <summary>
        ///  Wrapper function to attempt and parse the transaction's optional data field as some kind of Multisig object.
        /// </summary>
        /// <returns>A multisig data object, if found, or null.</returns>
        public object GetMultisigData()
        {
            if (type == (int)Transaction.Type.MultisigTX
                || type == (int)Transaction.Type.MultisigAddTxSignature)
            {
                return getMultisigTxData();
            }
            else if (type == (int)Transaction.Type.ChangeMultisigWallet)
            {
                return getChangeMultisigWalletData();
            }
            else
            {
                Logging.info(String.Format("Transaction {{ {0} }} is not a multisig transaction, so MultisigData cannot be retrieved.", getTxIdString()));
                return null;
            }
        }

        /// <summary>
        ///  Checks owned addresses and returns the first one which is allowed to sign transactions for `multisig_address`.
        /// </summary>
        /// <param name="multisig_address">Multisig address to check.</param>
        /// <returns>Own address which is allowed to sign transactions for `multisig_address`, or null, if no such local address.</returns>
        public static AddressData findMyMultisigAddressData(Address multisig_address)
        {
            WalletStorage ws = IxianHandler.getWalletStorageBySecondaryAddress(multisig_address);
            if(ws != null)
            {
                AddressData ad = ws.getAddress(multisig_address);
                if (ad != null)
                {
                    return ad;
                }
            }

            Wallet w = IxianHandler.getWallet(multisig_address);
            if (w == null)
            {
                return null;
            }

            if (w.allowedSigners != null)
            {
                foreach(var entry in w.allowedSigners)
                {
                    ws = IxianHandler.getWalletStorageBySecondaryAddress(entry);
                    if(ws == null)
                    {
                        continue;
                    }
                    AddressData tmp_ad = ws.getAddress(entry);
                    if(tmp_ad != null)
                    {
                        return tmp_ad;
                    }
                }
            }

            return null;
        }

        /// <summary>
        ///  Generates a multisig transaction.
        /// </summary>
        /// <param name="tx_amount">Amount of Ixi to widthraw and deposit.</param>
        /// <param name="tx_fee">Transaction fee</param>
        /// <param name="tx_to">Destination address where the funds should be deposited.</param>
        /// <param name="tx_from">Multisig wallet where the funds should be withdrawn.</param>
        /// <param name="tx_blockHeight">Blockheight at which the transaction is generated.</param>
        /// <returns>Generated transaction object.</returns>
        public static Transaction multisigTransaction(IxiNumber tx_amount, IxiNumber tx_fee, Address tx_to, Address tx_from, ulong tx_blockHeight)
        {
            Transaction t = new Transaction((int)Transaction.Type.MultisigTX, tx_amount, tx_fee, tx_to, tx_from, null, tx_from, tx_blockHeight);

            // TODO TODO TODO TODO TODO TODO make this compatible with wallet v3

            AddressData ad = findMyMultisigAddressData(tx_from);
            if(ad == null)
            {
                return null;
            }

            t.AddMultisigOrig(null, ad.keyPair.publicKeyBytes, ad.nonce);

            t.fee = t.calculateMinimumFee(tx_fee);
            t.fromList[t.fromList.First().Key] = tx_amount + t.fee;

            t.generateChecksums();

            t.signature = t.getSignature(t.checksum);

            return t;
        }

        /// <summary>
        ///  Generates a multisig transaction with multiple destination addresses.
        /// </summary>
        /// <param name="tx_fee">Transaction fee</param>
        /// <param name="tx_to_list">Destination addresses where the funds should be deposited.</param>
        /// <param name="tx_from">Multisig wallet where the funds should be withdrawn.</param>
        /// <param name="tx_blockHeight">Blockheight at which the transaction is generated.</param>
        /// <returns>Generated transaction object.</returns>
        public static Transaction multisigTransaction(IxiNumber tx_fee, IDictionary<Address, ToEntry> tx_to_list, Address tx_from, ulong tx_blockHeight)
        {
            Transaction t = new Transaction((int)Transaction.Type.MultisigTX, tx_fee, tx_to_list, tx_from, tx_from, tx_blockHeight);

            // TODO TODO TODO TODO TODO TODO make this compatible with wallet v3

            AddressData ad = findMyMultisigAddressData(tx_from);
            if (ad == null)
            {
                return null;
            }

            t.AddMultisigOrig(null, ad.keyPair.publicKeyBytes, ad.nonce);

            t.fee = t.calculateMinimumFee(tx_fee);
            t.fromList[t.fromList.First().Key] = t.amount + t.fee;

            t.generateChecksums();

            t.signature = t.getSignature(t.checksum, ad.keyPair.privateKeyBytes);

            return t;
        }

        /// <summary>
        ///  Adds a signature to the specified multisig transaction, if possible.
        ///  This function generates a transaction which adds the signature for `orig_txid`.
        /// </summary>
        /// <param name="orig_txid">Multisig transaction which is waiting to accumulate signatures.</param>
        /// <param name="tx_fee">Fee per kilobyte of data.</param>
        /// <param name="tx_from">Own address which may be allowed to sign `orig_txid`.</param>
        /// <param name="tx_blockHeight">Block height at which to generate the new transaction/</param>
        /// <returns>Signing transaction.</returns>
        public static Transaction multisigAddTxSignature(byte[] orig_txid, IxiNumber tx_fee, Address tx_from, ulong tx_blockHeight)
        {
            Transaction t = new Transaction((int)Transaction.Type.MultisigAddTxSignature, new IxiNumber(0), tx_fee, tx_from, tx_from, null, tx_from, tx_blockHeight);

            // TODO TODO TODO TODO TODO TODO make this compatible with wallet v3

            AddressData ad = findMyMultisigAddressData(tx_from);
            if (ad == null)
            {
                return null;
            }

            t.AddMultisigOrig(orig_txid, ad.keyPair.publicKeyBytes, ad.nonce);

            t.fee = t.calculateMinimumFee(tx_fee);
            t.fromList[t.fromList.First().Key] = t.fee;

            t.generateChecksums();

            t.signature = t.getSignature(t.checksum, ad.keyPair.privateKeyBytes);

            return t;
        }

        /// <summary>
        ///  Adds a signature to the specified multisig wallet.
        ///  This function generates a transaction which adds the specified `allowed_address` to the multisig wallet `tx_from`.
        /// </summary>
        ///  The transaction fee is paid by `tx_from` - the multisig wallet.
        /// </remarks>
        /// <param name="allowed_address">Address which will be added to `tx_from`.</param>
        /// <param name="tx_fee">Fee per kilobyte of data.</param>
        /// <param name="tx_from">Multisig address where the `allowed_address` will be added.</param>
        /// <param name="tx_blockHeight">Block height at which to generate the new transaction/</param>
        /// <returns>Multisig change transaction.</returns>
        public static Transaction multisigAddKeyTransaction(Address allowed_address,  IxiNumber tx_fee, Address tx_from, ulong tx_blockHeight)
        {
            Transaction t = new Transaction((int)Transaction.Type.ChangeMultisigWallet, new IxiNumber(0), tx_fee, tx_from, tx_from, null, tx_from, tx_blockHeight);

            // TODO TODO TODO TODO TODO TODO make this compatible with wallet v3

            AddressData ad = findMyMultisigAddressData(tx_from);
            if (ad == null)
            {
                return null;
            }

            t.AddMultisigChWallet(allowed_address, MultisigWalletChangeType.AddSigner, ad.keyPair.publicKeyBytes, ad.nonce);

            t.fee = t.calculateMinimumFee(tx_fee);
            t.fromList[t.fromList.First().Key] = t.fee;

            t.generateChecksums();

            t.signature = t.getSignature(t.checksum, ad.keyPair.privateKeyBytes);

            return t;
        }

        /// <summary>
        ///  Deletes a signature from the specified multisig wallet.
        ///  This function generates a transaction which deletes the specified `disallowed_address` from the multisig wallet `tx_from`.
        /// </summary>
        ///  The transaction fee is paid by `tx_from` - the multisig wallet.
        /// </remarks>
        /// <param name="disallowed_address">Address which will be removed from `tx_from`.</param>
        /// <param name="tx_fee">Fee per kilobyte of data.</param>
        /// <param name="tx_from">Multisig address where the `allowed_address` will be added.</param>
        /// <param name="tx_blockHeight">Block height at which to generate the new transaction/</param>
        /// <returns>Multisig change transaction.</returns>
        public static Transaction multisigDelKeyTransaction(Address disallowed_address, IxiNumber tx_fee, Address tx_from, ulong tx_blockHeight)
        {
            Transaction t = new Transaction((int)Transaction.Type.ChangeMultisigWallet, new IxiNumber(0), tx_fee, tx_from, tx_from, null, tx_from, tx_blockHeight);

            // TODO TODO TODO TODO TODO TODO make this compatible with wallet v3

            AddressData ad = findMyMultisigAddressData(tx_from);
            if (ad == null)
            {
                return null;
            }

            t.AddMultisigChWallet(disallowed_address, MultisigWalletChangeType.DelSigner, ad.keyPair.publicKeyBytes, ad.nonce);

            t.fee = t.calculateMinimumFee(tx_fee);
            t.fromList[t.fromList.First().Key] = t.fee;

            t.generateChecksums();

            t.signature = t.getSignature(t.checksum, ad.keyPair.privateKeyBytes);

            return t;
        }

        /// <summary>
        ///  Changes the multisig wallet minimum required signatures value.
        ///  This function generates a transaction which changes the specified multisig wallet `tx_from` with a new minimum
        ///  required signatures value..
        /// </summary>
        ///  The transaction fee is paid by `tx_from` - the multisig wallet.
        /// </remarks>
        /// <param name="sigs">New minimum required signatures value for `tx_from`.</param>
        /// <param name="tx_fee">Fee per kilobyte of data.</param>
        /// <param name="tx_from">Multisig address where the `allowed_address` will be added.</param>
        /// <param name="tx_blockHeight">Block height at which to generate the new transaction/</param>
        /// <returns>Multisig change transaction.</returns>
        public static Transaction multisigChangeReqSigs(byte sigs, IxiNumber tx_fee, Address tx_from, ulong tx_blockHeight)
        {
            Transaction t = new Transaction((int)Transaction.Type.ChangeMultisigWallet, new IxiNumber(0), tx_fee, tx_from, tx_from, null, tx_from, tx_blockHeight);

            // TODO TODO TODO TODO TODO TODO make this compatible with wallet v3

            AddressData ad = findMyMultisigAddressData(tx_from);
            if (ad == null)
            {
                return null;
            }

            t.AddMultisigChReqSigs(sigs, ad.keyPair.publicKeyBytes, ad.nonce);

            t.fee = t.calculateMinimumFee(tx_fee);
            t.fromList[t.fromList.First().Key] = t.fee;

            t.generateChecksums();

            t.signature = t.getSignature(t.checksum, ad.keyPair.privateKeyBytes);

            return t;
        }

        /// <summary>
        ///  Encodes all transaction data fields into a Dictionary for easier conversion to JSON via the REST API server.
        /// </summary>
        /// <returns>Dictionary with all transaction fields.</returns>
        public Dictionary<string, object> toDictionary()
        {
            Dictionary<string, object> tDic = new Dictionary<string, object>();
            tDic.Add("id", getTxIdString());
            tDic.Add("version", version);
            tDic.Add("blockHeight", blockHeight.ToString());
            tDic.Add("nonce", nonce.ToString());

            if (signature != null)
            {
                tDic.Add("signature", Crypto.hashToString(signature));
            }

            if (pubKey != null)
            {
                if (pubKey.pubKey != null)
                {
                    tDic.Add("pubKey", Base58Check.Base58CheckEncoding.EncodePlain(pubKey.pubKey));
                }else
                {
                    tDic.Add("pubKey", Base58Check.Base58CheckEncoding.EncodePlain(pubKey.addressWithChecksum));
                }
            }

            if (toList.First().Value.data != null)
            {
                tDic.Add("data", Crypto.hashToString(toList.First().Value.data));
            }

            tDic.Add("timestamp", timeStamp.ToString());
            tDic.Add("type", type.ToString());
            tDic.Add("amount", amount.ToString());
            tDic.Add("applied", applied.ToString());
            tDic.Add("checksum", Crypto.hashToString(checksum));

            Dictionary<string, string> fromListDic = new Dictionary<string, string>();
            foreach (var entry in fromList)
            {
                fromListDic.Add(Base58Check.Base58CheckEncoding.EncodePlain(entry.Key), entry.Value.ToString());
            }
            tDic.Add("from", fromListDic);

            Dictionary<string, string> toListDic = new Dictionary<string, string>();
            foreach (var entry in toList)
            {
                toListDic.Add(entry.Key.ToString(), entry.Value.amount.ToString());
            }
            tDic.Add("to", toListDic);

            tDic.Add("fee", fee.ToString());
            tDic.Add("totalAmount", (amount + fee).ToString());

            return tDic;
        }

        private int getRandomNonce()
        {
            int milliseconds = (int)(DateTimeOffset.Now.ToUnixTimeMilliseconds() - (DateTimeOffset.Now.ToUnixTimeSeconds() * 1000));
            return (milliseconds * 1000) + random.Next(1000);
        }

        // Cache block type values
        private static byte[] b_type0 = IxiVarInt.GetIxiVarIntBytes(0);
        private static byte[] b_type1 = IxiVarInt.GetIxiVarIntBytes(1);

        public static byte[] txIdLegacyToV8(string txid)
        {
            byte[] b_txid;

            var split_txid = txid.Split('-');

            if (txid.StartsWith("stk-"))
            {
                byte[] b_bh = IxiVarInt.GetIxiVarIntBytes(UInt64.Parse(split_txid[2]));
                byte[] b_tx_hash = Base58Check.Base58CheckEncoding.DecodePlain(split_txid[3]);
                b_txid = new byte[b_type0.Length + b_bh.Length + b_tx_hash.Length];
                Array.Copy(b_type0, 0, b_txid, 0, b_type0.Length);
                Array.Copy(b_bh, 0, b_txid, b_type0.Length, b_bh.Length);
                Array.Copy(b_tx_hash, 0, b_txid, b_type0.Length + b_bh.Length, b_tx_hash.Length);
            }
            else
            {
                byte[] b_bh = IxiVarInt.GetIxiVarIntBytes(UInt64.Parse(split_txid[0]));
                byte[] b_tx_hash = Base58Check.Base58CheckEncoding.DecodePlain(split_txid[1]);
                b_txid = new byte[b_type1.Length + b_bh.Length + b_tx_hash.Length];
                Array.Copy(b_type1, 0, b_txid, 0, b_type1.Length);
                Array.Copy(b_bh, 0, b_txid, b_type1.Length, b_bh.Length);
                Array.Copy(b_tx_hash, 0, b_txid, b_type1.Length + b_bh.Length, b_tx_hash.Length);
            }

            return b_txid;
        }

        public string getTxIdString()
        {
            return getTxIdString(id);
        }

        public static string getTxIdString(byte[] txid)
        {
            // TODO Omega - this needs to be updated after rocksdb and when other parts of code isn't relying on it anymore
            string s_txid;
            var type_ret = IxiVarInt.GetIxiVarUInt(txid, 0);
            int type = (int)type_ret.num;
            int type_len = type_ret.bytesRead;

            var bh_ret = IxiVarInt.GetIxiVarUInt(txid, type_len);
            ulong bh = bh_ret.num;
            int bh_len = bh_ret.bytesRead;

            byte[] tx_hash = new byte[txid.Length - type_len - bh_len];
            Array.Copy(txid, type_len + bh_len, tx_hash, 0, tx_hash.Length);
            if (type == 0)
            {
                s_txid = "stk-" + (bh - 5) + "-" + bh + "-" + Base58Check.Base58CheckEncoding.EncodePlain(tx_hash);
            }
            else
            {
                s_txid = bh + "-" + Base58Check.Base58CheckEncoding.EncodePlain(tx_hash);
            }
            return s_txid;
        }
    }
}
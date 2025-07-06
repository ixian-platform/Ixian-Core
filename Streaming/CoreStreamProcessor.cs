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

using CommunityToolkit.Maui.Converters;
using IXICore.Meta;
using IXICore.Network;
using IXICore.SpixiBot;
using IXICore.Storage;
using IXICore.Streaming.Models;
using IXICore.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using static IXICore.Transaction;

namespace IXICore.Streaming
{
    class ReceiveDataResponse
    {
        public SpixiMessage spixiMessage { get; private set; }
        public StreamMessage streamMessage { get; private set; }
        public Friend friend { get; private set; }
        public Address senderAddress { get; private set; }
        public Address realSenderAddress { get; private set; }

        public ReceiveDataResponse(SpixiMessage spixiMessage, StreamMessage streamMessage, Friend friend, Address senderAddress, Address realSenderAddress)
        {
            this.spixiMessage = spixiMessage;
            this.streamMessage = streamMessage;
            this.friend = friend;
            this.senderAddress = senderAddress;
            this.realSenderAddress = realSenderAddress;
        }
    }

    abstract class CoreStreamProcessor
    {
        readonly byte[] IXI_AES_KEY_INFO = UTF8Encoding.UTF8.GetBytes("IXI AES Key");
        readonly byte[] IXI_CHACHA_KEY_INFO = UTF8Encoding.UTF8.GetBytes("IXI ChaCha Key");

        protected bool running = false;

        protected static PendingMessageProcessor pendingMessageProcessor = null;

        protected List<Timer> _typingTimers = new();

        // Initialize the global stream processor
        public CoreStreamProcessor(PendingMessageProcessor pendingMessageProcessor)
        {
            CoreStreamProcessor.pendingMessageProcessor = pendingMessageProcessor;
            pendingMessageProcessor.start();

            running = true;
        }

        // Uninitialize the global stream processor
        public void uninitialize()
        {
            running = false;
            if (pendingMessageProcessor != null)
            {
                pendingMessageProcessor.stop();
                pendingMessageProcessor = null;
            }
        }

        // Send an encrypted message using the S2 network
        public static void sendMessage(Friend friend, StreamMessage msg, bool add_to_pending_messages = true, bool send_to_server = true, bool send_push_notification = true, bool remove_after_sending = false)
        {
            if (friend.bot)
            {
                send_to_server = false;
                if (msg.id.SequenceEqual(new byte[1] { 3 })
                    || msg.id.SequenceEqual(new byte[1] { 4 })
                    || msg.id.SequenceEqual(new byte[1] { 11 })
                    || msg.id.SequenceEqual(new byte[1] { 12 })
                    || msg.id.SequenceEqual(new byte[1] { 13 })
                    || msg.id.SequenceEqual(new byte[1] { 14 })
                    )
                {
                    add_to_pending_messages = false;
                }
            }
            if (Clock.getNetworkTimestamp() - friend.updatedStreamingNodes < CoreConfig.clientPresenceExpiration
                && friend.relayNode != null)
            {
                StreamClientManager.connectTo(friend.relayNode.hostname, friend.relayNode.walletAddress);
            }
            else
            {
                fetchFriendsPresence(friend);
            }
            pendingMessageProcessor.sendMessage(friend, msg, add_to_pending_messages, send_to_server, send_push_notification, remove_after_sending);
        }


        // Called when receiving encryption keys from the S2 node
        protected bool handleReceivedKeys(Address sender, byte[] data)
        {
            // TODO TODO secure this function to prevent "downgrade"; possibly other handshake functions need securing

            Friend friend = FriendList.getFriend(sender);
            if (friend != null)
            {
                if (friend.handshakeStatus >= 3)
                {
                    return false;
                }

                if (friend.protocolVersion >= 1)
                {
                    Logging.error("Received keys but client encryption version is 1.");
                    return false;
                }

                Logging.info("In received keys");

                friend.receiveKeys(data);

                friend.handshakeStatus = 3;

                sendNickname(friend);

                sendAvatar(friend);

                return true;
            }
            else
            {
                // TODO TODO TODO handle this edge case, by displaying request to add notification to user
                Logging.error("Received keys for an unknown friend.");
            }
            return false;
        }



        // Called when receiving encryption keys from the S2 node
        protected bool handleReceivedKeys2(Address sender, Keys2 data)
        {
            // TODO TODO secure this function to prevent "downgrade"; possibly other handshake functions need securing

            Friend friend = FriendList.getFriend(sender);
            if (friend != null)
            {
                if (friend.handshakeStatus >= 3)
                {
                    return false;
                }

                Logging.info("In received keys");

                var ecdh_shared_key = CryptoManager.lib.deriveECDHSharedKey(friend.ecdhPrivateKey, data.ecdhPubKey);
                var mlkem_secret = CryptoManager.lib.decapsulateMLKem(friend.mlKemPrivateKey, data.mlkemCiphertext);

                var combined_secrets = new byte[ecdh_shared_key.Length + mlkem_secret.Length];
                Buffer.BlockCopy(ecdh_shared_key, 0, combined_secrets, 0, ecdh_shared_key.Length);
                Buffer.BlockCopy(mlkem_secret, 0, combined_secrets, ecdh_shared_key.Length, mlkem_secret.Length);
                
                friend.aesKey = CryptoManager.lib.deriveSymmetricKey(combined_secrets, 32, friend.aesSalt, IXI_AES_KEY_INFO);
                friend.chachaKey = CryptoManager.lib.deriveSymmetricKey(combined_secrets, 32, data.chaChaSalt, IXI_CHACHA_KEY_INFO);
                friend.aesSalt = null;
                friend.ecdhPrivateKey = null;
                friend.mlKemPrivateKey = null;
                friend.handshakeStatus = 3;

                sendNickname(friend);

                sendAvatar(friend);

                return true;
            }
            else
            {
                // TODO TODO TODO handle this edge case, by displaying request to add notification to user
                Logging.error("Received keys for an unknown friend.");
            }
            return false;
        }

        // Called when receiving received confirmation from the message recipient
        protected bool handleMsgReceived(Address sender, int channel, byte[] msg_id)
        {
            Friend friend = FriendList.getFriend(sender);

            if (friend != null)
            {
                pendingMessageProcessor.removeMessage(friend, msg_id);

                Logging.info("Friend's handshake status is {0}", friend.handshakeStatus);

                if (msg_id.Length == 1)
                {
                    if (msg_id.SequenceEqual(new byte[] { 0 }))
                    {
                        if (friend.handshakeStatus == 0)
                        {
                            friend.handshakeStatus = 1;
                            Logging.info("Set handshake status to {0} for {1}", friend.handshakeStatus, friend.walletAddress.ToString());
                            return true;
                        }
                        return false;
                    }

                    if (msg_id.SequenceEqual(new byte[] { 1 }))
                    {
                        // ignore - accept add
                        return false;
                    }

                    if (msg_id.SequenceEqual(new byte[] { 2 }))
                    {
                        if (friend.handshakeStatus == 2)
                        {
                            friend.handshakeStatus = 3;
                            Logging.info("Set handshake status to {0} for {1}", friend.handshakeStatus, friend.walletAddress.ToString());
                            return true;
                        }
                        return false;
                    }

                    if (msg_id.SequenceEqual(new byte[] { 3 }))
                    {
                        // ignore - request nickname
                        return false;
                    }

                    if (msg_id.SequenceEqual(new byte[] { 4 }))
                    {
                        // ignore - request avatar
                        return false;
                    }

                    if (msg_id.SequenceEqual(new byte[] { 5 }))
                    {
                        // ignore - nickname
                        return false;
                    }

                    if (msg_id.SequenceEqual(new byte[] { 6 }))
                    {
                        // ignore - avatar
                        return false;
                    }

                    if (msg_id.SequenceEqual(new byte[] { 10 }))
                    {
                        // ignore, bot related
                        return false;
                    }

                    if (msg_id.SequenceEqual(new byte[] { 11 }))
                    {
                        // ignore, bot related
                        return false;
                    }

                    if (msg_id.SequenceEqual(new byte[] { 12 }))
                    {
                        // ignore, bot related
                        return false;
                    }

                    if (msg_id.SequenceEqual(new byte[] { 13 }))
                    {
                        // ignore, bot related
                        return false;
                    }

                    if (msg_id.SequenceEqual(new byte[] { 14 }))
                    {
                        // ignore, bot related
                        return false;
                    }
                }

                friend.setMessageReceived(channel, msg_id);
                return true;
            }
            else
            {
                Logging.error("Received Message received confirmation for an unknown friend.");
            }
            return false;
        }

        // Called when receiving read confirmation from the message recipient
        protected bool handleMsgRead(Address sender, int channel, byte[] msg_id)
        {
            Friend friend = FriendList.getFriend(sender);
            if (friend != null)
            {
                pendingMessageProcessor.removeMessage(friend, msg_id);
                friend.setMessageRead(channel, msg_id);
                return true;
            }
            else
            {
                Logging.error("Received Message read for an unknown friend.");
            }
            return false;
        }


        // Called when receiving S2 data from clients
        public virtual ReceiveDataResponse receiveData(byte[] bytes, RemoteEndpoint endpoint, bool fireLocalNotification = true)
        {
            if (running == false)
            {
                return null;
            }

            StreamMessage message = new StreamMessage(bytes);

            if (message.data == null)
            {
                Logging.error("Null message data.");
                return null;
            }

            bool replaced_sender_address = false;
            Address real_sender_address = null;
            Address sender_address = message.sender;

            Friend tmp_friend = FriendList.getFriend(message.recipient);
            if (tmp_friend != null)
            {
                if (tmp_friend.bot)
                {
                    // message from a bot group chat
                    real_sender_address = message.sender;
                    sender_address = message.recipient;

                    replaced_sender_address = true;
                }
                else
                {
                    Logging.error("Received message intended for recipient {0} that isn't a bot.", tmp_friend.walletAddress.ToString());
                    return null;
                }
            }
            else if (!IxianHandler.getWalletStorage().isMyAddress(message.recipient))
            {
                Logging.error("Received message for {0} but this address is not one of ours.", message.recipient.ToString());
                return null;
            }


            //Logging.info("Received S2 data from {0} for {1}", Base58Check.Base58CheckEncoding.EncodePlain(sender_address), Base58Check.Base58CheckEncoding.EncodePlain(message.recipient));

            byte[] aes_key = null;
            byte[] chacha_key = null;

            Friend friend = FriendList.getFriend(sender_address);
            if (friend != null)
            {
                aes_key = friend.aesKey;
                chacha_key = friend.chachaKey;
                if (friend.publicKey == null)
                {
                    if (endpoint != null && endpoint.presence.pubkey != null && endpoint.presence.wallet.SequenceEqual(friend.walletAddress))
                    {
                        friend.setPublicKey(endpoint.presence.pubkey);
                    }
                }
            }
            int channel = 0;
            try
            {
                if (message.type == StreamMessageCode.error)
                {
                    // TODO Additional checks have to be added here, so that it's not possible to spoof errors (see .sender .reciver attributes in S2 as well) - it will somewhat be improved with protocol-level encryption as well
                    PresenceList.removeAddressEntry(friend.walletAddress);
                    friend.relayNode = null;
                    friend.online = false;
                    friend.forcePush = true;
                    // TODO TODO current friend's keepalive has to be permanently discarded - i.e. save the timestamp
                    return null;
                }

                // decrypt the message if necessary
                // TODO TODO TODO prevent encryption type downgrades
                if (message.encryptionType != StreamMessageEncryptionCode.none)
                {
                    if (!message.decrypt(IxianHandler.getWalletStorage().getPrimaryPrivateKey(), aes_key, chacha_key))
                    {
                        Logging.error("Could not decrypt message from {0}", sender_address.ToString());
                        return null;
                    }
                }

                // Extract the Spixi message
                SpixiMessage spixi_message = new SpixiMessage(message.data);

                if (spixi_message != null)
                {
                    channel = spixi_message.channel;
                }

                if (friend != null)
                {
                    if (message.encryptionType == StreamMessageEncryptionCode.none)
                    {
                        if (!friend.bot)
                        {
                            switch (spixi_message.type)
                            {
                                case SpixiMessageCode.msgReceived:
                                case SpixiMessageCode.requestAdd:
                                case SpixiMessageCode.requestAdd2:
                                case SpixiMessageCode.acceptAddBot:
                                    break;
                                default:
                                    Logging.error("Expecting encrypted message from {0}", sender_address.ToString());
                                    return null;
                            }
                        }
                    }
                }

                if ((friend == null || !friend.bot) && message.requireRcvConfirmation)
                {
                    switch (spixi_message.type)
                    {
                        case SpixiMessageCode.msgReceived:
                        case SpixiMessageCode.requestFileData:
                        case SpixiMessageCode.fileData:
                        case SpixiMessageCode.appData:
                        case SpixiMessageCode.msgTyping:
                            // do not send received confirmation
                            break;

                        case SpixiMessageCode.chat:
                            sendReceivedConfirmation(friend, sender_address, message.id, channel);
                            break;

                        default:
                            sendReceivedConfirmation(friend, sender_address, message.id, -1);
                            break;
                    }
                }

                switch (spixi_message.type)
                {
                    case SpixiMessageCode.pubKey:
                        if (!handlePubKey(sender_address, spixi_message.data))
                        {
                            return null;
                        }
                        else
                        {
                            return new ReceiveDataResponse(spixi_message, message, friend, sender_address, real_sender_address);
                        }
                        break;
                    case SpixiMessageCode.chat:
                        {
                            // TODO Add a pending chat list for bots, add pending messages to the chat list until pubkey is received and uncoment the code below
                            /*if (replaced_sender_address && (!friend.contacts.ContainsKey(real_sender_address) || friend.contacts[real_sender_address].publicKey == null))
                            {
                                requestPubKey(friend, real_sender_address);
                            }
                            else if (replaced_sender_address && !message.verifySignature(friend.contacts[real_sender_address].publicKey))
                            {
                                Logging.error("Unable to verify signature for message type: {0}, id: {1}, from: {2}.", spixi_message.type, Crypto.hashToString(message.id), Base58Check.Base58CheckEncoding.EncodePlain(real_sender_address));
                            }
                            else if (!replaced_sender_address && friend.bot && !message.verifySignature(friend.publicKey))
                            {
                                Logging.error("Unable to verify signature for message type: {0}, id: {1}, from: {2}.", spixi_message.type, Crypto.hashToString(message.id), Base58Check.Base58CheckEncoding.EncodePlain(sender_address));
                            }
                            else
                            {*/
                            // Add the message to the friend list
                            return new ReceiveDataResponse(spixi_message, message, friend, sender_address, real_sender_address);
                            //}
                        }
                        break;

                    case SpixiMessageCode.getNick:
                        {
                            // Send the nickname to the sender as requested
                            if (!handleGetNick(sender_address, Encoding.UTF8.GetString(spixi_message.data)))
                            {
                                return null;
                            }
                            else
                            {
                                return new ReceiveDataResponse(spixi_message, message, friend, sender_address, real_sender_address);
                            }
                        }
                        break;

                    case SpixiMessageCode.nick:
                        {
                            // Set the nickname for the corresponding address
                            if (!replaced_sender_address && friend.publicKey != null
                                && message.encryptionType != StreamMessageEncryptionCode.spixi1
                                && message.encryptionType != StreamMessageEncryptionCode.spixi2
                                && !message.verifySignature(friend.publicKey))
                            {
                                Logging.error("Unable to verify signature for message type: {0}, id: {1}, from: {2}.", spixi_message.type, Crypto.hashToString(message.id), sender_address.ToString());
                                return null;
                            }
                            else if (replaced_sender_address && (!friend.users.hasUser(real_sender_address) || friend.users.getUser(real_sender_address).publicKey == null))
                            {
                                requestBotUser(friend, real_sender_address);
                                return null;
                            }
                            else if (replaced_sender_address && !message.verifySignature(friend.users.getUser(real_sender_address).publicKey))
                            {
                                Logging.error("Unable to verify signature for message type: {0}, id: {1}, from: {2}.", spixi_message.type, Crypto.hashToString(message.id), real_sender_address.ToString());
                                return null;
                            }
                            else
                            {
                                if (spixi_message.data != null)
                                {
                                    FriendList.setNickname(sender_address, Encoding.UTF8.GetString(spixi_message.data), real_sender_address);
                                }
                                else
                                {
                                    string nick;
                                    if (real_sender_address != null)
                                    {
                                        nick = real_sender_address.ToString();
                                    }
                                    else
                                    {
                                        nick = sender_address.ToString();
                                    }
                                    FriendList.setNickname(sender_address, nick, real_sender_address);
                                }
                                return new ReceiveDataResponse(spixi_message, message, friend, sender_address, real_sender_address);
                            }
                        }
                        break;

                    case SpixiMessageCode.getAvatar:
                        {
                            // Send the avatar to the sender as requested
                            if (!handleGetAvatar(sender_address, Encoding.UTF8.GetString(spixi_message.data)))
                            {
                                return null;
                            }
                            else
                            {
                                return new ReceiveDataResponse(spixi_message, message, friend, sender_address, real_sender_address);
                            }
                        }
                        break;

                    case SpixiMessageCode.avatar:
                        {
                            // Set the avatar for the corresponding address
                            if (!replaced_sender_address && friend.publicKey != null
                                && message.encryptionType != StreamMessageEncryptionCode.spixi1
                                && message.encryptionType != StreamMessageEncryptionCode.spixi2
                                && !message.verifySignature(friend.publicKey))
                            {
                                Logging.error("Unable to verify signature for message type: {0}, id: {1}, from: {2}.", spixi_message.type, Crypto.hashToString(message.id), sender_address.ToString());
                                return null;
                            }
                            else if (replaced_sender_address && (!friend.users.hasUser(real_sender_address) || friend.users.getUser(real_sender_address).publicKey == null))
                            {
                                requestBotUser(friend, real_sender_address);
                                return null;
                            }
                            else if (replaced_sender_address && !message.verifySignature(friend.users.getUser(real_sender_address).publicKey))
                            {
                                Logging.error("Unable to verify signature for message type: {0}, id: {1}, from: {2}.", spixi_message.type, Crypto.hashToString(message.id), real_sender_address.ToString());
                                return null;
                            }
                            else
                            {
                                return new ReceiveDataResponse(spixi_message, message, friend, sender_address, real_sender_address);
                            }
                        }
                        break;

                    case SpixiMessageCode.sentFunds:
                        {
                            // Friend requested funds
                            if (!handleSentFunds(message.id, sender_address, Transaction.getTxIdString(spixi_message.data)))
                            {
                                return null;
                            }
                            else
                            {
                                return new ReceiveDataResponse(spixi_message, message, friend, sender_address, real_sender_address);
                            }
                        }
                        break;

                    case SpixiMessageCode.requestFunds:
                        {
                            // Friend requested funds
                            if (!handleRequestFunds(message.id, sender_address, Encoding.UTF8.GetString(spixi_message.data)))
                            {
                                return null;
                            }
                            else
                            {
                                return new ReceiveDataResponse(spixi_message, message, friend, sender_address, real_sender_address);
                            }
                        }
                        break;

                    case SpixiMessageCode.requestFundsResponse:
                        {
                            if (!handleRequestFundsResponse(message.id, sender_address, Encoding.UTF8.GetString(spixi_message.data)))
                            {
                                return null;
                            }
                            else
                            {
                                return new ReceiveDataResponse(spixi_message, message, friend, sender_address, real_sender_address);
                            }
                        }
                        break;

                    case SpixiMessageCode.msgReceived:
                        {
                            if (!handleMsgReceived(sender_address, spixi_message.channel, spixi_message.data))
                            {
                                return null;
                            }
                            else
                            {
                                return new ReceiveDataResponse(spixi_message, message, friend, sender_address, real_sender_address);
                            }
                        }

                    case SpixiMessageCode.msgRead:
                        {
                            if (!handleMsgRead(sender_address, spixi_message.channel, spixi_message.data))
                            {
                                return null;
                            }
                            else
                            {
                                return new ReceiveDataResponse(spixi_message, message, friend, sender_address, real_sender_address);
                            }
                        }

                    case SpixiMessageCode.requestAdd:
                        {
                            // Friend request
                            if (!new Address(spixi_message.data).SequenceEqual(sender_address) || !message.verifySignature(spixi_message.data))
                            {
                                Logging.error("Unable to verify signature for message type: {0}, id: {1}, from: {2}.", spixi_message.type.ToString(), Crypto.hashToString(message.id), sender_address.ToString());
                                return null;
                            }
                            else
                            {
                                if (!handleRequestAdd(message.id, sender_address, spixi_message.data, message.timestamp))
                                {
                                    return null;
                                }
                                else
                                {
                                    friend = FriendList.getFriend(sender_address);
                                    return new ReceiveDataResponse(spixi_message, message, friend, sender_address, real_sender_address);
                                }
                            }
                        }
                        break;

                    case SpixiMessageCode.requestAdd2:
                        {
                            // Friend request
                            var version_with_offset = spixi_message.data.GetIxiVarUInt(0);
                            var pub_key_with_offset = spixi_message.data.ReadIxiBytes(version_with_offset.bytesRead);
                            var pub_key = pub_key_with_offset.bytes;

                            if (!new Address(pub_key).SequenceEqual(sender_address) || !message.verifySignature(pub_key))
                            {
                                Logging.error("Unable to verify signature for message type: {0}, id: {1}, from: {2}.", spixi_message.type.ToString(), Crypto.hashToString(message.id), sender_address.ToString());
                                return null;
                            }
                            else
                            {
                                if (!handleRequestAdd2(message.id, sender_address, spixi_message.data, message.timestamp))
                                {
                                    return null;
                                }
                                else
                                {
                                    friend = FriendList.getFriend(sender_address);
                                    return new ReceiveDataResponse(spixi_message, message, friend, sender_address, real_sender_address);
                                }
                            }
                        }
                        break;

                    case SpixiMessageCode.acceptAdd:
                        {
                            // Friend accepted request
                            byte[] pub_k = FriendList.findContactPubkey(friend.walletAddress);
                            if (pub_k == null)
                            {
                                Logging.info("Contact {0} not found in presence list!", friend.walletAddress.ToString());
                                return null;
                            }
                            if (!message.verifySignature(pub_k))
                            {
                                Logging.error("Unable to verify signature for message type: {0}, id: {1}, from: {2}.", spixi_message.type.ToString(), Crypto.hashToString(message.id), sender_address.ToString());
                                return null;
                            }
                            else
                            {
                                if (friend.lastReceivedHandshakeMessageTimestamp < message.timestamp)
                                {
                                    friend.lastReceivedHandshakeMessageTimestamp = message.timestamp;
                                    if (!handleAcceptAdd(sender_address, spixi_message.data))
                                    {
                                        return null;
                                    }
                                    else
                                    {
                                        return new ReceiveDataResponse(spixi_message, message, friend, sender_address, real_sender_address);
                                    }
                                }
                            }
                        }
                        break;

                    case SpixiMessageCode.acceptAdd2:
                        {
                            // Friend accepted request
                            var accept_add_2 = new AcceptAdd2(spixi_message.data);

                            if (!new Address(accept_add_2.rsaPubKey).SequenceEqual(message.sender))
                            {
                                Logging.error("Invalid public key in accept add2.", friend.walletAddress.ToString());
                                return null;
                            }
                            if (!message.verifySignature(accept_add_2.rsaPubKey))
                            {
                                Logging.error("Unable to verify signature for message type: {0}, id: {1}, from: {2}.", spixi_message.type.ToString(), Crypto.hashToString(message.id), sender_address.ToString());
                                return null;
                            }
                            else
                            {
                                if (friend.lastReceivedHandshakeMessageTimestamp < message.timestamp)
                                {
                                    friend.lastReceivedHandshakeMessageTimestamp = message.timestamp;
                                    if (!handleAcceptAdd2(sender_address, accept_add_2))
                                    {
                                        return null;
                                    }
                                    else
                                    {
                                        return new ReceiveDataResponse(spixi_message, message, friend, sender_address, real_sender_address);
                                    }
                                }
                            }
                        }
                        break;

                    case SpixiMessageCode.keys:
                        {
                            if (!message.verifySignature(friend.publicKey))
                            {
                                Logging.error("Unable to verify signature for message type: {0}, id: {1}, from: {2}.", spixi_message.type, Crypto.hashToString(message.id), real_sender_address.ToString());
                                return null;
                            }
                            else
                            {
                                if (friend.lastReceivedHandshakeMessageTimestamp < message.timestamp)
                                {
                                    friend.lastReceivedHandshakeMessageTimestamp = message.timestamp;
                                    if (!handleReceivedKeys(sender_address, spixi_message.data))
                                    {
                                        return null;
                                    }
                                    else
                                    {
                                        return new ReceiveDataResponse(spixi_message, message, friend, sender_address, real_sender_address);
                                    }
                                }
                            }
                        }
                        break;


                    case SpixiMessageCode.keys2:
                        {
                            if (!message.verifySignature(friend.publicKey))
                            {
                                Logging.error("Unable to verify signature for message type: {0}, id: {1}, from: {2}.", spixi_message.type, Crypto.hashToString(message.id), real_sender_address.ToString());
                                return null;
                            }
                            else
                            {
                                if (friend.lastReceivedHandshakeMessageTimestamp < message.timestamp)
                                {
                                    friend.lastReceivedHandshakeMessageTimestamp = message.timestamp;
                                    if (!handleReceivedKeys2(sender_address, new Keys2(spixi_message.data)))
                                    {
                                        return null;
                                    }
                                    else
                                    {
                                        return new ReceiveDataResponse(spixi_message, message, friend, sender_address, real_sender_address);
                                    }
                                }
                            }
                        }
                        break;

                    case SpixiMessageCode.acceptAddBot:
                        {
                            // Friend accepted request
                            if (!handleAcceptAddBot(sender_address, spixi_message.data))
                            {
                                return null;
                            }
                            else
                            {
                                return new ReceiveDataResponse(spixi_message, message, friend, sender_address, real_sender_address);
                            }
                        }
                        break;

                    case SpixiMessageCode.botAction:
                        if (!onBotAction(spixi_message.data, friend, channel))
                        {
                            return null;
                        }
                        else
                        {
                            return new ReceiveDataResponse(spixi_message, message, friend, sender_address, real_sender_address);
                        }
                        break;

                    case SpixiMessageCode.msgDelete:
                        if (friend.bot && !message.verifySignature(friend.publicKey))
                        {
                            Logging.error("Unable to verify signature for message type: {0}, id: {1}, from: {2}.", spixi_message.type, Crypto.hashToString(message.id), real_sender_address.ToString());
                            return null;
                        }
                        else
                        {
                            if (!handleMsgDelete(friend, message.id, spixi_message.data, channel))
                            {
                                return null;
                            }
                            else
                            {
                                return new ReceiveDataResponse(spixi_message, message, friend, sender_address, real_sender_address);
                            }
                        }
                        break;

                    case SpixiMessageCode.msgReaction:
                        if (!replaced_sender_address && friend.publicKey != null
                            && message.encryptionType != StreamMessageEncryptionCode.spixi1
                            && message.encryptionType != StreamMessageEncryptionCode.spixi2
                            && !message.verifySignature(friend.publicKey))
                        {
                            Logging.error("Unable to verify signature for message type: {0}, id: {1}, from: {2}.", spixi_message.type, Crypto.hashToString(message.id), sender_address.ToString());
                            return null;
                        }
                        else if (replaced_sender_address && (!friend.users.hasUser(real_sender_address) || friend.users.getUser(real_sender_address).publicKey == null))
                        {
                            requestBotUser(friend, real_sender_address);
                            return null;
                        }
                        else if (replaced_sender_address && !message.verifySignature(friend.users.getUser(real_sender_address).publicKey))
                        {
                            Logging.error("Unable to verify signature for message type: {0}, id: {1}, from: {2}.", spixi_message.type, Crypto.hashToString(message.id), real_sender_address.ToString());
                            return null;
                        }
                        else
                        {
                            if (!handleMsgReaction(friend, message.sender, message.id, spixi_message.data, channel))
                            {
                                return null;
                            }
                            else
                            {
                                return new ReceiveDataResponse(spixi_message, message, friend, sender_address, real_sender_address);
                            }
                        }
                        break;

                    case SpixiMessageCode.leaveConfirmed:
                        if (!friend.bot)
                        {
                            return null;
                        }
                        if (friend.pendingDeletion)
                        {
                            FriendList.removeFriend(friend);
                            var client = StreamClientManager.getClient(friend.walletAddress, false);
                            if (client != null)
                            {
                                CoreProtocolMessage.sendBye(client, ProtocolByeCode.bye, "", "", false);
                            }
                            return new ReceiveDataResponse(spixi_message, message, friend, sender_address, real_sender_address);
                        }
                        break;

                    case SpixiMessageCode.msgTyping:
                        if (friend.bot)
                        {
                            return null;
                        }
                        return new ReceiveDataResponse(spixi_message, message, friend, sender_address, real_sender_address);
                    
                    default:
                        return new ReceiveDataResponse(spixi_message, message, friend, sender_address, real_sender_address);
                }
            }
            catch (Exception e)
            {
                Logging.error("Exception occured in StreamProcessor.receiveData: " + e);
            }
            return null;
        }

        protected void sendReceivedConfirmation(Friend friend, Address senderAddress, byte[] messageId, int channel)
        {
            if (friend == null)
                return;

            // Send received confirmation
            StreamMessage msg_received = new StreamMessage(friend.protocolVersion);
            msg_received.type = StreamMessageCode.info;
            msg_received.sender = IxianHandler.getWalletStorage().getPrimaryAddress();
            msg_received.recipient = senderAddress;
            msg_received.data = new SpixiMessage(SpixiMessageCode.msgReceived, messageId, channel).getBytes();
            msg_received.encryptionType = StreamMessageEncryptionCode.none;

            sendMessage(friend, msg_received, true, true, false, true);
        }

        protected bool handleMsgDelete(Friend friend, byte[] msg_id, byte[] msg_id_to_del, int channel)
        {
            if (friend.deleteMessage(msg_id_to_del, channel))
            {
                if (friend.metaData.setLastReceivedMessageIds(msg_id, channel))
                {
                    friend.saveMetaData();
                }
                return true;
            }
            return false;
        }
        protected bool handleMsgReaction(Friend friend, Address sender, byte[] msg_id, byte[] reaction_data, int channel)
        {
            if (friend.addReaction(sender, new SpixiMessageReaction(reaction_data), channel))
            {
                if (friend.metaData.setLastReceivedMessageIds(msg_id, channel))
                {
                    friend.saveMetaData();
                }
                return true;
            }
            return false;
        }

        protected bool handlePubKey(Address sender_wallet, byte[] pub_key)
        {
            Friend friend = FriendList.getFriend(sender_wallet);
            if (friend == null)
            {
                Logging.error("Contact {0} not found in presence list!", sender_wallet.ToString());
                return false;
            }

            if (!friend.bot)
            {
                return false;
            }

            Address address = new Address(pub_key);
            friend.users.setPubKey(address, pub_key);
            return true;
        }

        // Sends the nickname back to the sender, detects if it should fetch the sender's nickname and fetches it automatically
        protected bool handleGetNick(Address sender_wallet, string text)
        {
            Friend friend = FriendList.getFriend(sender_wallet);
            if (friend == null)
            {
                Logging.error("Contact {0} not found in presence list!", sender_wallet.ToString());
                return false;
            }

            sendNickname(friend);

            return true;
        }

        protected bool handleGetAvatar(Address sender_wallet, string text)
        {
            Friend friend = FriendList.getFriend(sender_wallet);
            if (friend == null)
            {
                Logging.error("Contact {0} not found in presence list!", sender_wallet.ToString());
                return false;
            }

            sendAvatar(friend);

            return true;
        }

        protected bool handleRequestAdd(byte[] id, Address sender_wallet, byte[] pub_key, long received_timestamp)
        {
            // TODO TODO secure this function to prevent "downgrade"; possibly other handshake functions need securing

            if (!(new Address(pub_key)).SequenceEqual(sender_wallet))
            {
                Logging.error("Received invalid pubkey in handleRequestAdd for {0}", sender_wallet.ToString());
                return false;
            }

            Logging.info("In handle request add");

            Friend new_friend = FriendList.addFriend(FriendState.RequestReceived, sender_wallet, pub_key, sender_wallet.ToString(), null, null, 0, false);

            if (new_friend != null)
            {
                if (new_friend.lastReceivedHandshakeMessageTimestamp >= received_timestamp)
                {
                    return false;
                }
                new_friend.lastReceivedHandshakeMessageTimestamp = received_timestamp;
                new_friend.handshakeStatus = 1;
                new_friend.saveMetaData();
                requestNickname(new_friend);
                return true;
            }
            else
            {
                Friend friend = FriendList.getFriend(sender_wallet);
                if (friend.protocolVersion > 0)
                {
                    Logging.error("Client {0}, tried downgrading to {1} from {2}.", sender_wallet, 0, friend.protocolVersion);
                    return false;
                }
                if (friend.lastReceivedHandshakeMessageTimestamp >= received_timestamp)
                {
                    return false;
                }
                friend.lastReceivedHandshakeMessageTimestamp = received_timestamp;
                bool reset_keys = true;
                if (friend.handshakeStatus > 0 && friend.handshakeStatus < 3)
                {
                    reset_keys = false;
                }
                friend.handshakeStatus = 1;
                if (friend.approved)
                {
                    return sendAcceptAdd(friend, reset_keys);
                }
            }
            return false;
        }


        protected bool handleRequestAdd2(byte[] id, Address sender_wallet, byte[] data, long received_timestamp)
        {
            // TODO TODO secure this function to prevent "downgrade"; possibly other handshake functions need securing
            var version_with_offset = data.GetIxiVarUInt(0);
            int version = (int)version_with_offset.num;
            if (version > 1)
            {
                Logging.warn("Unsupported client version {0}, downgrading to {1} for {2}.", version, 1, sender_wallet);
                version = 1;
            }
            var pub_key_with_offset = data.ReadIxiBytes(version_with_offset.bytesRead);
            var pub_key = pub_key_with_offset.bytes;
            if (!(new Address(pub_key)).SequenceEqual(sender_wallet))
            {
                Logging.error("Received invalid pubkey in handleRequestAdd for {0}", sender_wallet.ToString());
                return false;
            }

            Logging.info("In handle request add");

            Friend new_friend = FriendList.addFriend(FriendState.RequestReceived, sender_wallet, pub_key, sender_wallet.ToString(), null, null, 0, false);

            if (new_friend != null)
            {
                new_friend.protocolVersion = version;
                if (new_friend.lastReceivedHandshakeMessageTimestamp >= received_timestamp)
                {
                    return false;
                }
                new_friend.lastReceivedHandshakeMessageTimestamp = received_timestamp;
                new_friend.handshakeStatus = 1;
                new_friend.saveMetaData();
                requestNickname(new_friend);
                return true;
            }
            else
            {
                // TODO - think about this section, perhaps user should be notified in this case
                Friend friend = FriendList.getFriend(sender_wallet);
                if (friend.protocolVersion > version)
                {
                    Logging.error("Client {0}, tried downgrading to {1} from {2}.", sender_wallet, version, friend.protocolVersion);
                    return false;
                }
                friend.protocolVersion = version;
                if (friend.lastReceivedHandshakeMessageTimestamp >= received_timestamp)
                {
                    return false;
                }

                friend.lastReceivedHandshakeMessageTimestamp = received_timestamp;
                friend.setPublicKey(pub_key);
                friend.saveMetaData();
                bool reset_keys = true;
                if (friend.handshakeStatus > 0 && friend.handshakeStatus < 3)
                {
                    reset_keys = false;
                }
                friend.handshakeStatus = 1;
                if (friend.approved)
                {
                    return sendAcceptAdd2(friend, reset_keys);
                }
            }
            return false;
        }

        protected bool handleAcceptAdd(Address sender_wallet, byte[] aes_key)
        {
            // TODO TODO secure this function to prevent "downgrade"; possibly other handshake functions need securing

            // Retrieve the corresponding contact
            Friend friend = FriendList.getFriend(sender_wallet);
            if (friend == null)
            {
                Logging.error("Contact {0} not found in contact list!", sender_wallet.ToString());
                return false;
            }

            if (friend.protocolVersion == 1)
            {
                Logging.error("Received accept add but client encryption version is 1.");
                return false;
            }

            if (friend.handshakeStatus > 1)
            {
                return false;
            }

            Logging.info("In handle accept add");

            friend.aesKey = aes_key;

            friend.generateKeys();

            friend.state = FriendState.Approved;
            friend.handshakeStatus = 2;

            friend.sendKeys(2);

            sendNickname(friend);

            sendAvatar(friend);
            return true;
        }


        protected bool handleAcceptAdd2(Address sender_wallet, AcceptAdd2 data)
        {
            // TODO TODO secure this function to prevent "downgrade"; possibly other handshake functions need securing

            // Retrieve the corresponding contact
            Friend friend = FriendList.getFriend(sender_wallet);
            if (friend == null)
            {
                Logging.error("Contact {0} not found in contact list!", sender_wallet.ToString());
                return false;
            }

            if (friend.handshakeStatus > 1)
            {
                return false;
            }

            Logging.info("In handle accept add");

            var ecdh_keypair = CryptoManager.lib.generateECDHKeyPair();
            var mlkem_keypair = CryptoManager.lib.generateMLKemKeyPair();

            var ecdh_shared_key = CryptoManager.lib.deriveECDHSharedKey(ecdh_keypair.privateKey, data.ecdhPubKey);
            var mlkem_secret = CryptoManager.lib.encapsulateMLKem(data.mlkemPubKey);

            var combined_secrets = new byte[ecdh_shared_key.Length + mlkem_secret.sharedSecret.Length];
            Buffer.BlockCopy(ecdh_shared_key, 0, combined_secrets, 0, ecdh_shared_key.Length);
            Buffer.BlockCopy(mlkem_secret.sharedSecret, 0, combined_secrets, ecdh_shared_key.Length, mlkem_secret.sharedSecret.Length);

            var chacha_salt = CryptoManager.lib.getSecureRandomBytes(32);

            friend.setPublicKey(data.rsaPubKey);
            friend.aesKey = CryptoManager.lib.deriveSymmetricKey(combined_secrets, 32, data.aesSalt, IXI_AES_KEY_INFO);
            friend.chachaKey = CryptoManager.lib.deriveSymmetricKey(combined_secrets, 32, chacha_salt, IXI_CHACHA_KEY_INFO);
            friend.aesSalt = null;
            friend.ecdhPrivateKey = null;
            friend.mlKemPrivateKey = null;

            friend.protocolVersion = data.version;
            friend.state = FriendState.Approved;
            friend.handshakeStatus = 2;

            sendKeys2(friend, ecdh_keypair.publicKey, mlkem_secret.ciphertext, chacha_salt);

            sendNickname(friend);

            sendAvatar(friend);
            return true;
        }

        protected bool handleAcceptAddBot(Address sender_wallet, byte[] aes_key)
        {
            // Retrieve the corresponding contact
            Friend friend = FriendList.getFriend(sender_wallet);
            if (friend == null)
            {
                Logging.error("Contact {0} not found in presence list!", sender_wallet.ToString());
                return false;
            }

            if (friend.handshakeStatus > 1)
            {
                return false;
            }

            friend.aesKey = aes_key;

            friend.setBotMode();

            friend.handshakeStatus = 3;

            sendNickname(friend);

            sendGetBotInfo(friend);

            return true;
        }


        protected bool handleRequestFunds(byte[] id, Address sender_wallet, string amount)
        {
            // Retrieve the corresponding contact
            Friend friend = FriendList.getFriend(sender_wallet);
            if (friend == null)
            {
                return false;
            }

            if (new IxiNumber(amount) > 0)
            {
                return true;
            }
            return false;
        }

        protected bool handleRequestFundsResponse(byte[] id, Address sender_wallet, string msg_id_tx_id)
        {
            // Retrieve the corresponding contact
            Friend friend = FriendList.getFriend(sender_wallet);
            if (friend == null)
            {
                return false;
            }

            string[] msg_id_tx_id_split = msg_id_tx_id.Split(':');
            byte[] msg_id = null;
            string tx_id = null;
            if (msg_id_tx_id_split.Length == 2)
            {
                msg_id = Crypto.stringToHash(msg_id_tx_id_split[0]);
                tx_id = msg_id_tx_id_split[1];
            }
            else
            {
                msg_id = Crypto.stringToHash(msg_id_tx_id);
            }

            FriendMessage msg = friend.getMessages(0).Find(x => x.id.SequenceEqual(msg_id));
            if (msg == null)
            {
                return false;
            }

            // Write to chat history
            IxianHandler.localStorage.requestWriteMessages(friend.walletAddress, 0);

            return true;
        }

        protected bool handleSentFunds(byte[] id, Address sender_wallet, string txid)
        {
            // Retrieve the corresponding contact
            Friend friend = FriendList.getFriend(sender_wallet);
            if (friend == null)
            {
                return false;
            }

            return true;
        }

        public static bool sendAcceptAdd(Friend friend, bool reset_keys)
        {
            // TODO TODO secure this function to prevent "downgrade"; possibly other handshake functions need securing

            if (friend.handshakeStatus > 1)
            {
                return false;
            }

            if (friend.protocolVersion >= 1)
            {
                return sendAcceptAdd2(friend, reset_keys);
            }

            Logging.info("Sending accept add");

            if (reset_keys)
            {
                friend.aesKey = null;
                friend.chachaKey = null;
                friend.generateKeys();
            }
            friend.state = FriendState.Approved;

            SpixiMessage spixi_message = new SpixiMessage(SpixiMessageCode.acceptAdd, friend.aesKey);

            StreamMessage message = new StreamMessage(friend.protocolVersion);
            message.type = StreamMessageCode.info;
            message.recipient = friend.walletAddress;
            message.sender = IxianHandler.getWalletStorage().getPrimaryAddress();
            message.data = spixi_message.getBytes();
            message.encryptionType = StreamMessageEncryptionCode.rsa;
            message.id = new byte[] { 1 };

            sendMessage(friend, message);

            friend.save();
            friend.saveMetaData();

            return true;
        }

        public static bool sendAcceptAdd2(Friend friend, bool reset_keys)
        {
            // TODO TODO secure this function to prevent "downgrade"; possibly other handshake functions need securing

            if (friend.handshakeStatus > 1)
            {
                return false;
            }

            Logging.info("Sending accept add2");

            if (reset_keys)
            {
                friend.aesKey = null;
                friend.chachaKey = null;
                friend.aesSalt = null;
                friend.ecdhPrivateKey = null;
                friend.mlKemPrivateKey = null;
            }

            friend.state = FriendState.Approved;

            var ecdh_keypair = CryptoManager.lib.generateECDHKeyPair();
            var mlkem_keypair = CryptoManager.lib.generateMLKemKeyPair();
            friend.ecdhPrivateKey = ecdh_keypair.privateKey;
            friend.mlKemPrivateKey = mlkem_keypair.privateKey;
            friend.aesSalt = CryptoManager.lib.getSecureRandomBytes(32);

            var accept_add_msg = new AcceptAdd2(friend.protocolVersion, IxianHandler.getWalletStorage().getPrimaryPublicKey(), ecdh_keypair.publicKey, mlkem_keypair.publicKey, friend.aesSalt);

            SpixiMessage spixi_message = new SpixiMessage(SpixiMessageCode.acceptAdd2, accept_add_msg.getBytes());

            StreamMessage message = new StreamMessage(friend.protocolVersion);
            message.type = StreamMessageCode.info;
            message.recipient = friend.walletAddress;
            message.sender = IxianHandler.getWalletStorage().getPrimaryAddress();
            message.data = spixi_message.getBytes();
            message.encryptionType = StreamMessageEncryptionCode.rsa2;
            message.id = new byte[] { 1 };

            sendMessage(friend, message);

            friend.save();
            friend.saveMetaData();

            return true;
        }

        public static bool sendKeys2(Friend friend, byte[] ecdh_pubkey, byte[] mlkem_ciphertext, byte[] chacha_salt)
        {
            Keys2 keys2_msg = new Keys2(ecdh_pubkey, mlkem_ciphertext, chacha_salt);

            SpixiMessage spixi_message = new SpixiMessage(SpixiMessageCode.keys2, keys2_msg.getBytes());

            // Send the key to the recipient
            StreamMessage sm = new StreamMessage(friend.protocolVersion);
            sm.type = StreamMessageCode.info;
            sm.recipient = friend.walletAddress;
            sm.sender = IxianHandler.getWalletStorage().getPrimaryAddress();
            sm.data = spixi_message.getBytes();
            sm.encryptionType = StreamMessageEncryptionCode.rsa2;
            sm.id = new byte[] { 2 };

            CoreStreamProcessor.sendMessage(friend, sm);

            return true;
        }

        public static void sendNickname(Friend friend)
        {
            SpixiMessage reply_spixi_message = new SpixiMessage(SpixiMessageCode.nick, Encoding.UTF8.GetBytes(IxianHandler.localStorage.nickname));

            // Send the nickname message to friend
            StreamMessage reply_message = new StreamMessage(friend.protocolVersion);
            reply_message.type = StreamMessageCode.info;
            reply_message.recipient = friend.walletAddress;
            reply_message.sender = IxianHandler.getWalletStorage().getPrimaryAddress();
            reply_message.data = reply_spixi_message.getBytes();
            reply_message.id = new byte[] { 5 };

            if (friend.bot)
            {
                reply_message.encryptionType = StreamMessageEncryptionCode.none;
                reply_message.sign(IxianHandler.getWalletStorage().getPrimaryPrivateKey());
            }
            else if (friend.aesKey == null || friend.chachaKey == null)
            {
                reply_message.encryptionType = StreamMessageEncryptionCode.rsa;
                if (friend.protocolVersion >= 1)
                {
                    reply_message.encryptionType = StreamMessageEncryptionCode.rsa2;
                }
            }

            sendMessage(friend, reply_message, true, true, false);
        }

        public static void sendAvatar(Friend friend)
        {
            byte[] avatar_bytes = IxianHandler.localStorage.getOwnAvatarBytes();

            SpixiMessage reply_spixi_message = new SpixiMessage(SpixiMessageCode.avatar, avatar_bytes);

            // Send the nickname message to friend
            StreamMessage reply_message = new StreamMessage(friend.protocolVersion);
            reply_message.type = StreamMessageCode.info;
            reply_message.recipient = friend.walletAddress;
            reply_message.sender = IxianHandler.getWalletStorage().getPrimaryAddress();
            reply_message.data = reply_spixi_message.getBytes();
            reply_message.id = new byte[] { 6 };

            if (friend.bot)
            {
                reply_message.encryptionType = StreamMessageEncryptionCode.none;
                reply_message.sign(IxianHandler.getWalletStorage().getPrimaryPrivateKey());
            }


            sendMessage(friend, reply_message, true, true, false);
        }

        // Requests the nickname of the sender
        protected void requestPubKey(Friend friend, byte[] contact_address)
        {
            // Prepare the message and send to the S2 nodes
            SpixiMessage spixi_message = new SpixiMessage(SpixiMessageCode.getPubKey, contact_address);

            StreamMessage message = new StreamMessage(friend.protocolVersion);
            message.type = StreamMessageCode.info;
            message.recipient = friend.walletAddress;
            message.sender = IxianHandler.getWalletStorage().getPrimaryAddress();
            message.data = spixi_message.getBytes();
            if (friend.bot)
            {
                message.id = new byte[contact_address.Length + 1];
                message.id[0] = 0;
                Array.Copy(contact_address, 0, message.id, 1, contact_address.Length);
            }

            if (friend.aesKey == null || friend.chachaKey == null)
            {
                message.encryptionType = StreamMessageEncryptionCode.rsa;
                if (friend.protocolVersion >= 1)
                {
                    message.encryptionType = StreamMessageEncryptionCode.rsa2;
                }
            }

            sendMessage(friend, message, false, true, false);
        }

        // Requests the nickname of the sender
        protected void requestNickname(Friend friend, byte[] contact_address = null)
        {
            if (contact_address == null)
            {
                contact_address = new byte[1];
            }

            // Prepare the message and send to the S2 nodes
            SpixiMessage spixi_message = new SpixiMessage(SpixiMessageCode.getNick, contact_address);

            StreamMessage message = new StreamMessage(friend.protocolVersion);
            message.type = StreamMessageCode.info;
            message.recipient = friend.walletAddress;
            message.sender = IxianHandler.getWalletStorage().getPrimaryAddress();
            message.data = spixi_message.getBytes();
            if (!friend.bot)
            {
                message.id = new byte[] { 3 };
            }
            else
            {
                message.id = new byte[contact_address.Length + 1];
                message.id[0] = 1;
                Array.Copy(contact_address, 0, message.id, 1, contact_address.Length);
            }

            if (friend.aesKey == null || friend.chachaKey == null)
            {
                message.encryptionType = StreamMessageEncryptionCode.rsa;
                if (friend.protocolVersion >= 1)
                {
                    message.encryptionType = StreamMessageEncryptionCode.rsa2;
                }
            }

            sendMessage(friend, message, true, true, false);
        }

        // Requests the avatar of the sender
        protected void requestAvatar(Friend friend, Address contact_address = null)
        {
            // Prepare the message and send to the S2 nodes
            SpixiMessage spixi_message = new SpixiMessage(SpixiMessageCode.getAvatar, contact_address.addressWithChecksum);

            StreamMessage message = new StreamMessage(friend.protocolVersion);
            message.type = StreamMessageCode.info;
            message.recipient = friend.walletAddress;
            message.sender = IxianHandler.getWalletStorage().getPrimaryAddress();
            message.data = spixi_message.getBytes();
            if (!friend.bot)
            {
                message.id = new byte[] { 4 };
            }
            else
            {
                message.id = new byte[contact_address.addressNoChecksum.Length + 1];
                message.id[0] = 2;
                Array.Copy(contact_address.addressNoChecksum, 0, message.id, 1, contact_address.addressNoChecksum.Length);
            }

            if (friend.aesKey == null || friend.chachaKey == null)
            {
                message.encryptionType = StreamMessageEncryptionCode.rsa;
                if (friend.protocolVersion >= 1)
                {
                    message.encryptionType = StreamMessageEncryptionCode.rsa2;
                }
            }

            sendMessage(friend, message, true, true, false);
        }

        // Requests the nickname of the sender
        public static void requestBotUser(Friend friend, Address contact_address)
        {
            SpixiBotAction sba = new SpixiBotAction(SpixiBotActionCode.getUser, contact_address.addressWithChecksum);
            // Send the message to the S2 nodes
            SpixiMessage spixi_message = new SpixiMessage(SpixiMessageCode.botAction, sba.getBytes());

            StreamMessage message = new StreamMessage(friend.protocolVersion);
            message.type = StreamMessageCode.info;
            message.sender = IxianHandler.getWalletStorage().getPrimaryAddress();
            message.recipient = friend.walletAddress;
            message.data = spixi_message.getBytes();
            message.encryptionType = StreamMessageEncryptionCode.none;
            message.id = new byte[contact_address.addressNoChecksum.Length + 1];
            message.id[0] = 3;
            Array.Copy(contact_address.addressNoChecksum, 0, message.id, 1, contact_address.addressNoChecksum.Length);

            sendMessage(friend, message, false);
        }

        public static void sendContactRequest_old(Friend friend)
        {
            Logging.info("Sending contact request old");


            // Send the message to the S2 nodes
            SpixiMessage spixi_message = new SpixiMessage(SpixiMessageCode.requestAdd, IxianHandler.getWalletStorage().getPrimaryPublicKey());


            StreamMessage message = new StreamMessage(friend.protocolVersion);
            message.type = StreamMessageCode.info;
            message.sender = IxianHandler.getWalletStorage().getPrimaryAddress();
            message.recipient = friend.walletAddress;
            message.data = spixi_message.getBytes();
            message.encryptionType = StreamMessageEncryptionCode.none;
            message.id = new byte[] { 0 };

            message.sign(IxianHandler.getWalletStorage().getPrimaryPrivateKey());

            sendMessage(friend, message);
        }

        public static void sendContactRequest(Friend friend)
        {
            Logging.info("Sending contact request");

            byte[] my_pub_key_ixi_bytes = IxianHandler.getWalletStorage().getPrimaryPublicKey().GetIxiBytes();
            byte[] contact_request_bytes = new byte[1 + my_pub_key_ixi_bytes.Length];
            contact_request_bytes[0] = (byte)1; // version
            Buffer.BlockCopy(my_pub_key_ixi_bytes, 0, contact_request_bytes, 1, my_pub_key_ixi_bytes.Length);

            // Send the message to the S2 nodes
            SpixiMessage spixi_message = new SpixiMessage(SpixiMessageCode.requestAdd2, contact_request_bytes);

            StreamMessage message = new StreamMessage(friend.protocolVersion);
            message.type = StreamMessageCode.info;
            message.sender = IxianHandler.getWalletStorage().getPrimaryAddress();
            message.recipient = friend.walletAddress;
            message.data = spixi_message.getBytes();
            message.encryptionType = StreamMessageEncryptionCode.none;
            message.id = new byte[] { 0 };

            message.sign(IxianHandler.getWalletStorage().getPrimaryPrivateKey());

            sendMessage(friend, message);
        }

        protected void sendGetMessages(Friend friend, int channel, byte[] id)
        {
            // Send the message to the S2 nodes
            SpixiMessage spixi_message = new SpixiMessage(SpixiMessageCode.botGetMessages, id, channel);

            StreamMessage message = new StreamMessage(friend.protocolVersion);
            message.type = StreamMessageCode.info;
            message.sender = IxianHandler.getWalletStorage().getPrimaryAddress();
            message.recipient = friend.walletAddress;
            message.data = spixi_message.getBytes();
            message.encryptionType = StreamMessageEncryptionCode.none;

            sendMessage(friend, message, false);
        }

        public static void sendGetBotInfo(Friend friend)
        {
            SpixiBotAction sba = new SpixiBotAction(SpixiBotActionCode.getInfo, null);
            // Send the message to the S2 nodes
            SpixiMessage spixi_message = new SpixiMessage(SpixiMessageCode.botAction, sba.getBytes());


            StreamMessage message = new StreamMessage(friend.protocolVersion);
            message.type = StreamMessageCode.info;
            message.sender = IxianHandler.getWalletStorage().getPrimaryAddress();
            message.recipient = friend.walletAddress;
            message.data = spixi_message.getBytes();
            message.encryptionType = StreamMessageEncryptionCode.none;
            message.id = new byte[] { 11 };

            sendMessage(friend, message);
        }

        protected void sendGetBotChannels(Friend friend)
        {
            SpixiBotAction sba = new SpixiBotAction(SpixiBotActionCode.getChannels, null);
            // Send the message to the S2 nodes
            SpixiMessage spixi_message = new SpixiMessage(SpixiMessageCode.botAction, sba.getBytes());


            StreamMessage message = new StreamMessage(friend.protocolVersion);
            message.type = StreamMessageCode.info;
            message.sender = IxianHandler.getWalletStorage().getPrimaryAddress();
            message.recipient = friend.walletAddress;
            message.data = spixi_message.getBytes();
            message.encryptionType = StreamMessageEncryptionCode.none;
            message.id = new byte[] { 12 };

            sendMessage(friend, message);
        }

        protected void sendGetBotUsers(Friend friend)
        {
            SpixiBotAction sba = new SpixiBotAction(SpixiBotActionCode.getUsers, null);
            // Send the message to the S2 nodes
            SpixiMessage spixi_message = new SpixiMessage(SpixiMessageCode.botAction, sba.getBytes());


            StreamMessage message = new StreamMessage(friend.protocolVersion);
            message.type = StreamMessageCode.info;
            message.sender = IxianHandler.getWalletStorage().getPrimaryAddress();
            message.recipient = friend.walletAddress;
            message.data = spixi_message.getBytes();
            message.encryptionType = StreamMessageEncryptionCode.none;
            message.id = new byte[] { 13 };

            sendMessage(friend, message);
        }

        protected void sendGetBotGroups(Friend friend)
        {
            SpixiBotAction sba = new SpixiBotAction(SpixiBotActionCode.getGroups, null);
            // Send the message to the S2 nodes
            SpixiMessage spixi_message = new SpixiMessage(SpixiMessageCode.botAction, sba.getBytes());


            StreamMessage message = new StreamMessage(friend.protocolVersion);
            message.type = StreamMessageCode.info;
            message.sender = IxianHandler.getWalletStorage().getPrimaryAddress();
            message.recipient = friend.walletAddress;
            message.data = spixi_message.getBytes();
            message.encryptionType = StreamMessageEncryptionCode.none;
            message.id = new byte[] { 14 };

            sendMessage(friend, message);
        }

        public static void deletePendingMessages()
        {
            pendingMessageProcessor.deleteAll();
        }


        protected bool onBotAction(byte[] action_data, Friend bot, int channel_id)
        {
            if (!bot.bot)
            {
                Logging.warn("Received onBotAction for a non-bot");
                return false;
            }
            if (bot.pendingDeletion)
            {
                Logging.warn("Received onBotAction for a bot pending deletion");
                return false;
            }
            SpixiBotAction sba = new SpixiBotAction(action_data);
            switch (sba.action)
            {
                case SpixiBotActionCode.channel:
                    BotChannel channel = new BotChannel(sba.data);
                    bot.channels.setChannel(channel.channelName, channel);
                    byte[] last_msg_id = null;
                    lock (bot.metaData.lastReceivedMessageIds)
                    {
                        if (bot.metaData.lastReceivedMessageIds.ContainsKey(channel.index))
                        {
                            last_msg_id = bot.metaData.lastReceivedMessageIds[channel.index];
                        }
                    }
                    Logging.info("Sending request for messages from ID: " + Crypto.hashToString(last_msg_id));
                    sendGetMessages(bot, channel.index, last_msg_id);
                    return true;
                    break;

                case SpixiBotActionCode.info:
                    BotInfo bi = new BotInfo(sba.data);
                    if (bot.metaData.botInfo == null || bi.settingsGeneratedTime != bot.metaData.botInfo.settingsGeneratedTime)
                    {
                        bot.metaData.botInfo = bi;
                        bot.saveMetaData();
                        FriendList.setNickname(bot.walletAddress, bi.serverName, null);
                        bot.save();
                        // TODO TODO delete deleted groups locally
                        sendGetBotGroups(bot);
                        // TODO remove < 500 check when switching to db
                        if (bi.userCount < 500)
                        {
                            sendGetBotUsers(bot);
                        }
                    }
                    else if (bot.metaData.botInfo != null)
                    {
                        if (bot.metaData.botInfo.userCount != bi.userCount)
                        {
                            bot.metaData.botInfo.userCount = bi.userCount;
                            bot.saveMetaData();
                            // TODO remove < 500 check when switching to db
                            if (bi.userCount < 500)
                            {
                                sendGetBotUsers(bot);
                            }
                        }
                    }
                    // TODO TODO delete deleted channels locally
                    sendGetBotChannels(bot);
                    return true;
                    break;

                case SpixiBotActionCode.user:
                    BotContact user = new BotContact(sba.data, false);
                    bot.users.setUser(user);
                    Address user_address = new Address(user.publicKey);
                    if (user.hasAvatar && IxianHandler.localStorage.getAvatarPath(user_address.ToString()) == null)
                    {
                        requestAvatar(bot, user_address);
                    }
                    return true;
                    break;

                case SpixiBotActionCode.getPayment:
                    onGetPayment(sba, bot, channel_id);
                    return true;
                    break;

                case SpixiBotActionCode.kickUser:
                    return true;
                    break;

                case SpixiBotActionCode.banUser:
                    return true;
                    break;
            }

            return false;
        }

        protected void onGetPayment(SpixiBotAction sba, Friend bot, int channel_id)
        {
            StreamTransactionRequest sta = new StreamTransactionRequest(sba.data);
            FriendMessage fm = bot.getMessages(channel_id).Find(x => x.id.SequenceEqual(sta.messageID));
            if (fm == null)
            {
                Logging.error("Unable to find message with id " + sta.messageID);
                return;
            }

            if (fm.transactionId == "")
            {
                SortedDictionary<Address, ToEntry> to_list = new SortedDictionary<Address, ToEntry>(new AddressComparer());

                Address from = IxianHandler.getWalletStorage().getPrimaryAddress();
                IxiNumber price = bot.getMessagePrice(fm.payableDataLen);
                if (price > sta.cost)
                {
                    // TODO TODO notify the user somehow
                    Logging.warn("Received payment request for " + Crypto.hashToString(fm.id) + " that has higher than expected amount.");
                    return;
                }

                if (price == 0)
                {
                    Logging.warn("Received payment request for " + Crypto.hashToString(fm.id) + " but requested price is 0.");
                    return;
                }

                to_list.Add(bot.walletAddress, new ToEntry(Transaction.getExpectedVersion(IxianHandler.getLastBlockVersion()), sta.cost));

                IxiNumber fee = ConsensusConfig.forceTransactionPrice;
                Address pubKey = new Address(IxianHandler.getWalletStorage().getPrimaryPublicKey());

                Transaction tx = new Transaction((int)Transaction.Type.Normal, fee, to_list, from, pubKey, IxianHandler.getHighestKnownNetworkBlockHeight());

                IxiNumber total_amount = tx.amount + tx.fee;

                if (IxianHandler.balances.First().balance < total_amount)
                {
                    // TODO TODO notify the user somehow
                    Logging.warn("Received payment request for " + Crypto.hashToString(fm.id) + " but balance is too low.");
                    return;
                }

                StreamTransaction st = new StreamTransaction(fm.id, tx);
                sendBotAction(bot, SpixiBotActionCode.payment, st.getBytes(), channel_id, true);

                fm.transactionId = tx.getTxIdString();

                IxianHandler.localStorage.requestWriteMessages(bot.walletAddress, channel_id);

                TransactionCache.addUnconfirmedTransaction(tx);
            }
            else
            {
                byte[] b_txid = Transaction.txIdLegacyToV8(fm.transactionId);
                Transaction tx = TransactionCache.getTransaction(b_txid);
                if (tx == null)
                {
                    tx = TransactionCache.getUnconfirmedTransaction(b_txid);
                }
                // TODO TODO TODO handle expired/failed transaction
                if (tx == null)
                {
                    // TODO TODO TODO do something
                    Logging.warn("Tx " + fm.transactionId + " was already prepared for bot payment but is null now.");
                }
                else
                {
                    IxiNumber total_amount = tx.amount + tx.fee;

                    if (IxianHandler.balances.First().balance < total_amount)
                    {
                        // TODO TODO notify the user somehow
                        Logging.warn("Tx " + fm.transactionId + " was already prepared for bot payment but balance is too low now.");
                        return;
                    }

                    StreamTransaction st = new StreamTransaction(fm.id, tx);
                    sendBotAction(bot, SpixiBotActionCode.payment, st.getBytes(), channel_id, true);
                }
            }
        }

        public static void sendBotAction(Friend bot, SpixiBotActionCode action, byte[] data, int channel = 0, bool sign = false)
        {
            SpixiBotAction sba = new SpixiBotAction(action, data);

            // Prepare the message and send to the S2 nodes
            SpixiMessage spixi_message = new SpixiMessage(SpixiMessageCode.botAction, sba.getBytes(), channel);

            StreamMessage message = new StreamMessage(bot.protocolVersion);
            message.type = StreamMessageCode.info;
            message.recipient = bot.walletAddress;
            message.sender = IxianHandler.getWalletStorage().getPrimaryAddress();
            message.data = spixi_message.getBytes();

            if (bot.bot)
            {
                message.encryptionType = StreamMessageEncryptionCode.none;
            }

            if (sign)
            {
                message.sign(IxianHandler.getWalletStorage().getPrimaryPrivateKey());
            }

            sendMessage(bot, message);
        }

        public static void sendMsgDelete(Friend friend, byte[] msg_id, int channel = 0)
        {
            // Prepare the message and send to the S2 nodes
            SpixiMessage spixi_message = new SpixiMessage(SpixiMessageCode.msgDelete, msg_id, channel);

            StreamMessage message = new StreamMessage(friend.protocolVersion);
            message.type = StreamMessageCode.data;
            message.recipient = friend.walletAddress;
            message.sender = IxianHandler.getWalletStorage().getPrimaryAddress();
            message.data = spixi_message.getBytes();

            if (friend.bot)
            {
                message.encryptionType = StreamMessageEncryptionCode.none;
                message.sign(IxianHandler.getWalletStorage().getPrimaryPrivateKey());
            }

            sendMessage(friend, message);
        }

        public static void sendMsgReport(Friend friend, byte[] msg_id, int channel = 0)
        {
            // Prepare the message and send to the S2 nodes
            SpixiMessage spixi_message = new SpixiMessage(SpixiMessageCode.msgReport, msg_id, channel);

            StreamMessage message = new StreamMessage(friend.protocolVersion);
            message.type = StreamMessageCode.data;
            message.recipient = friend.walletAddress;
            message.sender = IxianHandler.getWalletStorage().getPrimaryAddress();
            message.data = spixi_message.getBytes();

            if (friend.bot)
            {
                message.encryptionType = StreamMessageEncryptionCode.none;
                message.sign(IxianHandler.getWalletStorage().getPrimaryPrivateKey());
                sendMessage(friend, message);
            }
            else
            {
                Logging.warn("Message reported for non-bot user");
            }
        }

        public static void sendReaction(Friend friend, byte[] msg_id, string reaction, int channel = 0)
        {
            // Prepare the message and send to the S2 nodes
            SpixiMessage spixi_message = new SpixiMessage(SpixiMessageCode.msgReaction, new SpixiMessageReaction(msg_id, reaction).getBytes(), channel);

            StreamMessage message = new StreamMessage(friend.protocolVersion);
            message.type = StreamMessageCode.data;
            message.recipient = friend.walletAddress;
            message.sender = IxianHandler.getWalletStorage().getPrimaryAddress();
            message.data = spixi_message.getBytes();

            if (friend.bot)
            {
                message.encryptionType = StreamMessageEncryptionCode.none;
                message.sign(IxianHandler.getWalletStorage().getPrimaryPrivateKey());
            }

            sendMessage(friend, message);
        }

        public static void sendTyping(Friend friend)
        {
            if (friend.bot)
            {
                // ignore for bots, for now
                return;
            }

            // Prepare the message and send to the S2 nodes
            SpixiMessage spixi_message = new SpixiMessage(SpixiMessageCode.msgTyping, null, 0);

            StreamMessage message = new StreamMessage(friend.protocolVersion);
            message.type = StreamMessageCode.info;
            message.recipient = friend.walletAddress;
            message.sender = IxianHandler.getWalletStorage().getPrimaryAddress();
            message.data = spixi_message.getBytes();

            if (friend.bot)
            {
                message.encryptionType = StreamMessageEncryptionCode.none;
                message.sign(IxianHandler.getWalletStorage().getPrimaryPrivateKey());
            }

            sendMessage(friend, message, false, false, false, true);
        }

        public static void sendLeave(Friend friend, byte[] data)
        {
            // Prepare the message and send to the S2 nodes
            SpixiMessage spixi_message = new SpixiMessage(SpixiMessageCode.leave, data, 0);

            StreamMessage message = new StreamMessage(friend.protocolVersion);
            message.type = StreamMessageCode.info;
            message.recipient = friend.walletAddress;
            message.sender = IxianHandler.getWalletStorage().getPrimaryAddress();
            message.data = spixi_message.getBytes();

            if (friend.bot)
            {
                message.encryptionType = StreamMessageEncryptionCode.none;
                message.sign(IxianHandler.getWalletStorage().getPrimaryPrivateKey());
            }

            sendMessage(friend, message);
        }

        public static void fetchAllFriendsSectorNodes(int maxCount)
        {
            int count = 0;
            foreach (var friend in FriendList.friends)
            {
                count++;

                if (Clock.getNetworkTimestamp() - friend.updatedSectorNodes < CoreConfig.contactSectorNodeIntervalSeconds
                    || Clock.getNetworkTimestamp() - friend.updatedStreamingNodes < CoreConfig.contactSectorNodeIntervalSeconds)
                {
                    continue;
                }

                if (count > maxCount)
                {
                    break;
                }

                CoreProtocolMessage.fetchSectorNodes(friend.walletAddress, CoreConfig.maxRelaySectorNodesToRequest);
            }
        }

        public static void fetchAllFriendsPresences(int maxCount)
        {
            var friends = FriendList.friends.OrderBy(x => x.metaData.lastMessage.timestamp);
            int count = 0;
            foreach (var friend in friends)
            {
                if (count > maxCount)
                {
                    break;
                }

                if (Clock.getNetworkTimestamp() - friend.updatedStreamingNodes < CoreConfig.contactSectorNodeIntervalSeconds)
                {
                    continue;
                }

                fetchFriendsPresence(friend);
                count++;
            }
        }

        public static void fetchAllFriendsPresencesInSector(Address address)
        {
            Logging.trace("Fetching all friends presences in sector " + address.ToString());
            var friends = FriendList.friends;
            foreach (var friend in friends)
            {
                if (friend.sectorNodes.Find(x => x.walletAddress.SequenceEqual(address)) == null)
                {
                    continue;
                }

                if (Clock.getNetworkTimestamp() - friend.updatedStreamingNodes < CoreConfig.contactSectorNodeIntervalSeconds)
                {
                    continue;
                }

                fetchFriendsPresence(friend);
            }
        }

        public static void fetchFriendsPresence(Friend friend)
        {
            if (Clock.getTimestamp() - friend.requestedPresence < CoreConfig.requestPresenceTimeout)
            {
                return;
            }

            if (friend.sectorNodes.Count() == 0
                || (Clock.getNetworkTimestamp() - friend.updatedSectorNodes > CoreConfig.contactSectorNodeIntervalSeconds && Clock.getNetworkTimestamp() - friend.updatedStreamingNodes > CoreConfig.contactSectorNodeIntervalSeconds))
            {
                // If sector nodes are not yet initialized or we haven't received contact's presence information and haven't updated presence within the interval

                Logging.trace("Fetching sector nodes for " + friend.walletAddress.ToString());
                CoreProtocolMessage.fetchSectorNodes(friend.walletAddress, CoreConfig.maxRelaySectorNodesToRequest);
                return;
            }

            using (MemoryStream mw = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(mw))
                {
                    writer.WriteIxiVarInt(friend.walletAddress.addressNoChecksum.Length);
                    writer.Write(friend.walletAddress.addressNoChecksum);
                }

                Logging.trace("Fetching presence for " + friend.walletAddress.ToString());
                if (!StreamClientManager.sendToClient(friend.sectorNodes, ProtocolMessageCode.getPresence2, mw.ToArray(), null, 2))
                {
                    // Not connected to contact's sector node

                    var rnd = new Random();
                    if (friend.sectorNodes.Count > 1)
                    {
                        int fromIndex = rnd.Next(friend.sectorNodes.Count - 1);
                        for (int i = 0; i < 2; i++)
                        {
                            var sn = friend.sectorNodes[fromIndex + i];
                            Logging.trace("Connecting to sector node " + sn.hostname + " " + sn.walletAddress.ToString());
                            StreamClientManager.connectTo(sn.hostname, sn.walletAddress);
                        }
                    } else
                    {
                        var sn = friend.sectorNodes[0];
                        Logging.trace("Connecting to sector node " + sn.hostname + " " + sn.walletAddress.ToString());
                        StreamClientManager.connectTo(sn.hostname, sn.walletAddress);
                    }
                } else
                {
                    friend.requestedPresence = Clock.getTimestamp();
                }
            }
        }
    }
}
﻿// Copyright (C) 2017-2025 Ixian
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
using IXICore.Network;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;

namespace IXICore.Streaming
{
    class OffloadedMessage
    {
        public Friend friend;
        public StreamMessage msg;
        public bool addToPendingMessages;
        public bool sendToServer;
        public bool sendPushNotification;
        public bool removeAfterSending;
    }


    abstract class PendingMessageProcessor
    {
        Thread pendingMessagesThread; // Thread that checks the offline messages list for outstanding messages
        Thread offloadedMessagesThread;
        bool running = false;

        List<PendingRecipient> pendingRecipients = new List<PendingRecipient>();
        List<OffloadedMessage> msgQueue = new List<OffloadedMessage>();

        string storagePath = "MsgQueue";

        bool enablePushNotificationServer;

        public PendingMessageProcessor(string root_storage_path, bool enable_push_notification_server)
        {
            storagePath = Path.Combine(root_storage_path, storagePath);
            enablePushNotificationServer = enable_push_notification_server;
        }

        private void loadMessageQueue()
        {
            lock (pendingRecipients)
            {
                var dir_enum = Directory.EnumerateDirectories(storagePath);
                foreach (string dir_path in dir_enum)
                {
                    try
                    {
                        Friend friend = FriendList.getFriend(new Address(Path.GetFileName(dir_path)));
                        if (friend == null)
                        {
                            Directory.Delete(dir_path, true);
                            continue;
                        }
                        PendingRecipient pr = new PendingRecipient(friend.walletAddress);
                        pendingRecipients.Add(pr);
                        var file_arr = Directory.GetFiles(dir_path).OrderBy(x => x);
                        foreach (string file_path in file_arr)
                        {
                            PendingMessage pm = null;
                            try
                            {
                                pm = new PendingMessage(file_path);
                            }
                            catch (Exception)
                            {
                                pm = null;
                            }
                            if (pm != null && pr.messageQueue.Find(x => x.id.SequenceEqual(pm.streamMessage.id)) == null)
                            {
                                pr.messageQueue.Add(new PendingMessageHeader { id = pm.streamMessage.id, filePath = file_path, sendToServer = pm.sendToServer });
                            }
                            else
                            {
                                File.Delete(file_path);
                            }
                        }
                    }
                    catch (Exception e)
                    {
                        Logging.error("Unknown exception occured in loadMessageQueue: " + e);
                    }
                }
            }
        }

        public void start()
        {
            if(running)
            {
                return;
            }
            running = true;

            if (!Directory.Exists(storagePath))
            {
                Directory.CreateDirectory(storagePath);
            }

            pendingMessagesThread = new Thread(messageProcessorLoop);
            pendingMessagesThread.Start();

            offloadedMessagesThread = new Thread(offloadedMessageProcessorLoop);
            offloadedMessagesThread.Start();
        }

        public void stop()
        {
            running = false;
            pendingMessagesThread = null;
            offloadedMessagesThread = null;
        }

        public void processPendingMessages()
        {
            List<PendingRecipient> tmp_pending_recipients;
            lock (pendingRecipients)
            {
                tmp_pending_recipients = new List<PendingRecipient>(pendingRecipients);
            }
            foreach (PendingRecipient recipient in tmp_pending_recipients)
            {
                Friend friend = FriendList.getFriend(recipient.address);
                if (friend == null)
                {
                    Directory.Delete(Path.Combine(storagePath, recipient.address.ToString()), true);
                    lock (pendingRecipients)
                    {
                        pendingRecipients.Remove(recipient);
                    }
                    continue;
                }
                if(friend.bot && !friend.online)
                {
                    continue;
                }
                List<PendingMessageHeader> message_headers = null;
                if (!friend.online)
                {
                    message_headers = recipient.messageQueue.FindAll(x => x.sendToServer);
                }
                else
                {
                    message_headers = recipient.messageQueue;
                }
                if (message_headers != null && message_headers.Count > 0)
                {
                    List<PendingMessageHeader> tmp_msg_headers = new List<PendingMessageHeader>(message_headers);
                    bool failed_sending = false;
                    foreach (var message_header in tmp_msg_headers)
                    {
                        bool sent = processMessage(friend, message_header.filePath);
                        if (message_header.sendToServer && !sent)
                        {
                            failed_sending = true;
                            break;
                        }
                    }
                    if (!failed_sending)
                    {
                        friend.forcePush = false;
                    }
                }
            }
        }

        public void sendMessage(Friend friend, StreamMessage msg, bool add_to_pending_messages, bool send_to_server, bool send_push_notification, bool remove_after_sending = false)
        {
            OffloadedMessage om = new OffloadedMessage{ friend = friend, msg = msg, addToPendingMessages = add_to_pending_messages, sendToServer = send_to_server, sendPushNotification = send_push_notification, removeAfterSending = remove_after_sending  };
            msgQueue.Add(om);
        }

        private void sendMessage(OffloadedMessage om)
        {
            PendingMessage pm = new PendingMessage(om.msg, om.sendToServer, om.sendPushNotification, om.removeAfterSending);
            StreamMessage msg = pm.streamMessage;
            PendingMessageHeader tmp_msg_header = tmp_msg_header = getPendingMessageHeader(om.friend, msg.id);
            if (tmp_msg_header != null)
            {
                pm.filePath = tmp_msg_header.filePath;
            }
            PendingRecipient tmp_recipient = null;
            lock (pendingRecipients)
            {
                tmp_recipient = pendingRecipients.Find(x => x.address.SequenceEqual(msg.recipient));
                if (tmp_recipient == null)
                {
                    tmp_recipient = new PendingRecipient(msg.recipient);
                    pendingRecipients.Add(tmp_recipient);
                }
            }
            if (om.addToPendingMessages)
            {
                pm.save(storagePath);
                if (tmp_msg_header == null)
                {
                    tmp_recipient.messageQueue.Add(new PendingMessageHeader() { filePath = pm.filePath, id = pm.streamMessage.id, sendToServer = pm.sendToServer });
                }
            }
            if (tmp_recipient.messageQueue.Count() == 1 || !om.addToPendingMessages)
            {
                sendMessage(om.friend, pm, om.addToPendingMessages);
            }
        }

        private bool processMessage(Friend friend, string file_path)
        {
            PendingMessage pm = new PendingMessage(file_path);
            return sendMessage(friend, pm);
        }

        public bool removeMessage(Friend friend, byte[] msg_id)
        {
            lock (pendingRecipients)
            {
                PendingRecipient pending_recipient = pendingRecipients.Find(x => x.address.SequenceEqual(friend.walletAddress));
                if (pending_recipient != null)
                {
                    PendingMessageHeader tmp_msg_header = pending_recipient.messageQueue.Find(x => x.id.SequenceEqual(msg_id));
                    if (tmp_msg_header != null)
                    {
                        pending_recipient.messageQueue.Remove(tmp_msg_header);
                        if (File.Exists(tmp_msg_header.filePath))
                        {
                            File.Delete(tmp_msg_header.filePath);
                            return true;
                        }
                    }
                }
                return false;
            }
        }

        private bool sendMessage(Friend friend, PendingMessage pending_message, bool add_to_pending_messages = true)
        {
            StreamMessage msg = pending_message.streamMessage;
            bool send_to_server = pending_message.sendToServer;
            bool send_push_notification = pending_message.sendPushNotification;

            // TODO this function has to be improved and node's wallet address has to be added
            if (friend.publicKey != null || ((msg.encryptionType != StreamMessageEncryptionCode.rsa && msg.encryptionType != StreamMessageEncryptionCode.rsa2) && friend.aesKey != null && friend.chachaKey != null))
            {
                if(msg.encryptionType == StreamMessageEncryptionCode.none)
                {
                    if (friend.aesKey != null && friend.chachaKey != null)
                    {
                        // upgrade encryption type
                        msg.encryptionType = StreamMessageEncryptionCode.spixi1;
                        if (friend.protocolVersion >= 1)
                        {
                            msg.encryptionType = StreamMessageEncryptionCode.spixi2;
                        }
                    }
                    else if (!friend.bot)
                    {
                        // upgrade encryption type
                        msg.encryptionType = StreamMessageEncryptionCode.rsa;
                        if (friend.protocolVersion >= 1)
                        {
                            msg.encryptionType = StreamMessageEncryptionCode.rsa2;
                        }
                    }
                }
                if(msg.encryptionType != StreamMessageEncryptionCode.none)
                {
                    if (msg.version == 0 && (msg.encryptionType == StreamMessageEncryptionCode.rsa || msg.encryptionType == StreamMessageEncryptionCode.rsa2) && !msg.encrypted)
                    {
                        msg.sign(IxianHandler.getWalletStorage().getPrimaryPrivateKey());
                    }
                    if (!msg.encrypt(friend.publicKey, friend.aesKey, friend.chachaKey))
                    {
                        Logging.warn("Could not encrypt message for {0}!", msg.recipient.ToString());
                        return false;
                    }
                    if (msg.version > 0 && (msg.encryptionType == StreamMessageEncryptionCode.rsa || msg.encryptionType == StreamMessageEncryptionCode.rsa2))
                    {
                        msg.sign(IxianHandler.getWalletStorage().getPrimaryPrivateKey());
                    }
                }
            }
            else if (msg.encryptionType != StreamMessageEncryptionCode.none)
            {
                if(!friend.bot)
                {
                    Logging.warn("Could not send message to {0}, due to missing encryption keys!", msg.recipient.ToString());
                    // Return true in case it has other messages in the queue that need to be processed and aren't encrypted
                    return true;
                }else
                {
                    // TODO TODO TODO perhaps it would be better to discard such message and notify the user
                    Logging.warn("Tried sending encrypted message of type {0} without encryption keys to {1}, which is a bot, changing message encryption type to none!", msg.type, msg.recipient.ToString());
                    msg.encryptionType = StreamMessageEncryptionCode.none;
                }
            }

            bool sent = false;
            if (friend.online)
            {
                if (Clock.getNetworkTimestamp() - friend.updatedStreamingNodes < CoreConfig.clientPresenceExpiration
                    && friend.relayNode != null)
                {
                    StreamClientManager.connectTo(friend.relayNode.hostname, friend.relayNode.walletAddress);
                    sent = StreamClientManager.sendToClient(new List<Peer>() { friend.relayNode }, ProtocolMessageCode.s2data, msg.getBytes(), msg.id);
                    if (sent && pending_message.removeAfterSending)
                    {
                        removeMessage(friend, pending_message.streamMessage.id);
                    }
                }
            }
            if (!sent)
            {
                CoreStreamProcessor.fetchFriendsPresence(friend);
            }
            if (friend.forcePush || !friend.online || !sent)
            {
                if (send_to_server)
                {
                    send_to_server = enablePushNotificationServer;
                    if (friend.bot)
                    {
                        send_to_server = false;
                        send_push_notification = false;
                    }
                }
                if (send_to_server)
                {
                    if (OfflinePushMessages.sendPushMessage(msg, send_push_notification))
                    {
                        pending_message.sendToServer = false;
                        // TODO set the proper channel
                        friend.setMessageSent(0, pending_message.streamMessage.id);

                        try
                        {
                            onMessageSent(friend, 0, msg);
                        } catch (Exception e)
                        {
                            Logging.error("Error in onMessageSent: " + e);
                        }

                        if (add_to_pending_messages)
                        {
                            pending_message.save(storagePath);
                        }
                        PendingMessageHeader tmp_msg_header = getPendingMessageHeader(friend, pending_message.streamMessage.id);
                        if (tmp_msg_header != null)
                        {
                            tmp_msg_header.sendToServer = false;
                        }
                        if (pending_message.removeAfterSending)
                        {
                            removeMessage(friend, pending_message.streamMessage.id);
                        }
                        return true;
                    }
                }
                return false;
            }

            return true;

            /*         string pub_k = FriendList.findContactPubkey(msg.recipientAddress);
                     if (pub_k.Length < 1)
                     {
                         Console.WriteLine("Contact {0} not found, adding to offline queue!", msg.recipientAddress);
                         addOfflineMessage(msg);
                         return;
                     }


                     // Create a new IXIAN transaction
                     //  byte[] checksum = Crypto.sha256(encrypted_message);
                     Transaction transaction = new Transaction(0, msg.recipientAddress, IxianHandler.getWalletStorage().address);
                     //  transaction.data = Encoding.UTF8.GetString(checksum);
                     msg.transactionID = transaction.id;
                     //ProtocolMessage.broadcastProtocolMessage(ProtocolMessageCode.newTransaction, transaction.getBytes());

                     // Add message to the queue
                     messages.Add(msg);

                     // Request a new keypair from the S2 Node
                     if(hostname == null)
                         ProtocolMessage.broadcastProtocolMessage(ProtocolMessageCode.s2generateKeys, Encoding.UTF8.GetBytes(msg.getID()));
                     else
                     {
                         NetworkClientManager.sendData(ProtocolMessageCode.s2generateKeys, Encoding.UTF8.GetBytes(msg.getID()), hostname);
                     }*/
        }

        private PendingMessageHeader getPendingMessageHeader(Friend friend, byte[] msg_id)
        {
            lock (pendingRecipients)
            {
                PendingRecipient pending_recipient = pendingRecipients.Find(x => x.address.SequenceEqual(friend.walletAddress));
                if (pending_recipient != null)
                {
                    return pending_recipient.messageQueue.Find(x => x.id.SequenceEqual(msg_id));
                }
            }
            return null;
        }

        private void messageProcessorLoop()
        {
            loadMessageQueue();

            while (running)
            {
                try
                {
                    //sendPendingRequests();
                    processPendingMessages();
                }
                catch (Exception e)
                {
                    Logging.error("Unknown exception occured in messageProcessorLoop: " + e);
                }

                Thread.Sleep(5000);
            }
        }

        private void offloadedMessageProcessorLoop()
        {
            while (running)
            {
                while(msgQueue.Count > 0)
                {
                    try
                    {
                        OffloadedMessage om = msgQueue[0];
                        msgQueue.RemoveAt(0);
                        sendMessage(om);
                    }
                    catch (Exception e)
                    {
                        Logging.error("Unknown exception occured in offloadedMessageProcessorLoop: " + e);
                    }

                }

                Thread.Sleep(10); // TODO increase sleep onSleep, reset it onResume
            }
        }

        public void deleteAll()
        {
            lock (pendingRecipients)
            {
                pendingRecipients.Clear();
                if(Directory.Exists(storagePath))
                {
                    Directory.Delete(storagePath, true);
                }
            }
        }

        protected abstract void onMessageSent(Friend friend, int channel, StreamMessage msg);
    }
}

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
using IXICore.Network;
using IXICore.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;

namespace IXICore.Streaming
{
    public class FriendList
    {
        public static List<Friend> friends = new List<Friend>();

        private static Cuckoo friendMatcher = new Cuckoo(128); // default size of 128, will be increased if neccessary

        public static string accountsPath { get; private set; } = "Acc";

        public static bool contactsLoaded = false;

        public static void init(string base_path)
        {
            accountsPath = Path.Combine(base_path, accountsPath);
            if(!Directory.Exists(accountsPath))
            {
                Directory.CreateDirectory(accountsPath);
            }
            contactsLoaded = false;
        }

        // Retrieves a friend based on the wallet_address
        public static Friend getFriend(Address wallet_address)
        {
            foreach (Friend friend in friends)
            {
                if (friend.walletAddress.SequenceEqual(wallet_address))
                {
                    return friend;
                }
            }
            return null;
        }

        // Set the nickname for a specific wallet address
        public static void setNickname(Address wallet_address, string nick, Address real_sender_address)
        {
            Friend friend = getFriend(wallet_address);
            if (friend == null)
            {
                Logging.error("Received nickname for a friend that's not in the friend list.");
                return;
            }
            if (friend.bot && real_sender_address != null)
            {
                if (!friend.users.hasUser(real_sender_address))
                {
                    friend.users.setPubKey(real_sender_address, null);
                }
                if (friend.users.getUser(real_sender_address).getNick() != nick)
                {
                    friend.users.getUser(real_sender_address).setNick(nick);
                    lock (friend.channels.channels)
                    {
                        foreach (var channel in friend.channels.channels)
                        {
                            List<FriendMessage> messages = friend.getMessages(channel.Value.index);
                            if (messages == null)
                            {
                                continue;
                            }
                            // update messages with the new nick
                            for (int i = messages.Count - 1, j = 0; i >= 0; i--, j++)
                            {
                                if (j > 1000)
                                {
                                    break;
                                }
                                if (messages[i].senderNick != "")
                                {
                                    continue;
                                }
                                if (messages[i].senderAddress == null || real_sender_address == null)
                                {
                                    Logging.warn("Sender address is null");
                                    continue;
                                }
                                if (messages[i].senderAddress.SequenceEqual(real_sender_address))
                                {
                                    messages[i].senderNick = nick;
                                }
                            }
                        }
                    }

                    friend.users.writeContactsToFile();
                }
            }
            else
            {
                if(friend.nickname != nick)
                {
                    friend.nickname = nick;
                }
            }
        }
        // Set the avatar for a specific wallet address
        public static void setAvatar(Address wallet_address, byte[] avatar, byte[] resized_avatar, Address real_sender_address)
        {
            Friend friend = getFriend(wallet_address);
            if (friend == null)
            {
                Logging.error("Received avatar for a friend that's not in the friend list.");
                return;
            }
            string address;
            if (friend.bot && real_sender_address != null)
            {
                address = real_sender_address.ToString();
            }
            else
            {
                address = wallet_address.ToString();
            }
            IxianHandler.localStorage.deleteAvatar(address);
            if (avatar != null
                && resized_avatar != null)
            {
                IxianHandler.localStorage.writeAvatar(address, avatar);
                IxianHandler.localStorage.writeAvatar(address + "_128", resized_avatar);
            }
        }

        public static FriendMessage addMessageWithType(byte[] id, FriendMessageType type, Address wallet_address, int channel, string message, bool local_sender = false, Address sender_address = null, long timestamp = 0, bool fire_local_notification = true, int payable_data_len = 0)
        {
            Friend friend = getFriend(wallet_address);
            if(friend == null)
            {
                // No matching contact found in friendlist
                // Add the contact, then issue the message again?
                // TODO: need to fetch the stage 1 public key somehow here
                // Ignoring such messages for now
                //addFriend(wallet_address, "pubkey", "Unknown");
                //addMessage(wallet_address, message);

                Logging.warn("Received message but contact isn't in our contact list.");
                return null;
            }

            if (!friend.online)
            {
                using (MemoryStream mw = new MemoryStream())
                {
                    using (BinaryWriter writer = new BinaryWriter(mw))
                    {
                        writer.WriteIxiVarInt(wallet_address.addressWithChecksum.Length);
                        writer.Write(wallet_address.addressWithChecksum);

                        CoreProtocolMessage.broadcastProtocolMessage(new char[] { 'M', 'H' }, ProtocolMessageCode.getPresence2, mw.ToArray(), null);
                    }
                }
            }

            bool set_read = false;

            string sender_nick = "";
            if(friend.bot && sender_address != null)
            {
                if(IxianHandler.getWalletStorage().isMyAddress(sender_address))
                {
                    if (!local_sender)
                    {
                        set_read = true;
                    }
                    local_sender = true;
                }
                if (!local_sender)
                {
                    if (friend.users.hasUser(sender_address) && friend.users.getUser(sender_address).getNick() != "")
                    {
                        sender_nick = friend.users.getUser(sender_address).getNick();
                    }
                    else
                    {
                        if(!friend.users.hasUser(sender_address) || friend.users.getUser(sender_address).publicKey == null)
                        {
                            CoreStreamProcessor.requestBotUser(friend, sender_address);
                        }
                    }
                }
            }else
            {
                sender_nick = friend.nickname;
            }

            if(timestamp == 0)
            {
                timestamp = Clock.getTimestamp();
            }

            FriendMessage friend_message = new FriendMessage(id, message, timestamp, local_sender, type, sender_address, sender_nick);
            friend_message.payableDataLen = payable_data_len;

            List<FriendMessage> messages = friend.getMessages(channel);
            if(messages == null)
            {
                Logging.warn("Message with id {0} was sent to invalid channel {1}.", Crypto.hashToString(id), channel);
                return null;
            }
            lock (messages)
            {
                // TODO should be optimized
                if(id != null)
                {
                    FriendMessage tmp_msg = messages.Find(x => x.id != null && x.id.SequenceEqual(id));

                    if(tmp_msg != null)
                    {
                        if (!tmp_msg.localSender)
                        {
                            Logging.warn("Message with id {0} was already in message list.", Crypto.hashToString(id));
                        }else
                        {
                            friend.setMessageRead(channel, id);
                        }
                        if (messages.Last() == tmp_msg)
                        {
                            friend.metaData.setLastMessage(tmp_msg, channel);
                            friend.metaData.setLastReceivedMessageIds(tmp_msg.id, channel);
                            friend.saveMetaData();
                        }
                        return null;
                    }else
                    {
                        friend.metaData.setLastReceivedMessageIds(friend_message.id, channel);
                        friend.saveMetaData();
                    }
                }
                else if(!local_sender)
                {
                    Logging.error("Message id sent by {0} is null!", friend.walletAddress.ToString());
                    return null;
                }
                messages.Add(friend_message);
            }

            bool old_message = false;
            // Check if the message was sent before the friend was added to the contact list
            if(friend.addedTimestamp > friend_message.timestamp)
            {
                old_message = true;               
            }

            if (set_read || old_message)
            {
                friend_message.confirmed = true;
                friend_message.read = true;
            }

            friend.metaData.setLastMessage(friend_message, channel);
            friend.saveMetaData();

            // Write to chat history
            IxianHandler.localStorage.requestWriteMessages(wallet_address, channel);
            return friend_message;
        }

        // Sort the friend list alphabetically based on nickname
        public static void sortFriends()
        {
            friends = friends.OrderBy(x => x.nickname).ToList();
        }

        public static Friend addFriend(FriendState state, Address wallet_address, byte[] public_key, string name, byte[] aes_key, byte[] chacha_key, long key_generated_time, bool approved = true)
        {
            Friend new_friend = new Friend(state, wallet_address, public_key, name, aes_key, chacha_key, key_generated_time, approved);
            return addFriend(new_friend);
        }

        public static Friend addFriend(Friend new_friend)
        {
            if(friends.Find(x => x.walletAddress.SequenceEqual(new_friend.walletAddress)) != null)
            {
                // Already in the list
                return null;
            }

            lock (friends)
            {
                // Add new friend to the friendlist
                friends.Add(new_friend);
            }

            if (new_friend.approved)
            {
                lock (friendMatcher)
                {
                    if (friendMatcher.Add(new_friend.walletAddress.addressNoChecksum) == Cuckoo.CuckooStatus.NotEnoughSpace)
                    {
                        // rebuild cuckoo filter with a larger size
                        friendMatcher = new Cuckoo(friendMatcher.numItems * 2);
                        lock (friends)
                        {
                            foreach (Friend f in friends)
                            {
                                friendMatcher.Add(f.walletAddress.addressNoChecksum);
                            }
                        }
                    }
                }
            }

            sortFriends();

            return new_friend;
        }

        // Clear the entire list of contacts
        public static bool clear()
        {
            lock (friends)
            {
                friends.Clear();
            }
            return true;
        }

        // Removes a friend from the list
        public static bool removeFriend(Friend friend)
        {
            // Remove history file
            IxianHandler.localStorage.deleteMessages(friend.walletAddress);

            // Delete avatar
            IxianHandler.localStorage.deleteAvatar(friend.walletAddress.ToString());

            lock (friends)
            {
                if (!friends.Remove(friend))
                {
                    return false;
                }
            }

            lock(friendMatcher)
            {
                friendMatcher.Delete(friend.walletAddress.addressNoChecksum);
            }

            // Write changes to storage
            friend.delete();

            return true;
        }

        // Finds a presence entry's pubkey
        public static byte[] findContactPubkey(Address wallet_address)
        {
            Friend f = getFriend(wallet_address);
            if(f != null && f.publicKey != null)
            {
                return f.publicKey;
            }

            Presence p = PresenceList.getPresenceByAddress(wallet_address);
            if(p != null && p.addresses.Find(x => x.type == 'C') != null)
            {
                return p.pubkey;
            }
            return null;
        }

        // Retrieve a presence entry connected S2 node. Returns null if not found
        public static string getRelayHostname(Address wallet_address)
        {
            string hostname = null;
            Presence presence = PresenceList.getPresenceByAddress(wallet_address);
            if (presence == null)
            {
                using (MemoryStream mw = new MemoryStream())
                {
                    using (BinaryWriter writer = new BinaryWriter(mw))
                    {
                        writer.WriteIxiVarInt(wallet_address.addressWithChecksum.Length);
                        writer.Write(wallet_address.addressWithChecksum);

                        CoreProtocolMessage.broadcastProtocolMessage(new char[] { 'M', 'H' }, ProtocolMessageCode.getPresence2, mw.ToArray(), null);
                    }
                }
                return null;
            }

            lock (presence)
            {
                // Go through each presence address searching for C nodes
                foreach (PresenceAddress addr in presence.addresses)
                {
                    // Only check Client nodes
                    if (addr.type == 'C')
                    {
                        string[] hostname_split = addr.address.Split(':');

                        if (hostname_split.Count() == 2 && NetworkUtils.validateIP(hostname_split[0]))
                        {
                            hostname = addr.address;
                            break;
                        }
                    }
                }
            }

            // Finally, return the ip address of the node
            return hostname;
        }

        public static void deleteAccounts()
        {
            lock (friends)
            {
                foreach (Friend friend in friends)
                {
                    friend.delete();
                }
            }
        }

        // Deletes entire history for all friends in the friendlist
        public static void deleteEntireHistory()
        {
            lock (friends)
            {
                foreach (Friend friend in friends)
                {
                    // Clear messages from memory
                    friend.deleteHistory();
                }
            }
        }

        // Returns the number of unread messages
        public static int getUnreadMessageCount()
        {
            int unreadCount = 0;
            lock (friends)
            {
                // Go through each friend and check for the pubkey in the PL
                foreach (Friend friend in friends)
                {
                    unreadCount += friend.getUnreadMessageCount();
                }
            }
            return unreadCount;
        }

        public static byte[] getFriendCuckooFilter()
        {
            lock (friendMatcher)
            {
                return friendMatcher.getFilterBytes();
            }
        }

        public static void requestAllFriendsPresences()
        {
            // TODO TODO use hidden address matcher
            List<Friend> tmp_friends = null;
            lock (friends)
            {
                tmp_friends = new List<Friend>(friends);
            }
            foreach (var entry in tmp_friends)
            {
                using (MemoryStream m = new MemoryStream(1280))
                {
                    using (BinaryWriter writer = new BinaryWriter(m))
                    {
                        writer.WriteIxiVarInt(entry.walletAddress.addressWithChecksum.Length);
                        writer.Write(entry.walletAddress.addressWithChecksum);

                        CoreProtocolMessage.broadcastProtocolMessageToSingleRandomNode(new char[] { 'M', 'H' }, ProtocolMessageCode.getPresence2, m.ToArray(), 0, null);
                    }
                }
            }
        }

        public static void broadcastNicknameChange()
        {
            new Thread(() =>
            {
                List<Friend> tmp_friends = null;
                lock (friends)
                {
                    tmp_friends = new List<Friend>(friends);
                }
                foreach (var friend in tmp_friends)
                {
                    if (friend.approved)
                    {
                        CoreStreamProcessor.sendNickname(friend);
                    }
                }
            }).Start();
        }

        public static void broadcastAvatarChange()
        {
            new Thread(() =>
            {
                List<Friend> tmp_friends = null;
                lock (friends)
                {
                    tmp_friends = new List<Friend>(friends);
                }
                foreach (var friend in tmp_friends)
                {
                    if (friend.handshakeStatus >= 3)
                    {
                        CoreStreamProcessor.sendAvatar(friend);
                    }
                }
            }).Start();
        }


        public static void onLowMemory(List<Address> excludeAddresses)
        {
            lock (friends)
            {
                var ac = new AddressComparer();
                foreach (var friend in friends)
                {
                    if (excludeAddresses.Contains(friend.walletAddress, ac))
                    {
                        continue;
                    }
                    friend.freeMemory();
                }
            }
        }

        public static void loadContacts()
        {
            if(contactsLoaded)
            {
                return;
            }
            contactsLoaded = true;
            lock (friends)
            {
                friends.Clear();

                var accs = Directory.EnumerateDirectories(accountsPath);
                foreach(var acc in accs)
                {
                    string acc_path = Path.Combine(acc, "account.ixi");
                    if (File.Exists(acc_path))
                    {
                        try
                        {
                            Friend f = addFriend(new Friend(File.ReadAllBytes(acc_path)));
                            if (f != null)
                            {
                                f.loadMetaData();
                            }
                            else
                            {
                                Logging.error("Error adding contact {0}", acc);
                            }
                        }catch(Exception e)
                        {
                            Logging.error("Exception occured while loading contact {0}: {1}", acc, e);
                        }
                    }else
                    {
                        Logging.error("Error adding contact {0}, account.ixi doesn't exist", acc);
                    }
                }
            }
        }
    }
}

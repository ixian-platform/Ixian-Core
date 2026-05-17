using IXICore.Meta;
using IXICore.SpixiBot;
using System;
using System.Collections.Generic;

namespace IXICore.Streaming
{
    public class GroupChat
    {
        private static byte virtualAddressVersion = 1;
        private GroupChat() { }

        public static Address DeriveGroupAddress(Address creator, byte[] randomId)
        {
            byte[] derivationBytes = new byte[creator.addressNoChecksum.Length + randomId.Length];
            creator.addressNoChecksum.CopyTo(derivationBytes, 0);
            randomId.CopyTo(derivationBytes, creator.addressNoChecksum.Length);
            byte[] hash = CryptoManager.lib.sha3_512sqTrunc(derivationBytes, 0, 0, Address.addressVersionLengths[virtualAddressVersion] - 1);

            byte[] groupAddressBytes = new byte[Address.addressVersionLengths[1]];
            groupAddressBytes[0] = virtualAddressVersion;
            hash.CopyTo(groupAddressBytes, 1);

            return new Address(groupAddressBytes);
        }

        public static Friend CreateGroup(Address creator, OrderedDictionary<Address, string?> participants, string groupName, bool hideParticipantAddresses)
        {
            // Lock group address to creator's address and random identifier
            byte[] randomId = new byte[16];
            Random.Shared.NextBytes(randomId);
            Address groupAddress = DeriveGroupAddress(creator, randomId);

            Friend f = new Friend(FriendType.Group, FriendState.Approved, groupAddress, null, groupName, null, null, 0, true);
            f.setGroupMode();
            if (FriendList.addFriend(f) == null)
            {
                throw new Exception($"Failed to join group {groupName}, could not add to friend list.");
            }

            f.save();

            // Always add creator as the first contact
            f.users.setUser(new BotContact(null, creator.pubKey, 0, false, false, BotContactStatus.normal));
            foreach (var participant in participants)
            {
                var pf = FriendList.getFriend(participant.Key);
                if (pf == null)
                {
                    throw new Exception($"Cannot create group, missing contact {participant.ToString()}");
                }

                f.users.setUser(new BotContact(null, pf.publicKey, 0, false, false, BotContactStatus.normal));
            }

            f.metaData.botInfo = new BotInfo(0, randomId, hideParticipantAddresses, "", 0, 0, true, 0, 0, true, f.users.count());
            f.saveMetaData();

            return f;
        }

        public static Friend JoinGroup(Address creator, byte[] randomId, OrderedDictionary<Address, string?>? participants, string groupName, bool hideParticipantAddresses, long timestamp)
        {
            // Lock group address to creator's address and group name
            Address groupAddress = DeriveGroupAddress(creator, randomId);

            Friend? f = FriendList.getFriend(groupAddress);
            if (f == null)
            {
                f = new Friend(FriendType.Group, FriendState.Approved, groupAddress, null, groupName, null, null, 0, true);
                f.setGroupMode();
                if (FriendList.addFriend(f) == null)
                {
                    throw new Exception($"Failed to join group {groupName}, could not add to friend list.");
                }
            }
            else if (f.lastReceivedHandshakeMessageTimestamp > timestamp)
            {
                // Playback protection
                throw new Exception($"Failed to join group {groupName}, already joined with a newer or same handshake message.");
            }

            f.lastReceivedHandshakeMessageTimestamp = timestamp;
            f.save();

            f.users.clearUsers();

            // Always add creator as the first contact
            f.users.setUser(new BotContact(null, creator.pubKey, 0, false, false, BotContactStatus.normal));
            if (participants != null)
            {
                foreach (var participant in participants)
                {
                    var bc = new BotContact(null, participant.Key.addressNoChecksum, 0, false, false, BotContactStatus.normal);
                    if (!string.IsNullOrEmpty(participant.Value))
                    {
                        bc.setNick(participant.Value);
                    }
                    f.users.setUser(bc);
                }
            }

            f.metaData.botInfo = new BotInfo(0, randomId, hideParticipantAddresses, "", 0, 0, false, 0, 0, true, f.users.count());
            f.saveMetaData();

            return f;
        }

        public bool AddParticipant(Friend group, BotContact participant)
        {
            group.users.setUser(participant);
            return true;
        }

        public bool RemoveParticipant(Friend group, Address participant)
        {
            return group.users.delUser(participant);
        }

        public static Friend? ValidateAndGetGroup(Address groupAddress, Address senderAddress)
        {
            var group = FriendList.getFriend(groupAddress);
            if (group == null)
            {
                Logging.warn("Validating group {0} but it doesn't exist.", groupAddress.ToString());
                return null;
            }
            if (group.type != FriendType.Group)
            {
                Logging.warn("Validating group {0} but contact is not a group.", groupAddress.ToString());
                return null;
            }
            if (!group.users.hasUser(senderAddress))
            {
                Logging.warn("Validating group {0} but sender {1} is not a group.", groupAddress.ToString(), senderAddress.ToString());
                return null;
            }

            return group;
        }
    }
}

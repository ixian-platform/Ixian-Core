using IXICore;
using IXICore.SpixiBot;
using IXICore.Streaming;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace UnitTests
{
    [TestClass]
    public class TestGroupChat
    {
        private static byte[] RandomBytes(int length)
        {
            byte[] bytes = new byte[length];
            RandomNumberGenerator.Fill(bytes);
            return bytes;
        }
        private static (byte[] privateKey, byte[] publicKey) GenerateRsaKeypair()
        {
            var rsa = CryptoManager.lib.generateKeys(4096, 1);

            return (
                rsa.privateKeyBytes,
                rsa.publicKeyBytes
            );
        }

        private static Address GenerateAddress()
        {
            var keys = GenerateRsaKeypair();
            return new Address(keys.publicKey);
        }

        private static Friend CreateFriend(Address address)
        {
            Friend friend = new Friend(
                FriendType.Normal,
                FriendState.Approved,
                address,
                address.addressNoChecksum,
                "test",
                null,
                null,
                0,
                true);

            return friend;
        }

        [TestInitialize]
        public void Init()
        {
            // Optional:
            // If FriendList has reset/clear support in your project,
            // call it here to isolate tests.
            //
            // Example:
            // FriendList.clear();
        }

        #region DERIVE GROUP ADDRESS TESTS

        [TestMethod]
        public void DeriveGroupAddress_SameInputs_ProducesSameAddress()
        {
            Address creator = GenerateAddress();
            byte[] randomId = RandomBytes(16);

            Address group1 = GroupChat.DeriveGroupAddress(
                creator,
                randomId);

            Address group2 = GroupChat.DeriveGroupAddress(
                creator,
                randomId);

            CollectionAssert.AreEqual(
                group1.addressNoChecksum,
                group2.addressNoChecksum);
        }

        [TestMethod]
        public void DeriveGroupAddress_DifferentRandomIds_ProducesDifferentAddresses()
        {
            Address creator = GenerateAddress();

            Address group1 = GroupChat.DeriveGroupAddress(
                creator,
                RandomBytes(16));

            Address group2 = GroupChat.DeriveGroupAddress(
                creator,
                RandomBytes(16));

            CollectionAssert.AreNotEqual(
                group1.addressNoChecksum,
                group2.addressNoChecksum);
        }

        [TestMethod]
        public void DeriveGroupAddress_DifferentCreators_ProducesDifferentAddresses()
        {
            byte[] randomId = RandomBytes(16);

            Address group1 = GroupChat.DeriveGroupAddress(
                GenerateAddress(),
                randomId);

            Address group2 = GroupChat.DeriveGroupAddress(
                GenerateAddress(),
                randomId);

            CollectionAssert.AreNotEqual(
                group1.addressNoChecksum,
                group2.addressNoChecksum);
        }

        [TestMethod]
        public void DeriveGroupAddress_UsesVirtualAddressVersion()
        {
            Address creator = GenerateAddress();

            Address group = GroupChat.DeriveGroupAddress(
                creator,
                RandomBytes(16));

            Assert.AreEqual(1, group.addressNoChecksum[0]);
        }

        [TestMethod]
        public void DeriveGroupAddress_IsNeverEmpty()
        {
            Address creator = GenerateAddress();

            Address group = GroupChat.DeriveGroupAddress(
                creator,
                RandomBytes(16));

            Assert.IsNotNull(group);
            Assert.IsNotNull(group.addressNoChecksum);

            Assert.IsFalse(
                group.addressNoChecksum.All(b => b == 0));
        }

        #endregion

        #region CREATE GROUP TESTS

        [TestMethod]
        public void CreateGroup_CreatesValidGroup()
        {
            Address creator = GenerateAddress();

            Friend creatorFriend = CreateFriend(creator);

            FriendList.addFriend(creatorFriend);

            OrderedDictionary<Address, string?> participants =
                new OrderedDictionary<Address, string?>();

            Address participantAddress = GenerateAddress();

            Friend participantFriend = CreateFriend(participantAddress);

            FriendList.addFriend(participantFriend);

            participants.Add(participantAddress, "alice");

            Friend group = GroupChat.CreateGroup(
                creator,
                participants,
                "Test Group",
                false);

            Assert.IsNotNull(group);

            Assert.AreEqual(FriendType.Group, group.type);

            Assert.IsTrue(group.users.count() >= 2);

            Assert.IsNotNull(group.metaData);
            Assert.IsNotNull(group.metaData.botInfo);
        }

        [TestMethod]
        public void CreateGroup_AddsCreatorAsFirstParticipant()
        {
            Address creator = GenerateAddress();

            Friend creatorFriend = CreateFriend(creator);

            FriendList.addFriend(creatorFriend);

            OrderedDictionary<Address, string?> participants =
                new OrderedDictionary<Address, string?>();

            Friend group = GroupChat.CreateGroup(
                creator,
                participants,
                "Test Group",
                false);

            Assert.IsTrue(
                group.users.hasUser(creator));
        }

        [TestMethod]
        public void CreateGroup_WithHiddenParticipants_SetsMetadata()
        {
            Address creator = GenerateAddress();

            Friend creatorFriend = CreateFriend(creator);

            FriendList.addFriend(creatorFriend);

            OrderedDictionary<Address, string?> participants =
                new OrderedDictionary<Address, string?>();

            Friend group = GroupChat.CreateGroup(
                creator,
                participants,
                "Hidden Group",
                true);

            Assert.IsTrue(
                group.metaData.botInfo.hideParticipantAddresses);
        }

        [TestMethod]
        public void CreateGroup_MissingParticipant_Throws()
        {
            Address creator = GenerateAddress();

            Friend creatorFriend = CreateFriend(creator);

            FriendList.addFriend(creatorFriend);

            OrderedDictionary<Address, string?> participants =
                new OrderedDictionary<Address, string?>();

            participants.Add(
                GenerateAddress(),
                "missing-user");

            try
            {
                _ = GroupChat.CreateGroup(
                    creator,
                    participants,
                    "Invalid Group",
                    false);
            }
            catch
            {
                return;
            }

            Assert.Fail();
        }

        #endregion

        #region JOIN GROUP TESTS

        [TestMethod]
        public void JoinGroup_CreatesGroup_WhenNotExisting()
        {
            Address creator = GenerateAddress();

            byte[] randomId = RandomBytes(16);

            OrderedDictionary<Address, string?> participants =
                new OrderedDictionary<Address, string?>();

            Address participantAddress = GenerateAddress();

            participants.Add(participantAddress, "bob");

            Friend group = GroupChat.JoinGroup(
                creator,
                randomId,
                participants,
                "Joined Group",
                false,
                100);

            Assert.IsNotNull(group);

            Assert.AreEqual(FriendType.Group, group.type);

            Assert.IsTrue(group.users.count() >= 1);
        }

        [TestMethod]
        public void JoinGroup_AddsCreator()
        {
            Address creator = GenerateAddress();

            Friend group = GroupChat.JoinGroup(
                creator,
                RandomBytes(16),
                null,
                "Creator Test",
                false,
                100);

            Assert.IsTrue(group.users.hasUser(creator));
        }

        [TestMethod]
        public void JoinGroup_AddsParticipants()
        {
            Address creator = GenerateAddress();

            OrderedDictionary<Address, string?> participants =
                new OrderedDictionary<Address, string?>();

            Address p1 = GenerateAddress();
            Address p2 = GenerateAddress();

            participants.Add(p1, "alice");
            participants.Add(p2, "bob");

            Friend group = GroupChat.JoinGroup(
                creator,
                RandomBytes(16),
                participants,
                "Participants",
                false,
                100);

            Assert.IsTrue(group.users.hasUser(p1));
            Assert.IsTrue(group.users.hasUser(p2));
        }

        [TestMethod]
        public void JoinGroup_SetsParticipantNicknames()
        {
            Address creator = GenerateAddress();

            OrderedDictionary<Address, string?> participants =
                new OrderedDictionary<Address, string?>();

            Address participant = GenerateAddress();

            participants.Add(participant, "alice");

            Friend group = GroupChat.JoinGroup(
                creator,
                RandomBytes(16),
                participants,
                "Nicknames",
                false,
                100);

            BotContact user = group.users.getUser(participant);

            Assert.IsNotNull(user);

            Assert.AreEqual("alice", user.getNick());
        }

        [TestMethod]
        public void JoinGroup_UpdatesExistingGroup()
        {
            Address creator = GenerateAddress();

            byte[] randomId = RandomBytes(16);

            Friend group1 = GroupChat.JoinGroup(
                creator,
                randomId,
                null,
                "Group",
                false,
                100);

            Friend group2 = GroupChat.JoinGroup(
                creator,
                randomId,
                null,
                "Group",
                false,
                200);

            Assert.AreEqual(
                200,
                group2.lastReceivedHandshakeMessageTimestamp);
        }

        [TestMethod]
        public void JoinGroup_ReplayAttack_Throws()
        {
            Address creator = GenerateAddress();

            byte[] randomId = RandomBytes(16);

            _ = GroupChat.JoinGroup(
                creator,
                randomId,
                null,
                "Replay",
                false,
                200);

            try
            {
                _ = GroupChat.JoinGroup(
                    creator,
                    randomId,
                    null,
                    "Replay",
                    false,
                    100);
            }
            catch
            {
                return;
            }

            Assert.Fail();
        }

        [TestMethod]
        public void JoinGroup_WithHiddenParticipants_SetsMetadata()
        {
            Address creator = GenerateAddress();

            Friend group = GroupChat.JoinGroup(
                creator,
                RandomBytes(16),
                null,
                "Hidden",
                true,
                100);

            Assert.IsTrue(
                group.metaData.botInfo.hideParticipantAddresses);
        }

        [TestMethod]
        public void JoinGroup_NullParticipants_Works()
        {
            Address creator = GenerateAddress();

            Friend group = GroupChat.JoinGroup(
                creator,
                RandomBytes(16),
                null,
                "Null Participants",
                false,
                100);

            Assert.IsNotNull(group);

            Assert.IsTrue(group.users.count() >= 1);
        }

        #endregion

        #region PARTICIPANT MANAGEMENT TESTS

        [TestMethod]
        public void AddParticipant_AddsUser()
        {
            Address creator = GenerateAddress();

            Friend group = GroupChat.JoinGroup(
                creator,
                RandomBytes(16),
                null,
                "Add User",
                false,
                100);

            GroupChat gc =
                (GroupChat)Activator.CreateInstance(
                    typeof(GroupChat),
                    true);

            Address participant = GenerateAddress();

            BotContact bc = new BotContact(
                null,
                participant.addressNoChecksum,
                0,
                false,
                false,
                BotContactStatus.normal);

            bool result = gc.AddParticipant(group, bc);

            Assert.IsTrue(result);

            Assert.IsTrue(group.users.hasUser(participant));
        }

        [TestMethod]
        public void RemoveParticipant_RemovesUser()
        {
            Address creator = GenerateAddress();

            OrderedDictionary<Address, string?> participants =
                new OrderedDictionary<Address, string?>();

            Address participant = GenerateAddress();

            participants.Add(participant, "alice");

            Friend group = GroupChat.JoinGroup(
                creator,
                RandomBytes(16),
                participants,
                "Remove User",
                false,
                100);

            GroupChat gc =
                (GroupChat)Activator.CreateInstance(
                    typeof(GroupChat),
                    true);

            bool removed = gc.RemoveParticipant(
                group,
                participant);

            Assert.IsTrue(removed);

            Assert.IsFalse(group.users.hasUser(participant));
        }

        [TestMethod]
        public void RemoveParticipant_UnknownUser_ReturnsFalse()
        {
            Address creator = GenerateAddress();

            Friend group = GroupChat.JoinGroup(
                creator,
                RandomBytes(16),
                null,
                "Remove Unknown",
                false,
                100);

            GroupChat gc =
                (GroupChat)Activator.CreateInstance(
                    typeof(GroupChat),
                    true);

            bool removed = gc.RemoveParticipant(
                group,
                GenerateAddress());

            Assert.IsFalse(removed);
        }

        #endregion

        #region VALIDATION TESTS

        [TestMethod]
        public void ValidateAndGetGroup_ValidGroup_ReturnsGroup()
        {
            Address creator = GenerateAddress();

            Friend group = GroupChat.JoinGroup(
                creator,
                RandomBytes(16),
                null,
                "Validation",
                false,
                100);

            Friend result = GroupChat.ValidateAndGetGroup(
                group.walletAddress,
                creator);

            Assert.IsNotNull(result);

            Assert.AreEqual(
                group.walletAddress,
                result.walletAddress);
        }

        [TestMethod]
        public void ValidateAndGetGroup_MissingGroup_ReturnsNull()
        {
            Friend result = GroupChat.ValidateAndGetGroup(
                GenerateAddress(),
                GenerateAddress());

            Assert.IsNull(result);
        }

        [TestMethod]
        public void ValidateAndGetGroup_NonGroupFriend_ReturnsNull()
        {
            Address address = GenerateAddress();

            Friend friend = CreateFriend(address);

            FriendList.addFriend(friend);

            Friend result = GroupChat.ValidateAndGetGroup(
                address,
                address);

            Assert.IsNull(result);
        }

        [TestMethod]
        public void ValidateAndGetGroup_SenderNotInGroup_ReturnsNull()
        {
            Address creator = GenerateAddress();

            Friend group = GroupChat.JoinGroup(
                creator,
                RandomBytes(16),
                null,
                "Validation",
                false,
                100);

            Friend result = GroupChat.ValidateAndGetGroup(
                group.walletAddress,
                GenerateAddress());

            Assert.IsNull(result);
        }

        #endregion

        [TestMethod]
        public void DeriveGroupAddress_HasStableDeterministicOutput()
        {
            Address creator = GenerateAddress();

            byte[] randomId = Enumerable.Repeat(
                (byte)0xAB,
                16).ToArray();

            Address addr1 = GroupChat.DeriveGroupAddress(
                creator,
                randomId);

            Address addr2 = GroupChat.DeriveGroupAddress(
                creator,
                randomId);

            CollectionAssert.AreEqual(
                addr1.addressNoChecksum,
                addr2.addressNoChecksum);
        }

        [TestMethod]
        public void DeriveGroupAddress_HasNoPlaintextLeakage()
        {
            Address creator = GenerateAddress();

            byte[] randomId = RandomBytes(16);

            Address group = GroupChat.DeriveGroupAddress(
                creator,
                randomId);

            CollectionAssert.AreNotEqual(
                creator.addressNoChecksum,
                group.addressNoChecksum);

            CollectionAssert.AreNotEqual(
                randomId,
                group.addressNoChecksum.Take(randomId.Length).ToArray());
        }

        [TestMethod]
        public void JoinGroup_RejoinWithNewerTimestamp_Succeeds()
        {
            Address creator = GenerateAddress();

            byte[] randomId = RandomBytes(16);

            Friend first = GroupChat.JoinGroup(
                creator,
                randomId,
                null,
                "Timestamp",
                false,
                100);

            Friend second = GroupChat.JoinGroup(
                creator,
                randomId,
                null,
                "Timestamp",
                false,
                101);

            Assert.IsNotNull(second);

            Assert.AreEqual(
                101,
                second.lastReceivedHandshakeMessageTimestamp);
        }

        [TestMethod]
        public void GroupContainsExpectedUserCount()
        {
            Address creator = GenerateAddress();

            OrderedDictionary<Address, string?> participants =
                new OrderedDictionary<Address, string?>();

            participants.Add(GenerateAddress(), "a");
            participants.Add(GenerateAddress(), "b");
            participants.Add(GenerateAddress(), "c");

            Friend group = GroupChat.JoinGroup(
                creator,
                RandomBytes(16),
                participants,
                "Count",
                false,
                100);

            // creator + 3 participants
            Assert.AreEqual(4, group.users.count());
        }

        [TestMethod]
        public void GroupAddress_IsUniqueAcrossRandomIds()
        {
            Address creator = GenerateAddress();

            var addresses = Enumerable.Range(0, 100)
                .Select(_ =>
                    GroupChat.DeriveGroupAddress(
                        creator,
                        RandomBytes(16)))
                .Select(a => Convert.ToHexString(a.addressNoChecksum))
                .ToList();

            int uniqueCount = addresses.Distinct().Count();

            Assert.AreEqual(100, uniqueCount);
        }
    }
}

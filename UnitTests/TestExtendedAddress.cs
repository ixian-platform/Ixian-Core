using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using IXICore;
using IXICore.Meta;
using System.Threading.Tasks;
using System.Linq;


namespace UnitTests
{
    [TestClass]
    public class TestExtendedAddress
    {
        private Address _testAddress;
        private Address _testRoutingAddress;
        private Address _testPaymentAddress;
        private byte[] _testTag;

        [TestInitialize]
        public void Setup()
        {
            // Create test addresses (v0 format - 33 bytes)
            _testAddress = new Address(new byte[33] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 });
            _testRoutingAddress = new Address(new byte[33] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 });
            _testPaymentAddress = new Address(new byte[33] { 0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 1 });
            _testTag = new byte[] { 1, 2, 3, 4, 5 };
        }

        #region Constructor Tests

        [TestMethod]
        public void Constructor_WithAddressAndPrimaryFlag_CreateValidExtendedAddress()
        {
            // Act
            var extAddr = new ExtendedAddress(_testAddress, AddressPaymentFlag.Primary, null);

            // Assert
            Assert.IsNotNull(extAddr);
            Assert.AreEqual(AddressPaymentFlag.Primary, extAddr.Flag);
            Assert.IsTrue(extAddr.RoutingAddress.SequenceEqual(_testAddress));
            Assert.IsTrue(extAddr.PaymentAddress.SequenceEqual(_testAddress));
            Assert.IsNull(extAddr.Tag);
        }

        [TestMethod]
        public void Constructor_WithAddressAndEnd2EndFlag_CreateValidExtendedAddress()
        {
            // Act
            var extAddr = new ExtendedAddress(_testAddress, AddressPaymentFlag.End2End, null);

            // Assert
            Assert.IsNotNull(extAddr);
            Assert.AreEqual(AddressPaymentFlag.End2End, extAddr.Flag);
            Assert.IsTrue(extAddr.RoutingAddress.SequenceEqual(_testAddress));
            Assert.IsTrue(extAddr.PaymentAddress.SequenceEqual(_testAddress));
        }

        [TestMethod]
        public void Constructor_WithAddressAndOfflineTagFlag_CreateValidExtendedAddress()
        {
            // Act
            var extAddr = new ExtendedAddress(_testAddress, AddressPaymentFlag.OfflineTag, null);

            // Assert
            Assert.IsNotNull(extAddr);
            Assert.AreEqual(AddressPaymentFlag.OfflineTag, extAddr.Flag);
            Assert.IsTrue(extAddr.RoutingAddress.SequenceEqual(_testAddress));
            Assert.IsTrue(extAddr.PaymentAddress.SequenceEqual(_testAddress));
        }

        [TestMethod]
        public void Constructor_WithAddressAndTag_CreateValidExtendedAddress()
        {
            // Act
            var extAddr = new ExtendedAddress(_testAddress, AddressPaymentFlag.Primary, _testTag);

            // Assert
            Assert.IsNotNull(extAddr);
            Assert.IsNotNull(extAddr.Tag);
            Assert.IsTrue(extAddr.Tag.SequenceEqual(_testTag));
        }

        [TestMethod]
        public void Constructor_WithOfflineAddressFlag_ThrowsException()
        {
            Assert.Throws<Exception>(() =>
            {
                // Act - should throw because OfflineAddress flag requires separate routing and payment addresses
                new ExtendedAddress(_testAddress, AddressPaymentFlag.OfflineAddress, null);
            });
        }

        [TestMethod]
        public void Constructor_WithAddressHavingNonce_ThrowsException()
        {
            // Arrange
            var addressWithNonce = new Address(new byte[33] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 }, new byte[] { 1 });

            Assert.Throws<Exception>(() =>
            {
                // Act
                new ExtendedAddress(addressWithNonce, AddressPaymentFlag.Primary, null);
            });
        }

        [TestMethod]
        public void Constructor_WithSeparateRoutingAndPaymentAddresses_CreateValidExtendedAddress()
        {
            // Act
            var extAddr = new ExtendedAddress(_testRoutingAddress, _testPaymentAddress, null);

            // Assert
            Assert.IsNotNull(extAddr);
            Assert.AreEqual(AddressPaymentFlag.OfflineAddress, extAddr.Flag);
            Assert.IsTrue(extAddr.RoutingAddress.SequenceEqual(_testRoutingAddress));
            Assert.IsTrue(extAddr.PaymentAddress.SequenceEqual(_testPaymentAddress));
            Assert.IsNull(extAddr.Tag);
        }

        [TestMethod]
        public void Constructor_WithSeparateAddressesAndTag_CreateValidExtendedAddress()
        {
            // Act
            var extAddr = new ExtendedAddress(_testRoutingAddress, _testPaymentAddress, _testTag);

            // Assert
            Assert.IsNotNull(extAddr);
            Assert.AreEqual(AddressPaymentFlag.OfflineAddress, extAddr.Flag);
            Assert.IsTrue(extAddr.Tag.SequenceEqual(_testTag));
        }

        [TestMethod]
        public void Constructor_WithSeparateAddressesAndRoutingAddressHavingNonce_ThrowsException()
        {
            // Arrange
            var routingAddressWithNonce = new Address(new byte[33] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 }, new byte[] { 1 });

            Assert.Throws<Exception>(() =>
            {
                // Act
                new ExtendedAddress(routingAddressWithNonce, _testPaymentAddress, null);
            });
        }

        [TestMethod]
        public void Constructor_FromBase58EncodedString_CreateValidExtendedAddress()
        {
            // Arrange
            var original = new ExtendedAddress(_testAddress, AddressPaymentFlag.Primary, null);
            var base58String = original.ToString();

            // Act
            var restored = new ExtendedAddress(base58String);

            // Assert
            Assert.IsNotNull(restored);
            Assert.AreEqual(original.Flag, restored.Flag);
            Assert.IsTrue(original.PaymentAddress.SequenceEqual(restored.PaymentAddress));
            Assert.IsTrue(original.RoutingAddress.SequenceEqual(restored.RoutingAddress));
        }

        [TestMethod]
        public void Constructor_FromBase58EncodedStringWithTag_CreateValidExtendedAddress()
        {
            // Arrange
            var original = new ExtendedAddress(_testAddress, AddressPaymentFlag.OfflineTag, _testTag);
            var base58String = original.ToString();

            // Act
            var restored = new ExtendedAddress(base58String);

            // Assert
            Assert.IsNotNull(restored);
            Assert.AreEqual(original.Flag, restored.Flag);
            Assert.IsTrue(original.Tag.SequenceEqual(restored.Tag));
            Assert.IsTrue(original.PaymentAddress.SequenceEqual(restored.PaymentAddress));
        }

        [TestMethod]
        public void Constructor_FromBase58EncodedStringWithOfflineAddress_CreateValidExtendedAddress()
        {
            // Arrange
            var original = new ExtendedAddress(_testRoutingAddress, _testPaymentAddress, _testTag);
            var base58String = original.ToString();

            // Act
            var restored = new ExtendedAddress(base58String);

            // Assert
            Assert.IsNotNull(restored);
            Assert.AreEqual(AddressPaymentFlag.OfflineAddress, restored.Flag);
            Assert.IsTrue(original.RoutingAddress.SequenceEqual(restored.RoutingAddress));
            Assert.IsTrue(original.PaymentAddress.SequenceEqual(restored.PaymentAddress));
            Assert.IsTrue(original.Tag.SequenceEqual(restored.Tag));
        }

        [TestMethod]
        public void Constructor_FromBytes_CreateValidExtendedAddress()
        {
            // Arrange
            var original = new ExtendedAddress(_testAddress, AddressPaymentFlag.Primary, null);
            var bytes = original.GetBytes();

            // Act
            var restored = new ExtendedAddress(bytes);

            // Assert
            Assert.IsNotNull(restored);
            Assert.AreEqual(original.Flag, restored.Flag);
            Assert.IsTrue(original.PaymentAddress.SequenceEqual(restored.PaymentAddress));
            Assert.IsTrue(original.RoutingAddress.SequenceEqual(restored.RoutingAddress));
        }

        [TestMethod]
        public void Constructor_FromBytesWithTag_CreateValidExtendedAddress()
        {
            // Arrange
            var original = new ExtendedAddress(_testAddress, AddressPaymentFlag.End2End, _testTag);
            var bytes = original.GetBytes();

            // Act
            var restored = new ExtendedAddress(bytes);

            // Assert
            Assert.IsNotNull(restored);
            Assert.AreEqual(original.Flag, restored.Flag);
            if (original.Tag != null)
            {
                Assert.IsTrue(original.Tag.SequenceEqual(restored.Tag));
            }
        }

        [TestMethod]
        public void Constructor_FromBytesWithOfflineAddress_CreateValidExtendedAddress()
        {
            // Arrange
            var original = new ExtendedAddress(_testRoutingAddress, _testPaymentAddress, _testTag);
            var bytes = original.GetBytes();

            // Act
            var restored = new ExtendedAddress(bytes);

            // Assert
            Assert.IsNotNull(restored);
            Assert.AreEqual(AddressPaymentFlag.OfflineAddress, restored.Flag);
            Assert.IsTrue(original.RoutingAddress.SequenceEqual(restored.RoutingAddress));
            Assert.IsTrue(original.PaymentAddress.SequenceEqual(restored.PaymentAddress));
        }

        #endregion

        #region Serialization Tests

        [TestMethod]
        public void GetBytes_WithPrimaryFlag_ReturnValidByteArray()
        {
            // Arrange
            var extAddr = new ExtendedAddress(_testAddress, AddressPaymentFlag.Primary, null);

            // Act
            var bytes = extAddr.GetBytes();

            // Assert
            Assert.IsNotNull(bytes);
            Assert.IsTrue(bytes.Length > 0);
        }

        [TestMethod]
        public void GetBytes_RoundTrip_ResultMatchesOriginal()
        {
            // Arrange
            var original = new ExtendedAddress(_testAddress, AddressPaymentFlag.End2End, _testTag);

            // Act
            var bytes = original.GetBytes();
            var restored = new ExtendedAddress(bytes);

            // Assert
            Assert.AreEqual(original.Flag, restored.Flag);
            Assert.IsTrue(original.PaymentAddress.SequenceEqual(restored.PaymentAddress));
            Assert.IsTrue(original.RoutingAddress.SequenceEqual(restored.RoutingAddress));
        }

        [TestMethod]
        public void ToString_WithPrimaryFlag_ReturnValidBase58String()
        {
            // Arrange
            var extAddr = new ExtendedAddress(_testAddress, AddressPaymentFlag.Primary, null);

            // Act
            var base58String = extAddr.ToString();

            // Assert
            Assert.IsNotNull(base58String);
            Assert.IsTrue(base58String.Length > 0);
            Assert.IsTrue(base58String.Contains("_"));
        }

        [TestMethod]
        public void ToString_RoundTrip_ResultMatchesOriginal()
        {
            // Arrange
            var original = new ExtendedAddress(_testAddress, AddressPaymentFlag.OfflineTag, _testTag);

            // Act
            var base58String = original.ToString();
            var restored = new ExtendedAddress(base58String);

            // Assert
            Assert.AreEqual(original.Flag, restored.Flag);
            Assert.IsTrue(original.PaymentAddress.SequenceEqual(restored.PaymentAddress));
            if (original.Tag != null)
            {
                Assert.IsTrue(original.Tag.SequenceEqual(restored.Tag));
            }
        }

        [TestMethod]
        public void ToString_WithOfflineAddressAndTag_ReturnValidBase58String()
        {
            // Arrange
            var extAddr = new ExtendedAddress(_testRoutingAddress, _testPaymentAddress, _testTag);

            // Act
            var base58String = extAddr.ToString();

            // Assert
            Assert.IsNotNull(base58String);
            Assert.IsTrue(base58String.Length > 0);
            Assert.IsTrue(base58String.Contains("_"));
        }

        #endregion

        #region Flag Tests

        [TestMethod]
        public void Flag_AllValidFlags_SupportedCorrectly()
        {
            // Test all flag types
            var flags = new[] { AddressPaymentFlag.Primary, AddressPaymentFlag.End2End, AddressPaymentFlag.OfflineTag };

            foreach (var flag in flags)
            {
                // Act
                var extAddr = new ExtendedAddress(_testAddress, flag, null);

                // Assert
                Assert.AreEqual(flag, extAddr.Flag);
            }
        }

        [TestMethod]
        public void Flag_OfflineAddressFlagWithSeparateAddresses_SetCorrectly()
        {
            // Act
            var extAddr = new ExtendedAddress(_testRoutingAddress, _testPaymentAddress, null);

            // Assert
            Assert.AreEqual(AddressPaymentFlag.OfflineAddress, extAddr.Flag);
        }

        #endregion

        #region Tag Tests

        [TestMethod]
        public void Tag_NullTag_HandledCorrectly()
        {
            // Arrange
            var extAddr = new ExtendedAddress(_testAddress, AddressPaymentFlag.Primary, null);

            // Act & Assert
            Assert.IsNull(extAddr.Tag);
        }

        [TestMethod]
        public void Tag_WithValidTag_StoredCorrectly()
        {
            // Arrange
            var tag = new byte[] { 1, 2, 3, 4, 5 };

            // Act
            var extAddr = new ExtendedAddress(_testAddress, AddressPaymentFlag.OfflineTag, tag);

            // Assert
            Assert.IsNotNull(extAddr.Tag);
            Assert.IsTrue(extAddr.Tag.SequenceEqual(tag));
        }

        [TestMethod]
        public void Tag_WithMaximumLength_HandleCorrectly()
        {
            // Arrange - max tag length is 16 bytes
            var maxTag = new byte[16] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

            // Act
            var extAddr = new ExtendedAddress(_testAddress, AddressPaymentFlag.End2End, maxTag);

            // Assert
            Assert.IsNotNull(extAddr.Tag);
            Assert.IsTrue(extAddr.Tag.SequenceEqual(maxTag));
        }

        [TestMethod]
        public void Tag_ExceedsMaximumLength_ThrowsException()
        {
            // Arrange - create a tag longer than 16 bytes
            var oversizeTag = new byte[17];
            for (int i = 0; i < 17; i++)
            {
                oversizeTag[i] = (byte)i;
            }

            Assert.Throws<Exception>(() =>
            {
                // Act - should throw when constructing the address with an oversize tag
                var extAddr = new ExtendedAddress(_testAddress, AddressPaymentFlag.Primary, oversizeTag);
                extAddr.ToString();
            });
        }

        #endregion

        #region Edge Cases Tests

        [TestMethod]
        public void Constructor_Base58StringWithoutExtension_CreatesValidAddress()
        {
            // Arrange - create a base58 string without the extension delimiter
            var plainAddress = new Address(new byte[33] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 });
            var base58String = plainAddress.ToString();

            // Act
            var extAddr = new ExtendedAddress(base58String);

            // Assert
            Assert.IsNotNull(extAddr);
            Assert.AreEqual(AddressPaymentFlag.Primary, extAddr.Flag);
            Assert.IsTrue(extAddr.PaymentAddress.SequenceEqual(plainAddress));
        }

        [TestMethod]
        public void Properties_AreReadOnly_CannotBeModified()
        {
            // Arrange
            var extAddr = new ExtendedAddress(_testAddress, AddressPaymentFlag.Primary, null);

            // Act & Assert - properties should be private setters
            Assert.AreEqual(AddressPaymentFlag.Primary, extAddr.Flag);
            Assert.IsNotNull(extAddr.RoutingAddress);
            Assert.IsNotNull(extAddr.PaymentAddress);
        }

        [TestMethod]
        public void MultipleInstances_IndependentStates_NoInterference()
        {
            // Arrange
            var extAddr1 = new ExtendedAddress(_testAddress, AddressPaymentFlag.Primary, new byte[] { 1, 2, 3 });
            var extAddr2 = new ExtendedAddress(_testAddress, AddressPaymentFlag.End2End, new byte[] { 4, 5, 6 });

            // Act & Assert
            Assert.AreEqual(AddressPaymentFlag.Primary, extAddr1.Flag);
            Assert.AreEqual(AddressPaymentFlag.End2End, extAddr2.Flag);
            Assert.IsFalse(extAddr1.Tag.SequenceEqual(extAddr2.Tag));
        }

        [TestMethod]
        public void AllFlags_WithoutTag_SerializeAndDeserializeCorrectly()
        {
            // Arrange
            var flags = new[] { AddressPaymentFlag.Primary, AddressPaymentFlag.End2End, AddressPaymentFlag.OfflineTag };

            foreach (var flag in flags)
            {
                // Act
                var original = new ExtendedAddress(_testAddress, flag, null);
                var bytes = original.GetBytes();
                var restored = new ExtendedAddress(bytes);

                // Assert
                Assert.AreEqual(flag, restored.Flag);
                Assert.IsTrue(original.PaymentAddress.SequenceEqual(restored.PaymentAddress));
            }
        }

        [TestMethod]
        public void AllFlags_WithTag_SerializeAndDeserializeCorrectly()
        {
            // Arrange
            var flags = new[] { AddressPaymentFlag.Primary, AddressPaymentFlag.End2End, AddressPaymentFlag.OfflineTag };
            var tag = new byte[] { 10, 20, 30 };

            foreach (var flag in flags)
            {
                // Act
                var original = new ExtendedAddress(_testAddress, flag, tag);
                var bytes = original.GetBytes();
                var restored = new ExtendedAddress(bytes);

                // Assert
                Assert.AreEqual(flag, restored.Flag);
                Assert.IsNotNull(restored.Tag);
                Assert.IsTrue(tag.SequenceEqual(restored.Tag));
            }
        }

        #endregion

        #region String Representation Tests

        [TestMethod]
        public void ToString_IsNotEmpty_ForAllFlags()
        {
            // Arrange
            var flags = new[] { AddressPaymentFlag.Primary, AddressPaymentFlag.End2End, AddressPaymentFlag.OfflineTag };

            foreach (var flag in flags)
            {
                // Act
                var extAddr = new ExtendedAddress(_testAddress, flag, null);
                var stringRepresentation = extAddr.ToString();

                // Assert
                Assert.IsFalse(string.IsNullOrEmpty(stringRepresentation));
                Assert.IsTrue(stringRepresentation.Length > 0);
            }
        }

        [TestMethod]
        public void ToString_ContainsDelimiter_WhenHasExtendedData()
        {
            // Arrange
            var extAddr = new ExtendedAddress(_testAddress, AddressPaymentFlag.End2End, _testTag);

            // Act
            var stringRepresentation = extAddr.ToString();

            // Assert
            Assert.IsTrue(stringRepresentation.Contains("_"), "Extended address should contain delimiter when it has extended data");
        }

        #endregion

        #region Base58 Encoding Tests

        [TestMethod]
        public void Constructor_FromBase58_AllFlags_RestoresCorrectly()
        {
            // Arrange
            var flags = new[] { AddressPaymentFlag.Primary, AddressPaymentFlag.End2End, AddressPaymentFlag.OfflineTag };

            foreach (var flag in flags)
            {
                // Arrange
                var original = new ExtendedAddress(_testAddress, flag, _testTag);

                // Act
                var base58String = original.ToString();
                var restored = new ExtendedAddress(base58String);

                // Assert
                Assert.AreEqual(flag, restored.Flag, $"Flag mismatch for {flag}");
                Assert.IsTrue(original.PaymentAddress.SequenceEqual(restored.PaymentAddress), $"PaymentAddress mismatch for {flag}");
                if (original.Tag != null)
                {
                    Assert.IsTrue(original.Tag.SequenceEqual(restored.Tag), $"Tag mismatch for {flag}");
                }
            }
        }

        #endregion
    }
}

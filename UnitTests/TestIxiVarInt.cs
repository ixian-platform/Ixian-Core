using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Security.Cryptography;
using IXICore;
using IXICore.Utils;

namespace UnitTests
{
    [TestClass]
    public class TestIxiVarInt
    {
        private static void RoundTripSigned(long value)
        {
            byte[] bytes = value.GetIxiVarIntBytes();

            var (decoded, consumed) = bytes.GetIxiVarInt(0);
            Assert.AreEqual(value, decoded, $"Array decode failed for {value}");
            Assert.AreEqual(bytes.Length, consumed);

            using var ms = new MemoryStream(bytes);
            using var br = new BinaryReader(ms);
            long brVal = br.ReadIxiVarInt();
            Assert.AreEqual(value, brVal, $"BinaryReader decode failed for {value}");
        }

        private static void RoundTripUnsigned(ulong value)
        {
            byte[] bytes = value.GetIxiVarIntBytes();

            var (decoded, consumed) = bytes.GetIxiVarUInt(0);
            Assert.AreEqual(value, decoded, $"Array decode failed for {value}");
            Assert.AreEqual(bytes.Length, consumed);

            using var ms = new MemoryStream(bytes);
            using var br = new BinaryReader(ms);
            ulong brVal = br.ReadIxiVarUInt();
            Assert.AreEqual(value, brVal, $"BinaryReader decode failed for {value}");
        }

        [TestMethod]
        public void UnsignedValues()
        {
            // Small values
            for (ulong i = 0; i < 0xf8; i++) RoundTripUnsigned(i);

            // Boundary values
            ulong[] boundaries = { 0xf7, 0xf8, 0xffff, 0x10000, 0xffffffff, 0x100000000, ulong.MaxValue };
            foreach (var val in boundaries) RoundTripUnsigned(val);
        }

        [TestMethod]
        public void SignedValues()
        {
            long[] values = { 0, 1, 127, -1, -128, -255, 0xf7, 0xf8, 0xffff, -0xffff, 0x10000, -0x10000, 0xffffffff, -0xffffffff, long.MaxValue, long.MinValue };
            foreach (var val in values) RoundTripSigned(val);
        }

        [TestMethod]
        public void BinaryWriterReader()
        {
            using var ms = new MemoryStream();
            using (var bw = new BinaryWriter(ms, System.Text.Encoding.UTF8, true))
            {
                bw.WriteIxiVarInt(-12345);
                bw.WriteIxiVarInt((ulong)9876543210);
            }

            ms.Position = 0;
            using var br = new BinaryReader(ms);
            Assert.AreEqual(-12345, br.ReadIxiVarInt());
            Assert.AreEqual((ulong)9876543210, br.ReadIxiVarUInt());
        }

        [TestMethod]
        public void UnsignedRejectsSignedEncoding()
        {
            byte[] encoded = (-300).GetIxiVarIntBytes();
            Assert.Throws<InvalidDataException>(() =>
            {
                encoded.GetIxiVarUInt(0);
            });
        }

        [TestMethod]
        public void InvalidOffset()
        {
            byte[] encoded = (123).GetIxiVarIntBytes();
            Assert.Throws<IndexOutOfRangeException>(() =>
            {
                encoded.GetIxiVarInt(encoded.Length);
            });
        }

        [TestMethod]
        public void NullArrayThrows()
        {
            Assert.Throws<NullReferenceException>(() =>
            {
                IxiVarInt.GetIxiVarInt(null, 0);
            });
        }

        [TestMethod]
        public void NegativeOffsetThrows()
        {
            byte[] data = (123).GetIxiVarIntBytes();
            Assert.Throws<ArgumentOutOfRangeException>(() =>
            {
                data.GetIxiVarInt(-1);
            });
        }

        [TestMethod]
        public void EmptyStream()
        {
            using var ms = new MemoryStream();
            using var br = new BinaryReader(ms);
            Assert.Throws<EndOfStreamException>(() => br.ReadIxiVarInt());
            Assert.Throws<EndOfStreamException>(() => br.ReadIxiVarUInt());
        }

        [TestMethod]
        public void GetBytesBEAndToUlongAbs()
        {
            ulong v = 0x1122334455667788UL;
            byte[] be = v.GetBytesBE();
            Assert.AreEqual(0x11, be[0]);
            Assert.AreEqual(0x88, be[7]);

            int vi = 0x11223344;
            byte[] bei = vi.GetBytesBE();
            Assert.AreEqual(0x11, bei[0]);
            Assert.AreEqual(0x44, bei[3]);

            Assert.AreEqual(123UL, (123L).ToUlongAbs());
            Assert.AreEqual(123UL, (-123L).ToUlongAbs());
            Assert.AreEqual((ulong)long.MaxValue + 1, long.MinValue.ToUlongAbs());
        }

        [TestMethod]
        public void MaximumLengths()
        {
            ulong maxULong = ulong.MaxValue;
            byte[] maxBytes = maxULong.GetIxiVarIntBytes();
            Assert.AreEqual(9, maxBytes.Length);
            RoundTripUnsigned(maxULong);

            long minLong = long.MinValue;
            byte[] minBytes = minLong.GetIxiVarIntBytes();
            Assert.AreEqual(9, minBytes.Length);
            RoundTripSigned(minLong);
        }

        [TestMethod]
        public void MultipleVarIntsInStream()
        {
            long[] signedValues = { -1, 0, 1, 12345, long.MinValue, long.MaxValue };
            ulong[] unsignedValues = { 0, 1, 12345, 0xf8, 0xffffffff, ulong.MaxValue };

            using var ms = new MemoryStream();
            using (var bw = new BinaryWriter(ms, System.Text.Encoding.UTF8, true))
            {
                foreach (var s in signedValues) bw.WriteIxiVarInt(s);
                foreach (var u in unsignedValues) bw.WriteIxiVarInt(u);
            }

            ms.Position = 0;
            using var br = new BinaryReader(ms);
            foreach (var s in signedValues) Assert.AreEqual(s, br.ReadIxiVarInt());
            foreach (var u in unsignedValues) Assert.AreEqual(u, br.ReadIxiVarUInt());
        }

        [TestMethod]
        public void FuzzRoundTrip()
        {
            const int iterations = 10000;
            RandomNumberGenerator rng = RandomNumberGenerator.Create();
            Span<byte> buffer = stackalloc byte[8];

            for (int i = 0; i < iterations; i++)
            {
                rng.GetBytes(buffer);
                RoundTripSigned(BitConverter.ToInt64(buffer));

                rng.GetBytes(buffer);
                RoundTripUnsigned(BitConverter.ToUInt64(buffer));
            }
        }

        [TestMethod]
        public void FuzzIxiNumberRoundTrip_BigInteger()
        {
            const int iterations = 5000;
            RandomNumberGenerator rng = RandomNumberGenerator.Create();

            for (int i = 0; i < iterations; i++)
            {
                int len = RandomNumberGenerator.GetInt32(1, 129);
                byte[] randomBytes = new byte[len];
                rng.GetBytes(randomBytes);

                var number = new IxiNumber(randomBytes);

                using var ms = new MemoryStream();
                using (var bw = new BinaryWriter(ms, System.Text.Encoding.UTF8, true))
                {
                    bw.WriteIxiNumber(number);
                }

                ms.Position = 0;
                using var br = new BinaryReader(ms);
                IxiNumber decoded = br.ReadIxiNumber();
                Assert.AreEqual(number.amount, decoded.amount, $"Mismatch in iteration {i}");
            }
        }

        [TestMethod]
        public void IxiNumberEncoding()
        {
            byte[] payload = { 1, 2, 3, 4, 5 };
            var number = new IxiNumber(payload);

            using var ms = new MemoryStream();
            using (var bw = new BinaryWriter(ms, System.Text.Encoding.UTF8, true))
            {
                bw.WriteIxiNumber(number);
            }

            ms.Position = 0;
            using var br = new BinaryReader(ms);
            IxiNumber decoded = br.ReadIxiNumber();
            CollectionAssert.AreEqual(payload, decoded.getBytes());
        }
    }
}

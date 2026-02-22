using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Numerics;
using IXICore;
using System.Globalization;

namespace UnitTests
{
    [TestClass]
    public class TestIxiNumber
    {
        Random rng = new Random();

        private string RoundTo8Decimals(decimal d)
        {
            return decimal.Round(d, 8, MidpointRounding.ToZero).ToString("0.00000000", CultureInfo.InvariantCulture);
        }

        [TestMethod]
        public void ConstructorFromString()
        {
            var num = new IxiNumber("123.45678901");
            Assert.AreEqual("123.45678901", num.ToString());

            var num2 = new IxiNumber("2.0");
            Assert.AreEqual("2.00000000", num2.ToString());

            var num3 = new IxiNumber("0.5");
            Assert.AreEqual("0.50000000", num3.ToString());
        }

        [TestMethod]
        public void ConstructorFromIntegers()
        {
            var num1 = new IxiNumber(2);
            Assert.AreEqual("2.00000000", num1.ToString());

            var num2 = new IxiNumber(2L);
            Assert.AreEqual("2.00000000", num2.ToString());

            var num3 = new IxiNumber(2UL);
            Assert.AreEqual("2.00000000", num3.ToString());
        }

        [TestMethod]
        public void RawString()
        {
            var num = new IxiNumber("1.23456789");
            string raw = num.ToRawString();
            Assert.AreEqual("123456789", raw);
        }

        [TestMethod]
        public void Addition()
        {
            var a = new IxiNumber("1.5");
            var b = new IxiNumber("2.25");
            var result = a + b;

            Assert.AreEqual("3.75000000", result.ToString());
        }

        [TestMethod]
        public void Subtraction()
        {
            var a = new IxiNumber("5");
            var b = new IxiNumber("2.5");
            var result = a - b;

            Assert.AreEqual("2.50000000", result.ToString());
        }

        [TestMethod]
        public void Multiplication()
        {
            var a = new IxiNumber("2");
            var b = new IxiNumber("3");
            var result = a * b;

            Assert.AreEqual("6.00000000", result.ToString());
        }

        [TestMethod]
        public void Division()
        {
            var a = new IxiNumber("6");
            var b = new IxiNumber("2");
            var result = a / b;

            Assert.AreEqual("3.00000000", result.ToString());
        }

        [TestMethod]
        public void DivisionByZero()
        {
            var a = new IxiNumber("1");
            var b = new IxiNumber("0");
            Assert.Throws<DivideByZeroException>(() =>
            {
                var result = a / b;
            });
        }

        [TestMethod]
        public void NegativeNumbers()
        {
            var a = new IxiNumber("-2.5");
            var b = new IxiNumber("1.5");

            Assert.AreEqual("-1.00000000", (a + b).ToString());
            Assert.AreEqual("-4.00000000", (a - b).ToString());
            Assert.AreEqual("-3.75000000", (a * b).ToString());
            Assert.AreEqual("-1.66666666", (a / b).ToString());
        }

        [TestMethod]
        public void Comparisons()
        {
            var a = new IxiNumber("2");
            var b = new IxiNumber("3");
            var c = new IxiNumber("2");

            Assert.IsTrue(a < b);
            Assert.IsTrue(b > a);
            Assert.IsTrue(a <= c);
            Assert.IsTrue(a >= c);
            Assert.IsTrue(a == c);
            Assert.IsTrue(a != b);
        }

        [TestMethod]
        public void DivRem()
        {
            var a = new IxiNumber("7");
            var b = new IxiNumber("3");

            IxiNumber remainder;
            var quotient = IxiNumber.divRem(a, b, out remainder);

            Assert.AreEqual("2.33333333", quotient.ToString());
            Assert.AreEqual("0.00000001", remainder.ToString());
        }

        [TestMethod]
        public void FuzzedDivRem()
        {
            for (int i = 0; i < 100; i++)
            {
                // Random decimals between -1000 and 1000
                decimal d1 = (decimal)(rng.NextDouble() * 2000 - 1000);
                decimal d2 = (decimal)(rng.NextDouble() * 2000 - 1000);

                // Avoid zero divisor
                if (Math.Abs(d2) < 0.00000001m)
                    d2 = 1.23456789m;

                // Round to 8 decimals
                d1 = Math.Round(d1, 8, MidpointRounding.ToZero);
                d2 = Math.Round(d2, 8, MidpointRounding.ToZero);

                var n1 = new IxiNumber(d1.ToString("0.00000000", CultureInfo.InvariantCulture));
                var n2 = new IxiNumber(d2.ToString("0.00000000", CultureInfo.InvariantCulture));

                // Perform divRem
                IxiNumber remainder;
                var quotient = IxiNumber.divRem(n1, n2, out remainder);

                // Reconstruct: quotient * n2 + remainder
                var reconstructed = quotient * n2 + remainder;

                // Compare with original, rounded to 8 decimals
                string originalStr = RoundTo8Decimals(d1);
                string reconstructedStr = reconstructed.ToString();

                Assert.AreEqual(originalStr, reconstructedStr,
                    $"Failed on iteration {i}: {n1} / {n2} -> quotient {quotient}, remainder {remainder}");
            }
        }


        [TestMethod]
        public void LargeValues()
        {
            var big = BigInteger.Pow(10, 30); // very large integer
            var num = new IxiNumber(big);

            Assert.AreEqual(big.ToString(), num.ToRawString());

            var doubled = num + num;
            Assert.AreEqual((big * 2).ToString(), doubled.ToRawString());
        }

        [TestMethod]
        public void PrecisionLossInDivision()
        {
            var one = new IxiNumber("1");
            var three = new IxiNumber("3");

            var result = one / three;
            // Expected: truncated after 8 decimals
            Assert.AreEqual("0.33333333", result.ToString());
        }

        [TestMethod]
        public void EqualityAndHashCode()
        {
            var a = new IxiNumber("5.0");
            var b = new IxiNumber("5.00000000");
            var c = new IxiNumber("6.0");

            Assert.IsTrue(a.Equals(b));
            Assert.IsTrue(a == b);
            Assert.IsFalse(a.Equals(c));

            Assert.AreEqual(a.GetHashCode(), b.GetHashCode());
        }

        [TestMethod]
        public void OriginalScenarios()
        {
            IxiNumber num1 = new IxiNumber("2.00000000");
            IxiNumber num2 = new IxiNumber("2.0");

            Assert.AreEqual("2.00000000", num1.ToString());
            Assert.AreEqual("2.00000000", num2.ToString());
            Assert.AreEqual("1.00000000", (num1 / num2).ToString());
            Assert.AreEqual("4.00000000", (num1 * num2).ToString());

            num1 = new IxiNumber("0.5");
            num2 = new IxiNumber("2");
            Assert.AreEqual("0.25000000", (num1 / num2).ToString());
            Assert.AreEqual("1.00000000", (num1 * num2).ToString());

            num1 = new IxiNumber("1.23456789");
            num2 = new IxiNumber("2.34567890");
            Assert.AreEqual("0.52631580", (num1 / num2).ToString());
            Assert.AreEqual("2.89589985", (num1 * num2).ToString());
        }

        [TestMethod]
        public void FuzzedArithmetic()
        {
            for (int i = 0; i < 100; i++)
            {
                decimal d1 = (decimal)(rng.NextDouble() * 1000 - 500);
                decimal d2 = (decimal)(rng.NextDouble() * 1000 - 500);

                d1 = Math.Round(d1, 8, MidpointRounding.AwayFromZero);
                d2 = Math.Round(d2, 8, MidpointRounding.AwayFromZero);

                // Avoid division by zero
                if (Math.Abs(d2) < 0.00000001m)
                    d2 = 1.23456789m;

                var n1 = new IxiNumber(d1.ToString("0.00000000", CultureInfo.InvariantCulture));
                var n2 = new IxiNumber(d2.ToString("0.00000000", CultureInfo.InvariantCulture));

                // Addition
                string expectedAdd = RoundTo8Decimals(d1 + d2);
                Assert.AreEqual(expectedAdd, (n1 + n2).ToString());

                // Subtraction
                string expectedSub = RoundTo8Decimals(d1 - d2);
                Assert.AreEqual(expectedSub, (n1 - n2).ToString());

                // Multiplication
                string expectedMul = RoundTo8Decimals(d1 * d2);
                Assert.AreEqual(expectedMul, (n1 * n2).ToString());

                // Division
                string expectedDiv = RoundTo8Decimals(d1 / d2);
                Assert.AreEqual(expectedDiv, (n1 / n2).ToString());
            }
        }


        [TestMethod]
        public void ZeroLengthIxiNumber()
        {
            Assert.Throws<ArgumentException>(() =>
            {
                new IxiNumber(Array.Empty<byte>());
            });
        }

        [TestMethod]
        public void FuzzedEdgeCases_BigInteger()
        {
            BigInteger divisor = BigInteger.Pow(10, 8);

            for (int i = 0; i < 100; i++)
            {
                // Random numbers in a moderate-to-large range
                decimal d1 = (decimal)(rng.NextDouble() * 1_000_000_000 - 500_000_000);
                decimal d2 = (decimal)(rng.NextDouble() * 1_000_000_000 - 500_000_000);

                // Avoid tiny divisor
                if (Math.Abs(d2) < 0.00000001m)
                    d2 = 1.23456789m;

                // Round to 8 decimals
                d1 = Math.Round(d1, 8, MidpointRounding.ToZero);
                d2 = Math.Round(d2, 8, MidpointRounding.ToZero);

                var n1 = new IxiNumber(d1.ToString("0.00000000", CultureInfo.InvariantCulture));
                var n2 = new IxiNumber(d2.ToString("0.00000000", CultureInfo.InvariantCulture));

                // Compute expected results using BigInteger arithmetic
                BigInteger bi1 = n1.getAmount();
                BigInteger bi2 = n2.getAmount();

                // Addition/Subtraction
                string expectedAdd = new IxiNumber(bi1 + bi2).ToString();
                string expectedSub = new IxiNumber(bi1 - bi2).ToString();

                // Multiplication
                string expectedMul = new IxiNumber((bi1 * bi2) / divisor).ToString();

                // Division
                string expectedDiv = new IxiNumber((bi1 * divisor) / bi2).ToString();

                // Assertions
                Assert.AreEqual(expectedAdd, (n1 + n2).ToString());
                Assert.AreEqual(expectedSub, (n1 - n2).ToString());
                Assert.AreEqual(expectedMul, (n1 * n2).ToString());
                Assert.AreEqual(expectedDiv, (n1 / n2).ToString());

                // DivRem
                IxiNumber remainder;
                var quotient = IxiNumber.divRem(n1, n2, out remainder);
                var reconstructed = quotient * n2 + remainder;
                Assert.AreEqual(n1.ToString(), reconstructed.ToString(),
                    $"Failed on iteration {i}: {n1} / {n2} -> quotient {quotient}, remainder {remainder}");
            }
        }

        [TestMethod]
        public void ConstructorFromInvalidString_Empty()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                new IxiNumber("");
            });
        }

        [TestMethod]
        public void ConstructorFromInvalidString_Whitespace()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                new IxiNumber("    ");
            });
        }

        [TestMethod]
        public void ConstructorFromByteArray_Empty()
        {
            Assert.Throws<ArgumentException>(() =>
            {
                new IxiNumber(Array.Empty<byte>());
            });
        }

        [TestMethod]
        public void ByteArrayRoundTrip()
        {
            var original = new IxiNumber("12345.67890123");
            var bytes = original.getBytes();
            var reconstructed = new IxiNumber(bytes);
            Assert.AreEqual(original.ToRawString(), reconstructed.ToRawString());
        }

        [TestMethod]
        public void DivisionBySmallNumbers()
        {
            var n1 = new IxiNumber("1");
            var n2 = new IxiNumber("0.00000001"); // smallest possible IXI unit
            var result = n1 / n2;
            Assert.IsTrue(result > new IxiNumber("99999999.0"));
        }

        [TestMethod]
        public void FuzzedNegativeNumbers()
        {
            for (int i = 0; i < 20; i++)
            {
                // Random numbers between -1000 and 1000
                decimal d1 = (decimal)(rng.NextDouble() * 2000 - 1000);
                decimal d2 = (decimal)(rng.NextDouble() * 2000 - 1000);

                // Avoid tiny divisor
                if (Math.Abs(d2) < 0.00000001m) d2 = -1.23456789m;

                // Round to 8 decimals
                d1 = Math.Round(d1, 8, MidpointRounding.ToZero);
                d2 = Math.Round(d2, 8, MidpointRounding.ToZero);

                var n1 = new IxiNumber(d1.ToString("0.00000000", CultureInfo.InvariantCulture));
                var n2 = new IxiNumber(d2.ToString("0.00000000", CultureInfo.InvariantCulture));

                // Arithmetic checks
                Assert.AreEqual(RoundTo8Decimals(d1 + d2), (n1 + n2).ToString());
                Assert.AreEqual(RoundTo8Decimals(d1 - d2), (n1 - n2).ToString());
                Assert.AreEqual(RoundTo8Decimals(d1 * d2), (n1 * n2).ToString());
                Assert.AreEqual(RoundTo8Decimals(d1 / d2), (n1 / n2).ToString());

                // DivRem checks
                IxiNumber remainder;
                var quotient = IxiNumber.divRem(n1, n2, out remainder);
                var reconstructed = quotient * n2 + remainder;
                Assert.AreEqual(n1.ToString(), reconstructed.ToString(),
    $"Failed on iteration {i}: {n1} / {n2} -> quotient {quotient}, remainder {remainder}");
            }
        }

    }
}

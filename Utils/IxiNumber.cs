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

using System;
using System.Numerics;

namespace IXICore
{
    // An object representing an amount of IXI coins, complete with decimal support. Can handle very large amounts.
    public class IxiNumber : IComparable<IxiNumber>
    {
        // A divisor corresponding to 8 decimals as per WhitePaper
        private static BigInteger divisor = 100000000;
        private static int num_decimals = 8;

        // Set the initial value to 0
        public BigInteger amount { get; private set; } = BigInteger.Zero;

        public IxiNumber()
        {
            amount = BigInteger.Zero;
        }

        public IxiNumber(IxiNumber src)
        {
            amount = new BigInteger(src.amount.ToByteArray());
        }

        public IxiNumber(BigInteger big_integer)
        {
            amount = big_integer;
        }

        public IxiNumber(byte[] bytes)
        {
            if (bytes.Length == 0)
            {
                throw new ArgumentException("Byte array cannot be empty.");
            }
            amount = new BigInteger(bytes);
        }

        public IxiNumber(ulong number)
        {
            amount = BigInteger.Multiply(number, divisor);
        }

        public IxiNumber(long number)
        {
            amount = BigInteger.Multiply(number, divisor);
        }

        public IxiNumber(int number)
        {
            amount = BigInteger.Multiply(number, divisor);
        }

        public IxiNumber(string str)
        {
            if (string.IsNullOrWhiteSpace(str))
                throw new ArgumentNullException(nameof(str));

            str = str.Trim();

            bool isNegative = str.StartsWith("-");
            if (isNegative)
                str = str.Substring(1);

            string[] parts = str.Split('.');
            string intPart = parts[0];
            string fracPart = (parts.Length > 1 ? parts[1] : "");

            // Pad/truncate fractional part to 8 decimals
            if (fracPart.Length > 8)
                fracPart = fracPart.Substring(0, 8);
            else if (fracPart.Length < 8)
                fracPart = fracPart.PadRight(8, '0');

            string raw = intPart + fracPart;
            if (string.IsNullOrEmpty(raw))
                raw = "0";

            amount = BigInteger.Parse(raw);
            if (isNegative)
                amount = -amount;
        }

        // Returns a string containing the raw amount
        public string ToRawString()
        {
            return amount.ToString("D");
        }

        // Returns a formatted string containing decimals
        public override string ToString()
        {
            try
            {
                BigInteger p2;
                BigInteger p1 = BigInteger.DivRem(amount, divisor, out p2);

                bool isNegative = amount < 0;
                if (isNegative)
                {
                    p1 = BigInteger.Abs(p1);
                    p2 = BigInteger.Abs(p2);
                }

                string secondPart = p2.ToString().PadLeft(num_decimals, '0');

                string result = $"{p1}.{secondPart}";
                return isNegative ? "-" + result : result;
            }
            catch
            {
                return "ERR";
            }
        }

        public override int GetHashCode()
        {
            return amount.GetHashCode();
        }

        public override bool Equals(object obj)
        {
            if (obj is IxiNumber)
            {
                return this == (IxiNumber)obj;
            }
            if (obj is long)
            {
                return this == (long)obj;
            }
            return false;
        }

        public BigInteger getAmount()
        {
            return amount;
        }

        public byte[] getBytes()
        {
            return amount.ToByteArray();
        }

        public void add(IxiNumber num)
        {
            amount = BigInteger.Add(amount, num.getAmount());
        }

        public void subtract(IxiNumber num)
        {
            amount = BigInteger.Subtract(amount, num.getAmount());
        }


        public void multiply(IxiNumber num)
        {
            amount = BigInteger.Divide(BigInteger.Multiply(amount, num.getAmount()), divisor);
        }

        public void divide(IxiNumber num)
        {
            amount = BigInteger.Divide(BigInteger.Multiply(amount, divisor), num.getAmount());
        }


        public static IxiNumber add(IxiNumber num1, IxiNumber num2)
        {
            return new IxiNumber(BigInteger.Add(num1.getAmount(), num2.getAmount()));
        }

        public static IxiNumber subtract(IxiNumber num1, IxiNumber num2)
        {
            return new IxiNumber(BigInteger.Subtract(num1.getAmount(), num2.getAmount()));
        }

        public static IxiNumber multiply(IxiNumber num1, IxiNumber num2)
        {
            return new IxiNumber(BigInteger.Divide(BigInteger.Multiply(num1.getAmount(), num2.getAmount()), divisor));
        }

        public static IxiNumber divide(IxiNumber num1, IxiNumber num2)
        {
            return new IxiNumber(BigInteger.Divide(BigInteger.Multiply(num1.getAmount(), divisor), num2.getAmount()));
        }

        public static IxiNumber divRem(IxiNumber num1, IxiNumber num2, out IxiNumber remainder)
        {
            BigInteger bi_remainder = 0;
            BigInteger bi_quotient = BigInteger.DivRem(BigInteger.Multiply(num1.getAmount(), divisor), num2.getAmount(), out bi_remainder);

            remainder = new IxiNumber(BigInteger.Divide(bi_remainder, divisor));

            return new IxiNumber(bi_quotient);
        }


        // TODO: equals, assign, +, -

        public static implicit operator IxiNumber(string value)
        {
            return new IxiNumber(value);
        }

        public static implicit operator IxiNumber(ulong value)
        {
            return new IxiNumber(value);
        }

        public static implicit operator IxiNumber(long value)
        {
            return new IxiNumber(value);
        }

        public static implicit operator IxiNumber(int value)
        {
            return new IxiNumber(value);
        }

        public static bool operator ==(IxiNumber a, IxiNumber b)
        {
            if (a is null && b is null)
            {
                return true;
            }

            if (a is null || b is null)
            {
                return false;
            }

            bool status = false;
            if (BigInteger.Compare(a.getAmount(), b.getAmount()) == 0)
            {
                status = true;
            }
            return status;
        }

        public static bool operator !=(IxiNumber a, IxiNumber b)
        {
            return !(a == b);
        }
        public static bool operator >(IxiNumber a, IxiNumber b)
        {
            bool status = false;
            if (BigInteger.Compare(a.getAmount(), b.getAmount()) > 0)
            {
                status = true;
            }
            return status;
        }

        public static bool operator >=(IxiNumber a, IxiNumber b)
        {
            bool status = false;
            if (BigInteger.Compare(a.getAmount(), b.getAmount()) >= 0)
            {
                status = true;
            }
            return status;
        }

        public static bool operator <(IxiNumber a, IxiNumber b)
        {
            bool status = false;
            if (BigInteger.Compare(a.getAmount(), b.getAmount()) < 0)
            {
                status = true;
            }
            return status;
        }

        public static bool operator <=(IxiNumber a, IxiNumber b)
        {
            bool status = false;
            if (BigInteger.Compare(a.getAmount(), b.getAmount()) <= 0)
            {
                status = true;
            }
            return status;
        }

        public static IxiNumber operator +(IxiNumber a, IxiNumber b)
        {
            return add(a, b);
        }

        public static IxiNumber operator -(IxiNumber a, IxiNumber b)
        {
            return subtract(a, b);
        }


        public static IxiNumber operator *(IxiNumber a, IxiNumber b)
        {
            return multiply(a, b);
        }

        public static IxiNumber operator /(IxiNumber a, IxiNumber b)
        {
            return divide(a, b);
        }

        public int CompareTo(IxiNumber other)
        {
            return getAmount().CompareTo(other.getAmount());
        }
    }
}

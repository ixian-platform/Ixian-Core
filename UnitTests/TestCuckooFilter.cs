using System;
using System.Collections.Generic;
using IXICore.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Diagnostics;

namespace UnitTests
{
    [TestClass]
    public class TestCuckooFilter
    {
        private Random RNG;


        private Cuckoo generateLargeCuckoo(int min_items, int max_items, ref SortedSet<byte[]> items)
        {
            int cap = RNG.Next(min_items, max_items);
            items = new SortedSet<byte[]>(new ByteArrayComparer());
            Cuckoo cuckoo = new Cuckoo(cap);
            while (true)
            {
                byte[] item = new byte[32];
                RNG.NextBytes(item);
                if (items.Contains(item)) continue;
                if (cuckoo.Add(item) == Cuckoo.CuckooStatus.NotEnoughSpace)
                {
                    cuckoo.Add(item);
                    Assert.IsTrue(cuckoo.numItems >= cap, "Cuckoo should accept at least its constructed capacity.");
                    break;
                }
                items.Add(item);
            }
            return cuckoo;
        }

        [TestInitialize]
        public void testInitialize()
        {
            RNG = new Random();
        }

        [TestMethod]
        public void trivialSanityTest()
        {
            Cuckoo cuckoo = new Cuckoo(100);
            byte[] item = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99 };
            Assert.IsFalse(cuckoo.Contains(item));
        }

        [TestMethod]
        public void addItem()
        {
            Cuckoo cuckoo = new Cuckoo(100);
            byte[] item = new byte[32];
            RNG.NextBytes(item);
            cuckoo.Add(item);
            Assert.IsTrue(cuckoo.Contains(item));
        }

        [TestMethod]
        public void fillToCapacity()
        {
            SortedSet<byte[]> items = null;
            Cuckoo cuckoo = generateLargeCuckoo(2000, 4000, ref items);
            foreach (var i in items)
            {
                Assert.IsTrue(cuckoo.Contains(i), "Cuckoo should contain all items which were inserted.");
            }
        }

        [TestMethod]
        public void serializeDeserializeSmall()
        {
            SortedSet<byte[]> items = null;
            Cuckoo cuckoo = generateLargeCuckoo(20, 100, ref items);
            Stopwatch sw = new Stopwatch();
            sw.Start();
            byte[] serialized_cuckoo = cuckoo.getFilterBytes();
            sw.Stop();
            Trace.WriteLine(String.Format("Serializing cuckoo filter with {0} elements took {1} ms and yielded {2} bytes.",
                cuckoo.numItems,
                sw.ElapsedMilliseconds,
                serialized_cuckoo.Length));
            sw.Start();
            Cuckoo cuckoo2 = new Cuckoo(serialized_cuckoo);
            sw.Stop();
            Trace.WriteLine(String.Format("Deserializing cuckoo filter took {0} ms.", sw.ElapsedMilliseconds));

            // make sure all items are in the filter
            foreach (var i in items)
            {
                Assert.IsTrue(cuckoo2.Contains(i));
            }
        }

        [TestMethod]
        public void serializeDeserializeMedium()
        {
            SortedSet<byte[]> items = null;
            Cuckoo cuckoo = generateLargeCuckoo(1000, 1500, ref items);
            Stopwatch sw = new Stopwatch();
            sw.Start();
            byte[] serialized_cuckoo = cuckoo.getFilterBytes();
            sw.Stop();
            Trace.WriteLine(String.Format("Serializing cuckoo filter with {0} elements took {1} ms and yielded {2} bytes.",
                cuckoo.numItems,
                sw.ElapsedMilliseconds,
                serialized_cuckoo.Length));
            sw.Start();
            Cuckoo cuckoo2 = new Cuckoo(serialized_cuckoo);
            sw.Stop();
            Trace.WriteLine(String.Format("Deserializing cuckoo filter took {0} ms.", sw.ElapsedMilliseconds));

            // make sure all items are in the filter
            foreach (var i in items)
            {
                Assert.IsTrue(cuckoo2.Contains(i));
            }
        }


        [TestMethod]
        public void serializeDeserializeLarge()
        {
            SortedSet<byte[]> items = null;
            Cuckoo cuckoo = generateLargeCuckoo(2000, 4000, ref items);
            Stopwatch sw = new Stopwatch();
            sw.Start();
            byte[] serialized_cuckoo = cuckoo.getFilterBytes();
            sw.Stop();
            Trace.WriteLine(String.Format("Serializing cuckoo filter with {0} elements took {1} ms and yielded {2} bytes.", 
                cuckoo.numItems,
                sw.ElapsedMilliseconds,
                serialized_cuckoo.Length));
            sw.Start();
            Cuckoo cuckoo2 = new Cuckoo(serialized_cuckoo);
            sw.Stop();
            Trace.WriteLine(String.Format("Deserializing cuckoo filter took {0} ms.", sw.ElapsedMilliseconds));

            // make sure all items are in the filter
            foreach(var i in items)
            {
                Assert.IsTrue(cuckoo2.Contains(i));
            }
        }
    }
}

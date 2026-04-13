using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using IXICore.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace UnitTests
{
    [TestClass]
    public class LinkedHashSetTests
    {

        [TestMethod]
        public void Add_ShouldReturnTrue_WhenNewItem()
        {
            var set = new LinkedHashSet<int>();

            var result = set.Add(1);

            Assert.IsTrue(result);
            Assert.AreEqual(1, set.Count);
            Assert.IsTrue(set.Contains(1));
        }

        [TestMethod]
        public void Add_ShouldReturnFalse_WhenDuplicate()
        {
            var set = new LinkedHashSet<int>();

            set.Add(1);
            var result = set.Add(1);

            Assert.IsFalse(result);
            Assert.AreEqual(1, set.Count);
        }

        [TestMethod]
        public void Remove_ShouldRemoveExistingItem()
        {
            var set = new LinkedHashSet<int>();

            set.Add(1);
            var removed = set.Remove(1);

            Assert.IsTrue(removed);
            Assert.IsFalse(set.Contains(1));
            Assert.AreEqual(0, set.Count);
        }

        [TestMethod]
        public void Remove_ShouldReturnFalse_WhenItemDoesNotExist()
        {
            var set = new LinkedHashSet<int>();

            var removed = set.Remove(42);

            Assert.IsFalse(removed);
        }

        [TestMethod]
        public void Clear_ShouldRemoveAllItems()
        {
            var set = new LinkedHashSet<int>();

            set.Add(1);
            set.Add(2);

            set.Clear();

            Assert.AreEqual(0, set.Count);
            Assert.IsFalse(set.Contains(1));
            Assert.IsFalse(set.Contains(2));
        }

        [TestMethod]
        public void Enumeration_ShouldPreserveInsertionOrder()
        {
            var set = new LinkedHashSet<int>();

            set.Add(3);
            set.Add(1);
            set.Add(2);

            var result = set.ToList();

            Assert.IsTrue(new[] { 3, 1, 2 }.SequenceEqual(result));
        }

        [TestMethod]
        public void Constructor_ShouldIgnoreDuplicates()
        {
            var input = new[] { 1, 2, 2, 3, 1 };

            var set = new LinkedHashSet<int>(input);

            Assert.AreEqual(3, set.Count);
            Assert.IsTrue(new[] { 1, 2, 3 }.SequenceEqual(set.ToList()));
        }

        [TestMethod]
        public void SortInPlace_ShouldSortAscending()
        {
            var set = new LinkedHashSet<int>();

            set.Add(5);
            set.Add(1);
            set.Add(3);

            set.SortInPlace();

            Assert.IsTrue(new[] { 1, 3, 5 }.SequenceEqual(set.ToList()));
        }

        [TestMethod]
        public void SortInPlace_ShouldRespectCustomComparer()
        {
            var set = new LinkedHashSet<int>();

            set.Add(1);
            set.Add(3);
            set.Add(2);

            set.SortInPlace(Comparer<int>.Create((a, b) => b.CompareTo(a)));

            Assert.IsTrue(new[] { 3, 2, 1 }.SequenceEqual(set.ToList()));
        }
    }

    [TestClass]
    public class ConcurrentLinkedHashSetTests
    {
        [TestMethod]
        public void Add_And_Contains_ShouldWorkCorrectly()
        {
            var set = new ConcurrentLinkedHashSet<int>();

            set.Add(10);

            Assert.IsTrue(set.Contains(10));
            Assert.AreEqual(1, set.Count);
        }

        [TestMethod]
        public void Remove_ShouldWorkCorrectly()
        {
            var set = new ConcurrentLinkedHashSet<int>();

            set.Add(10);
            var removed = set.Remove(10);

            Assert.IsTrue(removed);
            Assert.IsFalse(set.Contains(10));
        }

        [TestMethod]
        public void Clear_ShouldRemoveAllItems()
        {
            var set = new ConcurrentLinkedHashSet<int>();

            set.Add(1);
            set.Add(2);

            set.Clear();

            Assert.AreEqual(0, set.Count);
        }

        [TestMethod]
        public void Enumeration_ShouldReturnSnapshot()
        {
            var set = new ConcurrentLinkedHashSet<int>();

            set.Add(1);
            set.Add(2);
            set.Add(3);

            var snapshot = set.ToList();

            Assert.IsTrue(new[] { 1, 2, 3 }.SequenceEqual(snapshot));
        }

        [TestMethod]
        public void Concurrent_Add_ShouldNotCorruptState()
        {
            var set = new ConcurrentLinkedHashSet<int>();

            Parallel.For(0, 1000, i =>
            {
                set.Add(i);
            });

            Assert.AreEqual(1000, set.Count);
        }

        [TestMethod]
        public void Concurrent_Add_Duplicates_ShouldNotIncreaseCount()
        {
            var set = new ConcurrentLinkedHashSet<int>();

            Parallel.For(0, 500, i =>
            {
                set.Add(1);
            });

            Assert.AreEqual(1, set.Count);
            Assert.IsTrue(set.Contains(1));
        }

        [TestMethod]
        public void SortInPlace_ShouldWorkUnderLock()
        {
            var set = new ConcurrentLinkedHashSet<int>();

            set.Add(3);
            set.Add(1);
            set.Add(2);

            set.SortInPlace();

            Assert.IsTrue(new[] { 1, 2, 3 }.SequenceEqual(set.ToList()));
        }
    }
}
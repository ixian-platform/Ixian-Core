// Copyright (C) 2017-2025 Ixian
// This file is part of Ixian DLT - www.github.com/ixian-platform/Ixian-DLT
//
// Ixian DLT is free software: you can redistribute it and/or modify
// it under the terms of the MIT License as published
// by the Open Source Initiative.
//
// Ixian DLT is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// MIT License for more details.

using IXICore;
using IXICore.Meta;
using IXICore.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;

namespace UnitTests
{
    [TestClass]
    public class TestPrefixIndexedTree
    {
        private void populate(PrefixIndexedTree<int> tree)
        {
            for (byte i = 0; i < 10; i++)
            {
                for (byte j = 0; j < 10; j++)
                {
                    for (byte k = 0; k < 10; k++)
                    {
                        tree.Add([i, j, k, 0, 5, 0], BitConverter.ToInt32([i, j, k, 0, 5, 0]));
                        tree.Add([i, j, k, 128, 5, 1], BitConverter.ToInt32([i, j, k, 128, 5, 1]));
                        tree.Add([i, j, k, 255, 5, 2], BitConverter.ToInt32([i, j, k, 255, 5, 2]));
                    }
                }
            }

            for (byte i = 10; i < 20; i += 2)
            {
                for (byte j = 0; j < 10; j += 2)
                {
                    for (byte k = 0; k < 10; k += 2)
                    {
                        tree.Add([i, j, k, 0, 5, 0], BitConverter.ToInt32([i, j, k, 0, 5, 0]));
                        tree.Add([i, j, k, 128, 5, 1], BitConverter.ToInt32([i, j, k, 128, 5, 1]));
                        tree.Add([i, j, k, 255, 5, 2], BitConverter.ToInt32([i, j, k, 255, 5, 2]));
                    }
                }
            }

            for (byte i = 20; i < 30; i += 3)
            {
                for (byte j = 0; j < 10; j += 3)
                {
                    for (byte k = 0; k < 10; k += 3)
                    {
                        tree.Add([i, j, k, 0, 5, 0], BitConverter.ToInt32([i, j, k, 0, 5, 0]));
                        tree.Add([i, j, k, 128, 5, 1], BitConverter.ToInt32([i, j, k, 128, 5, 1]));
                        tree.Add([i, j, k, 255, 5, 2], BitConverter.ToInt32([i, j, k, 255, 5, 2]));
                    }
                }
            }

            for (byte i = 30; i < 40; i += 4)
            {
                for (byte j = 0; j < 10; j += 4)
                {
                    for (byte k = 0; k < 10; k += 4)
                    {
                        tree.Add([i, j, k, 0, 5, 0], BitConverter.ToInt32([i, j, k, 0, 5, 0]));
                        tree.Add([i, j, k, 128, 5, 1], BitConverter.ToInt32([i, j, k, 128, 5, 1]));
                        tree.Add([i, j, k, 255, 5, 2], BitConverter.ToInt32([i, j, k, 255, 5, 2]));
                    }
                }
            }
        }

        private void verify_1level(PrefixIndexedTree<int> tree, List<byte[]> removedChildren)
        {
            var bac = new ByteArrayComparer();
            for (byte i = 0; i < 10; i++)
            {
                int removed = 0;
                for (byte j = 0; j < 10; j++)
                {
                    for (byte k = 0; k < 10; k++)
                    {
                        int offset = (j * 30) + k * 3 - removed;
                        if (!removedChildren.Contains([i, j, k, 0, 5, 0], bac))
                        {
                            Assert.IsTrue(tree.Root.Children[i].Values.ElementAt(offset).Key.SequenceEqual(new byte[] { i, j, k, 0, 5, 0 }));
                            Assert.AreEqual(tree.Root.Children[i].Values.ElementAt(offset).Value, BitConverter.ToInt32([i, j, k, 0, 5, 0]));
                        }
                        else
                        {
                            removed++;
                            offset--;
                        }

                        if (!removedChildren.Contains([i, j, k, 128, 5, 1], bac))
                        {
                            Assert.IsTrue(tree.Root.Children[i].Values.ElementAt(offset + 1).Key.SequenceEqual(new byte[] { i, j, k, 128, 5, 1 }));
                            Assert.AreEqual(tree.Root.Children[i].Values.ElementAt(offset + 1).Value, BitConverter.ToInt32([i, j, k, 128, 5, 1]));
                        }
                        else
                        {
                            removed++;
                            offset--;
                        }

                        if (!removedChildren.Contains([i, j, k, 255, 5, 2], bac))
                        {
                            Assert.IsTrue(tree.Root.Children[i].Values.ElementAt(offset + 2).Key.SequenceEqual(new byte[] { i, j, k, 255, 5, 2 }));
                            Assert.AreEqual(tree.Root.Children[i].Values.ElementAt(offset + 2).Value, BitConverter.ToInt32([i, j, k, 255, 5, 2]));
                        }
                        else
                        {
                            removed++;
                            offset--;
                        }
                    }
                }
            }

            for (byte i = 10; i < 20; i += 2)
            {
                int removed = 0;
                for (byte j = 0; j < 10; j += 2)
                {
                    for (byte k = 0; k < 10; k += 2)
                    {
                        int offset = (j / 2 * 15) + k / 2 * 3 - removed;
                        if (!removedChildren.Contains([i, j, k, 0, 5, 0], bac))
                        {
                            Assert.IsTrue(tree.Root.Children[i].Values.ElementAt(offset).Key.SequenceEqual(new byte[] { i, j, k, 0, 5, 0 }));
                            Assert.AreEqual(tree.Root.Children[i].Values.ElementAt(offset).Value, BitConverter.ToInt32([i, j, k, 0, 5, 0]));
                        }
                        else
                        {
                            removed++;
                            offset--;
                        }

                        if (!removedChildren.Contains([i, j, k, 128, 5, 1], bac))
                        {
                            Assert.IsTrue(tree.Root.Children[i].Values.ElementAt(offset + 1).Key.SequenceEqual(new byte[] { i, j, k, 128, 5, 1 }));
                            Assert.AreEqual(tree.Root.Children[i].Values.ElementAt(offset + 1).Value, BitConverter.ToInt32([i, j, k, 128, 5, 1]));
                        }
                        else
                        {
                            removed++;
                            offset--;
                        }

                        if (!removedChildren.Contains([i, j, k, 255, 5, 2], bac))
                        {
                            Assert.IsTrue(tree.Root.Children[i].Values.ElementAt(offset + 2).Key.SequenceEqual(new byte[] { i, j, k, 255, 5, 2 }));
                            Assert.AreEqual(tree.Root.Children[i].Values.ElementAt(offset + 2).Value, BitConverter.ToInt32([i, j, k, 255, 5, 2]));
                        }
                        else
                        {
                            removed++;
                            offset--;
                        }
                    }
                }
            }

            for (byte i = 20; i < 30; i += 3)
            {
                int removed = 0;
                for (byte j = 0; j < 10; j += 3)
                {
                    for (byte k = 0; k < 10; k += 3)
                    {
                        int offset = (j / 3 * 12) + k / 3 * 3 - removed;
                        if (!removedChildren.Contains([i, j, k, 0, 5, 0], bac))
                        {
                            Assert.IsTrue(tree.Root.Children[i].Values.ElementAt(offset).Key.SequenceEqual(new byte[] { i, j, k, 0, 5, 0 }));
                            Assert.AreEqual(tree.Root.Children[i].Values.ElementAt(offset).Value, BitConverter.ToInt32([i, j, k, 0, 5, 0]));
                        }
                        else
                        {
                            removed++;
                            offset--;
                        }

                        if (!removedChildren.Contains([i, j, k, 128, 5, 1], bac))
                        {
                            Assert.IsTrue(tree.Root.Children[i].Values.ElementAt(offset + 1).Key.SequenceEqual(new byte[] { i, j, k, 128, 5, 1 }));
                            Assert.AreEqual(tree.Root.Children[i].Values.ElementAt(offset + 1).Value, BitConverter.ToInt32([i, j, k, 128, 5, 1]));
                        }
                        else
                        {
                            removed++;
                            offset--;
                        }

                        if (!removedChildren.Contains([i, j, k, 255, 5, 2], bac))
                        {
                            Assert.IsTrue(tree.Root.Children[i].Values.ElementAt(offset + 2).Key.SequenceEqual(new byte[] { i, j, k, 255, 5, 2 }));
                            Assert.AreEqual(tree.Root.Children[i].Values.ElementAt(offset + 2).Value, BitConverter.ToInt32([i, j, k, 255, 5, 2]));
                        }
                        else
                        {
                            removed++;
                            offset--;
                        }
                    }
                }
            }

            for (byte i = 30; i < 40; i += 4)
            {
                int removed = 0;
                for (byte j = 0; j < 10; j += 4)
                {
                    for (byte k = 0; k < 10; k += 4)
                    {
                        int offset = (j / 4 * 9) + k / 4 * 3 - removed;
                        if (!removedChildren.Contains([i, j, k, 0, 5, 0], bac))
                        {
                            Assert.IsTrue(tree.Root.Children[i].Values.ElementAt(offset).Key.SequenceEqual(new byte[] { i, j, k, 0, 5, 0 }));
                            Assert.AreEqual(tree.Root.Children[i].Values.ElementAt(offset).Value, BitConverter.ToInt32([i, j, k, 0, 5, 0]));
                        }
                        else
                        {
                            removed++;
                            offset--;
                        }

                        if (!removedChildren.Contains([i, j, k, 128, 5, 1], bac))
                        {
                            Assert.IsTrue(tree.Root.Children[i].Values.ElementAt(offset + 1).Key.SequenceEqual(new byte[] { i, j, k, 128, 5, 1 }));
                            Assert.AreEqual(tree.Root.Children[i].Values.ElementAt(offset + 1).Value, BitConverter.ToInt32([i, j, k, 128, 5, 1]));
                        }
                        else
                        {
                            removed++;
                            offset--;
                        }

                        if (!removedChildren.Contains([i, j, k, 255, 5, 2], bac))
                        {
                            Assert.IsTrue(tree.Root.Children[i].Values.ElementAt(offset + 2).Key.SequenceEqual(new byte[] { i, j, k, 255, 5, 2 }));
                            Assert.AreEqual(tree.Root.Children[i].Values.ElementAt(offset + 2).Value, BitConverter.ToInt32([i, j, k, 255, 5, 2]));
                        }
                        else
                        {
                            removed++;
                            offset--;
                        }
                    }
                }
            }
        }

        [TestMethod]
        public void Add_1level()
        {
            PrefixIndexedTree<int> tree = new PrefixIndexedTree<int>(1);
            populate(tree);
            verify_1level(tree, []);
        }

        [TestMethod]
        [DataRow(1)]
        [DataRow(2)]
        [DataRow(3)]
        [DataRow(4)]
        [DataRow(5)]
        public void GetValue(int maxLevels)
        {
            PrefixIndexedTree<int> tree = new PrefixIndexedTree<int>(maxLevels);
            populate(tree);

            Assert.AreEqual(BitConverter.ToInt32([23, 3, 6, 128, 5, 1]), tree.GetValue([23, 3, 6, 128, 5, 1]));
        }

        [TestMethod]
        [DataRow(1)]
        [DataRow(2)]
        [DataRow(3)]
        [DataRow(4)]
        [DataRow(5)]
        public void GetValue_Missing(int maxLevels)
        {
            PrefixIndexedTree<int> tree = new PrefixIndexedTree<int>(maxLevels);
            populate(tree);

            Assert.AreEqual(default, tree.GetValue([23, 3, 6, 129, 5]));
        }

        [TestMethod]
        public void Remove_1level()
        {
            PrefixIndexedTree<int> tree = new PrefixIndexedTree<int>(1);
            populate(tree);
            byte[] key = [23, 3, 6, 128, 5, 1];
            Assert.AreEqual(BitConverter.ToInt32(key), tree.GetValue(key));
            tree.Remove(key);
            Assert.AreEqual(default, tree.GetValue(key));
            verify_1level(tree, [key]);
        }

        [TestMethod]
        public void RemovePrefix_1level()
        {
            PrefixIndexedTree<int> tree = new PrefixIndexedTree<int>(1);
            populate(tree);
            Assert.IsTrue(tree.Root.Children.ContainsKey(0));
            List<byte[]> keys = new();
            for (byte i = 0; i < 10; i++)
            {
                for (byte j = 0; j < 10; j++)
                {
                    for (byte k = 0; k < 10; k++)
                    {
                        byte[] key = [i, j, k, 0, 5, 0];
                        Assert.AreEqual(BitConverter.ToInt32(key), tree.GetValue(key));
                        tree.Remove(key);
                        Assert.AreEqual(default, tree.GetValue(key));
                        keys.Add(key);

                        key = [i, j, k, 128, 5, 1];
                        Assert.AreEqual(BitConverter.ToInt32(key), tree.GetValue(key));
                        tree.Remove(key);
                        Assert.AreEqual(default, tree.GetValue(key));
                        keys.Add(key);

                        key = [i, j, k, 255, 5, 2];
                        Assert.AreEqual(BitConverter.ToInt32(key), tree.GetValue(key));
                        tree.Remove(key);
                        Assert.AreEqual(default, tree.GetValue(key));
                        keys.Add(key);
                    }
                }
            }
            Assert.IsFalse(tree.Root.Children.ContainsKey(0));
            verify_1level(tree, keys);
        }

        [TestMethod]
        [DataRow(1)]
        [DataRow(2)]
        [DataRow(3)]
        [DataRow(4)]
        [DataRow(5)]
        public void GetClosestItemsFirst(int maxLevels)
        {
            PrefixIndexedTree<int> tree = new PrefixIndexedTree<int>(maxLevels);
            populate(tree);
            var items = tree.GetClosestItems([0, 0, 0, 0, 5, 0], 12);
            Assert.AreEqual(12, items.Count);
            for (byte i = 0; i < 4; i++)
            {
                int offset = i * 3;
                Assert.IsTrue(new byte[] { 0, 0, i, 0, 5, 0 }.SequenceEqual(items[offset].Key));
                Assert.IsTrue(new byte[] { 0, 0, i, 128, 5, 1 }.SequenceEqual(items[offset + 1].Key));
                Assert.IsTrue(new byte[] { 0, 0, i, 255, 5, 2 }.SequenceEqual(items[offset + 2].Key));
            }
        }

        [TestMethod]
        [DataRow(1)]
        [DataRow(2)]
        [DataRow(3)]
        [DataRow(4)]
        [DataRow(5)]
        public void GetClosestItemsSecond(int maxLevels)
        {
            PrefixIndexedTree<int> tree = new PrefixIndexedTree<int>(maxLevels);
            populate(tree);
            var items = tree.GetClosestItems([0, 0, 1, 0, 5, 0], 12);
            Assert.AreEqual(12, items.Count);
            for (byte i = 0; i < 4; i++)
            {
                int offset = i * 3;
                Assert.IsTrue(new byte[] { 0, 0, i, 0, 5, 0 }.SequenceEqual(items[offset].Key));
                Assert.IsTrue(new byte[] { 0, 0, i, 128, 5, 1 }.SequenceEqual(items[offset + 1].Key));
                Assert.IsTrue(new byte[] { 0, 0, i, 255, 5, 2 }.SequenceEqual(items[offset + 2].Key));
            }
        }

        [TestMethod]
        [DataRow(1)]
        [DataRow(2)]
        [DataRow(3)]
        [DataRow(4)]
        [DataRow(5)]
        public void GetClosestItemsLast(int maxLevels)
        {
            PrefixIndexedTree<int> tree = new PrefixIndexedTree<int>(maxLevels);
            populate(tree);
            var items = tree.GetClosestItems([38, 8, 8, 255, 5, 2], 27);
            Assert.AreEqual(27, items.Count);
            int offset = 0;
            for (byte j = 0; j < 10; j += 4)
            {
                for (byte k = 0; k < 10; k += 4)
                {
                    Assert.IsTrue(new byte[] { 38, j, k, 0, 5, 0 }.SequenceEqual(items[offset].Key));
                    Assert.IsTrue(new byte[] { 38, j, k, 128, 5, 1 }.SequenceEqual(items[offset + 1].Key));
                    Assert.IsTrue(new byte[] { 38, j, k, 255, 5, 2 }.SequenceEqual(items[offset + 2].Key));
                    offset += 3;
                }
            }
        }

        [TestMethod]
        public void GetClosestItemsEmpty()
        {
            PrefixIndexedTree<int> tree = new PrefixIndexedTree<int>(3);
            var items = tree.GetClosestItems([38, 8, 8, 128, 5, 1], 27);
            Assert.AreEqual(0, items.Count);
        }

        [TestMethod]
        [DataRow(1)]
        [DataRow(2)]
        [DataRow(3)]
        [DataRow(4)]
        [DataRow(5)]
        public void GetClosestItemsBeforeLast(int maxLevels)
        {
            PrefixIndexedTree<int> tree = new PrefixIndexedTree<int>(maxLevels);
            populate(tree);
            var items = tree.GetClosestItems([38, 8, 8, 128, 5, 1], 27);
            Assert.AreEqual(27, items.Count);
            int offset = 0;
            for (byte j = 0; j < 10; j += 4)
            {
                for (byte k = 0; k < 10; k += 4)
                {
                    Assert.IsTrue(new byte[] { 38, j, k, 0, 5, 0 }.SequenceEqual(items[offset].Key));
                    Assert.IsTrue(new byte[] { 38, j, k, 128, 5, 1 }.SequenceEqual(items[offset + 1].Key));
                    Assert.IsTrue(new byte[] { 38, j, k, 255, 5, 2 }.SequenceEqual(items[offset + 2].Key));
                    offset += 3;
                }
            }
        }


        [TestMethod]
        [DataRow(1)]
        [DataRow(2)]
        [DataRow(3)]
        [DataRow(4)]
        [DataRow(5)]
        public void GetClosestItemsMiddle(int maxLevels)
        {
            PrefixIndexedTree<int> tree = new PrefixIndexedTree<int>(maxLevels);
            populate(tree);
            var items = tree.GetClosestItems([10, 6, 0, 0, 5, 0], 31);
            Assert.AreEqual(31, items.Count);
            int offset = 0;
            for (byte j = 4; j < 10; j += 2)
            {
                for (byte k = 0; k < 10; k += 2)
                {
                    Assert.IsTrue(new byte[] { 10, j, k, 0, 5, 0 }.SequenceEqual(items[offset].Key));
                    if (offset == 30)
                    {
                        break;
                    }
                    Assert.IsTrue(new byte[] { 10, j, k, 128, 5, 1 }.SequenceEqual(items[offset + 1].Key));
                    Assert.IsTrue(new byte[] { 10, j, k, 255, 5, 2 }.SequenceEqual(items[offset + 2].Key));
                    offset += 3;
                }
            }
        }


        [TestMethod]
        // Exact key
        [DataRow(1, new byte[] { 16, 6, 0, 0, 5, 0 }, 392)]
        [DataRow(2, new byte[] { 16, 6, 0, 0, 5, 0 }, 392)]
        [DataRow(3, new byte[] { 16, 6, 0, 0, 5, 0 }, 392)]
        [DataRow(4, new byte[] { 16, 6, 0, 0, 5, 0 }, 392)]
        [DataRow(5, new byte[] { 16, 6, 0, 0, 5, 0 }, 392)]

        // Prefix
        [DataRow(1, new byte[] { 16, 6, 0, 0 }, 390)]
        [DataRow(2, new byte[] { 16, 6, 0, 0 }, 390)]
        [DataRow(3, new byte[] { 16, 6, 0, 0 }, 390)]
        [DataRow(4, new byte[] { 16, 6, 0, 0 }, 390)]
        [DataRow(5, new byte[] { 16, 6, 0, 0 }, 390)]

        // Approx key
        [DataRow(1, new byte[] { 15, 6, 0, 0, 5, 0 }, 300)]
        [DataRow(2, new byte[] { 15, 6, 0, 0, 5, 0 }, 270)]
        [DataRow(3, new byte[] { 15, 6, 0, 0, 5, 0 }, 246)]
        [DataRow(4, new byte[] { 15, 6, 0, 0, 5, 0 }, 242)]
        [DataRow(5, new byte[] { 15, 6, 0, 0, 5, 0 }, 242)]

        // Approx Prefix
        [DataRow(1, new byte[] { 15, 6, 0, 0 }, 300)]
        [DataRow(2, new byte[] { 15, 6, 0, 0 }, 270)]
        [DataRow(3, new byte[] { 15, 6, 0, 0 }, 246)]
        [DataRow(4, new byte[] { 15, 6, 0, 0 }, 242)]
        [DataRow(5, new byte[] { 15, 6, 0, 0 }, 242)]
        public void GetClosestItemsMiddleOverflow(int maxLevels, byte[] key, int maxItemCount, byte iOffset = 12)
        {
            PrefixIndexedTree<int> tree = new PrefixIndexedTree<int>(maxLevels);
            populate(tree);
            var items = tree.GetClosestItems(key, maxItemCount);
            Assert.AreEqual(maxItemCount, items.Count);
            int offset = 0;
            for (byte i = iOffset; i < 20; i += 2)
            {
                for (byte j = 0; j < 10; j += 2)
                {
                    for (byte k = 0; k < 10; k += 2)
                    {
                        if (offset + 2 >= maxItemCount)
                        {
                            break;
                        }
                        Assert.IsTrue(new byte[] { i, j, k, 0, 5, 0 }.SequenceEqual(items[offset].Key));
                        Assert.IsTrue(new byte[] { i, j, k, 128, 5, 1 }.SequenceEqual(items[offset + 1].Key));
                        Assert.IsTrue(new byte[] { i, j, k, 255, 5, 2 }.SequenceEqual(items[offset + 2].Key));
                        offset += 3;
                    }
                }
            }
        }

        private void verify_2levels(PrefixIndexedTree<int> tree, List<byte[]> removedChildren)
        {
            var bac = new ByteArrayComparer();
            for (byte i = 0; i < 10; i++)
            {
                for (byte j = 0; j < 10; j++)
                {
                    int removed = 0;
                    for (byte k = 0; k < 10; k++)
                    {
                        int offset = k * 3 - removed;
                        if (!removedChildren.Contains([i, j, k, 0, 5, 0], bac))
                        {
                            Assert.IsTrue(tree.Root.Children[i].Children[j].Values.ElementAt(offset).Key.SequenceEqual(new byte[] { i, j, k, 0, 5, 0 }));
                            Assert.AreEqual(tree.Root.Children[i].Children[j].Values.ElementAt(offset).Value, BitConverter.ToInt32([i, j, k, 0, 5, 0]));
                        }
                        else
                        {
                            removed++;
                            offset--;
                        }

                        if (!removedChildren.Contains([i, j, k, 128, 5, 1], bac))
                        {
                            Assert.IsTrue(tree.Root.Children[i].Children[j].Values.ElementAt(offset + 1).Key.SequenceEqual(new byte[] { i, j, k, 128, 5, 1 }));
                            Assert.AreEqual(tree.Root.Children[i].Children[j].Values.ElementAt(offset + 1).Value, BitConverter.ToInt32([i, j, k, 128, 5, 1]));
                        }
                        else
                        {
                            removed++;
                            offset--;
                        }

                        if (!removedChildren.Contains([i, j, k, 255, 5, 2], bac))
                        {
                            Assert.IsTrue(tree.Root.Children[i].Children[j].Values.ElementAt(offset + 2).Key.SequenceEqual(new byte[] { i, j, k, 255, 5, 2 }));
                            Assert.AreEqual(tree.Root.Children[i].Children[j].Values.ElementAt(offset + 2).Value, BitConverter.ToInt32([i, j, k, 255, 5, 2]));
                        }
                        else
                        {
                            removed++;
                            offset--;
                        }
                    }
                }
            }

            for (byte i = 10; i < 20; i += 2)
            {
                for (byte j = 0; j < 10; j += 2)
                {
                    int removed = 0;
                    for (byte k = 0; k < 10; k += 2)
                    {
                        int offset = k / 2 * 3 - removed;
                        if (!removedChildren.Contains([i, j, k, 0, 5, 0], bac))
                        {
                            Assert.IsTrue(tree.Root.Children[i].Children[j].Values.ElementAt(offset).Key.SequenceEqual(new byte[] { i, j, k, 0, 5, 0 }));
                            Assert.AreEqual(tree.Root.Children[i].Children[j].Values.ElementAt(offset).Value, BitConverter.ToInt32([i, j, k, 0, 5, 0]));
                        }
                        else
                        {
                            removed++;
                            offset--;
                        }

                        if (!removedChildren.Contains([i, j, k, 128, 5, 1], bac))
                        {
                            Assert.IsTrue(tree.Root.Children[i].Children[j].Values.ElementAt(offset + 1).Key.SequenceEqual(new byte[] { i, j, k, 128, 5, 1 }));
                            Assert.AreEqual(tree.Root.Children[i].Children[j].Values.ElementAt(offset + 1).Value, BitConverter.ToInt32([i, j, k, 128, 5, 1]));
                        }
                        else
                        {
                            removed++;
                            offset--;
                        }

                        if (!removedChildren.Contains([i, j, k, 255, 5, 2], bac))
                        {
                            Assert.IsTrue(tree.Root.Children[i].Children[j].Values.ElementAt(offset + 2).Key.SequenceEqual(new byte[] { i, j, k, 255, 5, 2 }));
                            Assert.AreEqual(tree.Root.Children[i].Children[j].Values.ElementAt(offset + 2).Value, BitConverter.ToInt32([i, j, k, 255, 5, 2]));
                        }
                        else
                        {
                            removed++;
                            offset--;
                        }
                    }
                }
            }


            for (byte i = 20; i < 30; i += 3)
            {
                for (byte j = 0; j < 10; j += 3)
                {
                    int removed = 0;
                    for (byte k = 0; k < 10; k += 3)
                    {
                        int offset = k / 3 * 3 - removed;
                        if (!removedChildren.Contains([i, j, k, 0, 5, 0], bac))
                        {
                            Assert.IsTrue(tree.Root.Children[i].Children[j].Values.ElementAt(offset).Key.SequenceEqual(new byte[] { i, j, k, 0, 5, 0 }));
                            Assert.AreEqual(tree.Root.Children[i].Children[j].Values.ElementAt(offset).Value, BitConverter.ToInt32([i, j, k, 0, 5, 0]));
                        }
                        else
                        {
                            removed++;
                            offset--;
                        }

                        if (!removedChildren.Contains([i, j, k, 128, 5, 1], bac))
                        {
                            Assert.IsTrue(tree.Root.Children[i].Children[j].Values.ElementAt(offset + 1).Key.SequenceEqual(new byte[] { i, j, k, 128, 5, 1 }));
                            Assert.AreEqual(tree.Root.Children[i].Children[j].Values.ElementAt(offset + 1).Value, BitConverter.ToInt32([i, j, k, 128, 5, 1]));
                        }
                        else
                        {
                            removed++;
                            offset--;
                        }

                        if (!removedChildren.Contains([i, j, k, 255, 5, 2], bac))
                        {
                            Assert.IsTrue(tree.Root.Children[i].Children[j].Values.ElementAt(offset + 2).Key.SequenceEqual(new byte[] { i, j, k, 255, 5, 2 }));
                            Assert.AreEqual(tree.Root.Children[i].Children[j].Values.ElementAt(offset + 2).Value, BitConverter.ToInt32([i, j, k, 255, 5, 2]));
                        }
                        else
                        {
                            removed++;
                            offset--;
                        }
                    }
                }
            }


            for (byte i = 30; i < 40; i += 4)
            {
                for (byte j = 0; j < 10; j += 4)
                {
                    int removed = 0;
                    for (byte k = 0; k < 10; k += 4)
                    {
                        int offset = k / 4 * 3 - removed;
                        if (!removedChildren.Contains([i, j, k, 0, 5, 0], bac))
                        {
                            Assert.IsTrue(tree.Root.Children[i].Children[j].Values.ElementAt(offset).Key.SequenceEqual(new byte[] { i, j, k, 0, 5, 0 }));
                            Assert.AreEqual(tree.Root.Children[i].Children[j].Values.ElementAt(offset).Value, BitConverter.ToInt32([i, j, k, 0, 5, 0]));
                        }
                        else
                        {
                            removed++;
                            offset--;
                        }

                        if (!removedChildren.Contains([i, j, k, 128, 5, 1], bac))
                        {
                            Assert.IsTrue(tree.Root.Children[i].Children[j].Values.ElementAt(offset + 1).Key.SequenceEqual(new byte[] { i, j, k, 128, 5, 1 }));
                            Assert.AreEqual(tree.Root.Children[i].Children[j].Values.ElementAt(offset + 1).Value, BitConverter.ToInt32([i, j, k, 128, 5, 1]));
                        }
                        else
                        {
                            removed++;
                            offset--;
                        }

                        if (!removedChildren.Contains([i, j, k, 255, 5, 2], bac))
                        {
                            Assert.IsTrue(tree.Root.Children[i].Children[j].Values.ElementAt(offset + 2).Key.SequenceEqual(new byte[] { i, j, k, 255, 5, 2 }));
                            Assert.AreEqual(tree.Root.Children[i].Children[j].Values.ElementAt(offset + 2).Value, BitConverter.ToInt32([i, j, k, 255, 5, 2]));
                        }
                        else
                        {
                            removed++;
                            offset--;
                        }
                    }
                }
            }
        }

        [TestMethod]
        public void Add_2levels()
        {
            PrefixIndexedTree<int> tree = new PrefixIndexedTree<int>(2);
            populate(tree);
            verify_2levels(tree, new());
            Logging.info(JsonConvert.SerializeObject(tree.Root, new JsonSerializerSettings() { ReferenceLoopHandling = ReferenceLoopHandling.Ignore }));
        }

        [TestMethod]
        public void Add_2levels_duplicate()
        {
            PrefixIndexedTree<int> tree = new PrefixIndexedTree<int>(2);
            populate(tree);
            populate(tree);
            verify_2levels(tree, new());
        }

        [TestMethod]
        public void Remove_2levels()
        {
            PrefixIndexedTree<int> tree = new PrefixIndexedTree<int>(2);
            populate(tree);
            byte[] key = [23, 3, 6, 128, 5, 1];
            Assert.AreEqual(BitConverter.ToInt32(key), tree.GetValue(key));
            tree.Remove(key);
            Assert.AreEqual(default, tree.GetValue(key));
            verify_2levels(tree, [key]);
        }

        [TestMethod]
        public void RemoveSinglePrefix_2levels()
        {
            PrefixIndexedTree<int> tree = new PrefixIndexedTree<int>(2);
            populate(tree);
            Assert.IsTrue(tree.Root.Children[0].Children.ContainsKey(0));
            List<byte[]> keys = new();
            for (byte k = 0; k < 10; k++)
            {
                byte[] key = [0, 0, k, 0, 5, 0];
                Assert.AreEqual(BitConverter.ToInt32(key), tree.GetValue(key));
                tree.Remove(key);
                Assert.AreEqual(default, tree.GetValue(key));
                keys.Add(key);

                key = [0, 0, k, 128, 5, 1];
                Assert.AreEqual(BitConverter.ToInt32(key), tree.GetValue(key));
                tree.Remove(key);
                Assert.AreEqual(default, tree.GetValue(key));
                keys.Add(key);

                key = [0, 0, k, 255, 5, 2];
                Assert.AreEqual(BitConverter.ToInt32(key), tree.GetValue(key));
                tree.Remove(key);
                Assert.AreEqual(default, tree.GetValue(key));
                keys.Add(key);
            }
            Assert.IsFalse(tree.Root.Children[0].Children.ContainsKey(0));
            verify_2levels(tree, keys);
        }

        [TestMethod]
        public void RemoveBothPrefixes_2levels()
        {
            PrefixIndexedTree<int> tree = new PrefixIndexedTree<int>(2);
            populate(tree);
            Assert.IsTrue(tree.Root.Children[0].Children.ContainsKey(0));
            List<byte[]> keys = new();
            for (byte j = 0; j < 10; j++)
            {
                for (byte k = 0; k < 10; k++)
                {
                    byte[] key = [0, j, k, 0, 5, 0];
                    Assert.AreEqual(BitConverter.ToInt32(key), tree.GetValue(key));
                    tree.Remove(key);
                    Assert.AreEqual(default, tree.GetValue(key));
                    keys.Add(key);

                    key = [0, j, k, 128, 5, 1];
                    Assert.AreEqual(BitConverter.ToInt32(key), tree.GetValue(key));
                    tree.Remove(key);
                    Assert.AreEqual(default, tree.GetValue(key));
                    keys.Add(key);

                    key = [0, j, k, 255, 5, 2];
                    Assert.AreEqual(BitConverter.ToInt32(key), tree.GetValue(key));
                    tree.Remove(key);
                    Assert.AreEqual(default, tree.GetValue(key));
                    keys.Add(key);
                }
            }
            Assert.IsFalse(tree.Root.Children.ContainsKey(0));
            verify_2levels(tree, keys);
        }

        [TestMethod]
        public void RemovePrefix_2levels()
        {
            PrefixIndexedTree<int> tree = new PrefixIndexedTree<int>(2);
            populate(tree);
            Assert.IsTrue(tree.Root.Children.ContainsKey(0));
            List<byte[]> keys = new();
            for (byte i = 0; i < 10; i++)
            {
                for (byte j = 0; j < 10; j++)
                {
                    for (byte k = 0; k < 10; k++)
                    {
                        byte[] key = [i, j, k, 0, 5, 0];
                        Assert.AreEqual(BitConverter.ToInt32(key), tree.GetValue(key));
                        tree.Remove(key);
                        Assert.AreEqual(default, tree.GetValue(key));
                        keys.Add(key);

                        key = [i, j, k, 128, 5, 1];
                        Assert.AreEqual(BitConverter.ToInt32(key), tree.GetValue(key));
                        tree.Remove(key);
                        Assert.AreEqual(default, tree.GetValue(key));
                        keys.Add(key);

                        key = [i, j, k, 255, 5, 2];
                        Assert.AreEqual(BitConverter.ToInt32(key), tree.GetValue(key));
                        tree.Remove(key);
                        Assert.AreEqual(default, tree.GetValue(key));
                        keys.Add(key);
                    }
                }
            }
            Assert.IsFalse(tree.Root.Children.ContainsKey(0));
            verify_2levels(tree, keys);
        }
    }
}
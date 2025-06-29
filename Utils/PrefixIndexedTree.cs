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
using System.Collections.Generic;
using System.Linq;

namespace IXICore.Utils
{
    public class PrefixIndexedTreeNode<T>
    {
        public byte Key;
        public PrefixIndexedTreeNode<T> Parent;
        public SortedDictionary<byte, PrefixIndexedTreeNode<T>> Children = new();
        public SortedDictionary<byte[], T> Values;

        public PrefixIndexedTreeNode()
        {
        }

        public PrefixIndexedTreeNode(PrefixIndexedTreeNode<T> parent, byte key)
        {
            Parent = parent;
            Key = key;
        }
    }

    public class PrefixIndexedTree<T>
    {
        public PrefixIndexedTreeNode<T> Root { get; private set; } = new();
        int MaxLevels;

        public PrefixIndexedTree(int maxLevels)
        {
            if (maxLevels < 1)
            {
                throw new ArgumentException("maxLevels should be at least 1");
            }
            MaxLevels = maxLevels;
        }


        private bool getClosestPreviousKey(PrefixIndexedTreeNode<T> currentNode, byte targetKey, out byte previousKey)
        {
            previousKey = targetKey;
            for (int i = targetKey; i >= 0; i--)
            {
                if (currentNode.Children.ContainsKey((byte)i))
                {
                    previousKey = (byte)i;
                    return true;
                }
            }
            return false;
        }

        private bool getClosestKey(PrefixIndexedTreeNode<T> currentNode, byte targetKey, out int direction, out byte closestKey)
        {
            direction = 0;
            closestKey = targetKey;
            for (int i = 1; i <= 255; i++)
            {
                if (targetKey >= i
                    && currentNode.Children.ContainsKey((byte)(targetKey - i)))
                {
                    closestKey = (byte)(targetKey - i);
                    direction = -1;
                    return true;
                }
                if (i + targetKey <= 255
                    && currentNode.Children.ContainsKey((byte)(targetKey + i)))
                {
                    closestKey = (byte)(targetKey + i);
                    direction = 1;
                    return true;
                }
            }
            return false;
        }

        private bool getClosestNextKey(PrefixIndexedTreeNode<T> currentNode, byte targetKey, out byte nextKey)
        {
            nextKey = targetKey;
            for (int i = targetKey; i <= 255; i++)
            {
                if (currentNode.Children.ContainsKey((byte)i))
                {
                    nextKey = (byte)i;
                    return true;
                }
            }
            return false;
        }

        private PrefixIndexedTreeNode<T> FindPrefixNode(byte[] key, bool closestNode, bool create)
        {
            if (!create
                && Root.Children.Count == 0)
            {
                return null;
            }

            var currentNode = Root;
            int level = 0;
            int direction = 0;
            foreach (var b in key)
            {
                level++;

                var closestKey = b;
                if (!currentNode.Children.ContainsKey(b))
                {
                    if (create)
                    {
                        currentNode.Children[b] = new PrefixIndexedTreeNode<T>(currentNode, b);
                    }
                    else if (!closestNode)
                    {
                        return null;
                    }
                    else
                    {
                        if (direction == -1)
                        {
                            getClosestPreviousKey(currentNode, 255, out closestKey);
                        }
                        else if (direction == 0)
                        {
                            getClosestKey(currentNode, b, out direction, out closestKey);
                        }
                        else if (direction == 1)
                        {
                            getClosestNextKey(currentNode, 0, out closestKey);
                        }
                    }
                }

                currentNode = currentNode.Children[closestKey];

                if (level >= MaxLevels)
                {
                    if (create && currentNode.Values == null)
                    {
                        currentNode.Values = new(new ByteArrayComparer());
                    }
                    break;
                }
            }

            return currentNode;
        }

        public bool Add(byte[] key, T value)
        {
            if (key.Length < MaxLevels)
            {
                throw new ArgumentOutOfRangeException("Invalid key length, should be at least as long as Max Levels");
            }
            var prefixNode = FindPrefixNode(key, false, true);

            if (!prefixNode.Values.ContainsKey(key))
            {
                prefixNode.Values.Add(key, value);
                return true;
            }

            return false;
        }

        public bool Remove(byte[] key)
        {
            var prefixNode = FindPrefixNode(key, false, false);

            if (prefixNode == null)
            {
                return false;
            }

            bool removed = prefixNode.Values.Remove(key);
            if (removed
                && prefixNode.Values.Count == 0)
            {
                PrefixIndexedTreeNode<T> removeChildNode = prefixNode;
                while (prefixNode.Parent != null)
                {
                    prefixNode.Parent.Children.Remove(prefixNode.Key);
                    prefixNode = prefixNode.Parent;

                    if (prefixNode.Children.Count > 0)
                    {
                        break;
                    }
                }
                return true;
            }

            return false;
        }

        private PrefixIndexedTreeNode<T> FindPreviousNodeNeighbour(PrefixIndexedTreeNode<T> node)
        {
            if (node.Parent == null)
            {
                return null;
            }

            for (int i = node.Parent.Children.Count - 1; i >= 0; i--)
            {
                var child = node.Parent.Children.ElementAt(i);
                if (child.Key < node.Key)
                {
                    if (child.Value.Values != null)
                    {
                        return child.Value;
                    }
                    else
                    {
                        var lastChild = child.Value.Children.Last().Value;
                        while (lastChild.Values == null)
                        {
                            lastChild = lastChild.Children.Last().Value;
                        }
                        if (lastChild.Values != null)
                        {
                            return lastChild;
                        }
                    }
                }
            }

            return FindPreviousNodeNeighbour(node.Parent);
        }

        private PrefixIndexedTreeNode<T> FindNextNodeNeighbour(PrefixIndexedTreeNode<T> node)
        {
            if (node.Parent == null)
            {
                return null;
            }

            foreach (var child in node.Parent.Children)
            {
                if (child.Key > node.Key)
                {
                    if (child.Value.Values != null)
                    {
                        return child.Value;
                    }
                    else
                    {
                        var firstChild = child.Value.Children.First().Value;
                        while (firstChild.Values == null)
                        {
                            firstChild = firstChild.Children.First().Value;
                        }
                        if (firstChild.Values != null)
                        {
                            return firstChild;
                        }
                    }
                }
            }

            return FindNextNodeNeighbour(node.Parent);
        }

        private List<(byte[] Key, T Value)> CollectItemsBeforeTarget(PrefixIndexedTreeNode<T> closestPrefixNode, int maxItemsCount)
        {
            List<(byte[], T)> items = new();
            if (maxItemsCount > 1)
            {
                while (items.Count < maxItemsCount)
                {
                    closestPrefixNode = FindPreviousNodeNeighbour(closestPrefixNode);

                    if (closestPrefixNode == null)
                    {
                        break;
                    }

                    if (closestPrefixNode.Values == null)
                    {
                        continue;
                    }

                    for (int j = closestPrefixNode.Values.Count - 1; j >= 0; j--)
                    {
                        var item = closestPrefixNode.Values.ElementAt(j);
                        items.Add((item.Key, item.Value));

                        if (items.Count >= maxItemsCount)
                        {
                            break;
                        }
                    }
                }

                items.Reverse();
            }
            return items;
        }

        private List<(byte[] Key, T Value)> CollectItems(byte[] key, PrefixIndexedTreeNode<T> closestPrefixNode, int maxItemsCount)
        {
            if (maxItemsCount < 1)
            {
                throw new ArgumentException("maxItemsCount must be at least 1");
            }

            while (closestPrefixNode.Values == null)
            {
                closestPrefixNode = closestPrefixNode.Children.First().Value;
            }

            List<(byte[], T)> items = CollectItemsBeforeTarget(closestPrefixNode, maxItemsCount);

            // Collect target items
            int afterTargetCount = 0;
            var bac = new ByteArrayComparer();
            foreach (var item in closestPrefixNode.Values)
            {
                items.Add((item.Key, item.Value));

                if (items.Count > maxItemsCount)
                {
                    items.RemoveAt(0);
                }

                if (afterTargetCount == 0)
                {
                    int cmp = bac.Compare(item.Key, key);
                    if (cmp == 0)
                    {
                        if (maxItemsCount == 1)
                        {
                            return items;
                        }
                    }
                    else if (cmp > 0)
                    {
                        afterTargetCount++;
                    }
                }
                else
                {
                    afterTargetCount++;
                    if (afterTargetCount >= maxItemsCount / 2
                        && items.Count >= maxItemsCount)
                    {
                        break;
                    }
                }
            }

            if (maxItemsCount == 1)
            {
                return null;
            }

            // Collect items after target
            for (int i = afterTargetCount; i < maxItemsCount / 2 || items.Count < maxItemsCount;)
            {
                closestPrefixNode = FindNextNodeNeighbour(closestPrefixNode);

                if (closestPrefixNode == null)
                {
                    break;
                }

                if (closestPrefixNode.Values == null)
                {
                    continue;
                }

                foreach (var item in closestPrefixNode.Values)
                {
                    i++;
                    items.Add((item.Key, item.Value));

                    if (items.Count > maxItemsCount)
                    {
                        items.RemoveAt(0);
                    }

                    if (i >= maxItemsCount / 2
                        && items.Count >= maxItemsCount)
                    {
                        break;
                    }
                }
            }

            return items;
        }

        public T GetValue(byte[] key)
        {
            var prefixNode = FindPrefixNode(key, false, false);
            if (prefixNode == null)
            {
                return default(T);
            }

            var items = CollectItems(key, prefixNode, 1);

            if (items == null || items.Count == 0)
            {
                return default(T);
            }

            return items.First().Value;
        }

        public List<(byte[] Key, T Value)> GetClosestItems(byte[] prefix, int maxItemsCount)
        {
            if (maxItemsCount < 2)
            {
                throw new ArgumentException("maxItemsCount must be at least 2");
            }

            var prefixNode = FindPrefixNode(prefix, true, false);
            if (prefixNode == null)
            {
                return new();
            }

            return CollectItems(prefix, prefixNode, maxItemsCount);
        }

        public void Clear()
        {
            Root = new PrefixIndexedTreeNode<T>();
        }
    }
}
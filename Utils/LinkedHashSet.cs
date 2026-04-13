// Copyright (C) 2017-2026 Ixian
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

using System.Collections;
using System.Collections.Generic;
using System.Threading;

namespace IXICore.Utils
{

    public class LinkedHashSet<T> : IEnumerable<T> where T : notnull
    {
        private readonly Dictionary<T, LinkedListNode<T>> _map;
        private readonly LinkedList<T> _list;

        public LinkedHashSet(IEqualityComparer<T>? comparer = null)
        {
            _map = new Dictionary<T, LinkedListNode<T>>(comparer);
            _list = new LinkedList<T>();
        }

        public LinkedHashSet(HashSet<T> source, IEqualityComparer<T>? comparer = null)
        {
            _map = new Dictionary<T, LinkedListNode<T>>(comparer);
            _list = new LinkedList<T>();

            foreach (var item in source)
            {
                var node = _list.AddLast(item);
                _map.Add(item, node);
            }
        }

        public int Count => _map.Count;

        public bool Add(T item)
        {
            if (_map.ContainsKey(item))
                return false;

            var node = _list.AddLast(item);
            _map.Add(item, node);
            return true;
        }

        public bool Remove(T item)
        {
            if (!_map.TryGetValue(item, out var node))
                return false;

            _map.Remove(item);
            _list.Remove(node);
            return true;
        }

        public bool Contains(T item) => _map.ContainsKey(item);

        public void Clear()
        {
            _map.Clear();
            _list.Clear();
        }

        public void SortInPlace(IComparer<T>? comparer = null)
        {
            var snapshot = new List<T>(_list);
            snapshot.Sort(comparer ?? Comparer<T>.Default);

            _map.Clear();
            _list.Clear();

            foreach (var item in snapshot)
            {
                var node = _list.AddLast(item);
                _map[item] = node;
            }
        }

        public IEnumerator<T> GetEnumerator() => _list.GetEnumerator();

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }

    public class ConcurrentLinkedHashSet<T> : IEnumerable<T> where T : notnull
    {
        private readonly LinkedHashSet<T> _inner;
        private readonly ReaderWriterLockSlim _lock;

        public ConcurrentLinkedHashSet(IEqualityComparer<T>? comparer = null)
        {
            _inner = new LinkedHashSet<T>(comparer);
            _lock = new ReaderWriterLockSlim(LockRecursionPolicy.NoRecursion);
        }

        public int Count
        {
            get
            {
                _lock.EnterReadLock();
                try { return _inner.Count; }
                finally { _lock.ExitReadLock(); }
            }
        }

        public bool Add(T item)
        {
            _lock.EnterWriteLock();
            try { return _inner.Add(item); }
            finally { _lock.ExitWriteLock(); }
        }

        public bool Remove(T item)
        {
            _lock.EnterWriteLock();
            try { return _inner.Remove(item); }
            finally { _lock.ExitWriteLock(); }
        }

        public bool Contains(T item)
        {
            _lock.EnterReadLock();
            try { return _inner.Contains(item); }
            finally { _lock.ExitReadLock(); }
        }

        public void Clear()
        {
            _lock.EnterWriteLock();
            try { _inner.Clear(); }
            finally { _lock.ExitWriteLock(); }
        }

        public void SortInPlace(IComparer<T>? comparer = null)
        {
            _lock.EnterWriteLock();
            try { _inner.SortInPlace(comparer); }
            finally { _lock.ExitWriteLock(); }
        }

        public IEnumerator<T> GetEnumerator()
        {
            _lock.EnterReadLock();
            try
            {
                // snapshot for safety
                return new List<T>(_inner).GetEnumerator();
            }
            finally
            {
                _lock.ExitReadLock();
            }
        }

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }
}
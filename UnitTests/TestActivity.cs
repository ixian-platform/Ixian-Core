using Microsoft.VisualStudio.TestTools.UnitTesting;
using IXICore.Activity;
using System;
using System.Linq;
using System.Threading;
using IXICore;
using System.Collections.Generic;

namespace UnitTests
{
    [TestClass]
    public class TestActivity
    {
        private IActivityStorage db;

        [TestInitialize]
        public void Init()
        {
            db = new ActivityStorage("test", 10UL << 20, 0);
            db.prepareStorage(false);
        }

        [TestCleanup]
        public void Cleanup()
        {
            db.stopStorage();
            db.deleteData();
        }

        // ---------- Helpers ----------

        private static byte[] New16()
        {
            var g = Guid.NewGuid().ToByteArray(); // 16 bytes
            return g;
        }

        private static byte[] FixedSeed16(byte fill = 0xAB)
        {
            var s = new byte[16];
            for (int i = 0; i < s.Length; i++) s[i] = fill;
            return s;
        }

        private static ActivityType AnyActivityType()
        {
            var values = Enum.GetValues(typeof(ActivityType)).Cast<ActivityType>().ToArray();
            return values.Length > 0 ? values[0] : (ActivityType)0;
        }

        private static ActivityStatus AnyStatus()
        {
            var values = Enum.GetValues(typeof(ActivityStatus)).Cast<ActivityStatus>().ToArray();
            return values.Length > 0 ? values[0] : (ActivityStatus)0;
        }

        private static ActivityStatus AnotherStatus(ActivityStatus s)
        {
            var values = Enum.GetValues(typeof(ActivityStatus)).Cast<ActivityStatus>().Distinct().ToArray();
            return values.FirstOrDefault(x => !x.Equals(s));
        }

        private static ActivityType AnotherType(ActivityType t)
        {
            var values = Enum.GetValues(typeof(ActivityType)).Cast<ActivityType>().Distinct().ToArray();
            return values.FirstOrDefault(x => !x.Equals(t));
        }

        private static ActivityObject MakeActivity(byte[] seed16, ulong block, ActivityType type, ActivityStatus status, string valueStr, long? ts = null)
        {
            Dictionary<Address, IxiNumber> addressList = new Dictionary<Address, IxiNumber>();
            addressList.Add(new Address("16LUmwUnU9M4Wn92nrvCStj83LDCRwvAaSio6Xtb3yvqqqCCz"), 100);
            addressList.Add(new Address("3vcJsrUNCjhfFD5Nqohx6pVmwDXeR2Gh8aePdj3cJ2ttLHCoSCxDB82qVTAKqZTcU"), 200);
            var ao = new ActivityObject(seed16,
                                        new Address("16LUmwUnU9M4Wn92nrvCStj83LDCRwvAaSio6Xtb3yvqqqCCz"),
                                        New16(),
                                        addressList,
                                        type,
                                        New16(),
                                        new IxiNumber(valueStr),
                                        ts ?? Clock.getTimestamp(),
                                        status,
                                        block);
            return ao;
        }

        private ActivityObject InsertOne(byte[] seed16, ulong block, ActivityType type, ActivityStatus status, string valueStr)
        {
            var ao = MakeActivity(seed16, block, type, status, valueStr);
            var ok = db.insertActivity(ao);
            Assert.IsTrue(ok, "insertActivity failed");
            // brief sleep to ensure strictly increasing timestamp order when needed
            Thread.Sleep(3);
            return ao;
        }

        // ---------- Tests ----------

        [TestMethod]
        public void Insert_And_Query_Ascending_NoFilter()
        {
            var seed = FixedSeed16(0x11);
            var t = AnyActivityType();
            var s = AnyStatus();

            var a1 = InsertOne(seed, 100, t, s, "1");
            var a2 = InsertOne(seed, 101, t, s, "2");
            var a3 = InsertOne(seed, 102, t, s, "3");

            var list = db.getActivitiesBySeedHashAndType(seed, null, null, count: 10, descending: false);
            Assert.AreEqual(3, list.Count, "Expected 3 activities");

            // ascending by (timestamp,id) implicit in key
            Assert.IsTrue(list[0].timestamp <= list[1].timestamp && list[1].timestamp <= list[2].timestamp, "Expected ascending order by insertion time");
        }

        [TestMethod]
        public void Query_FilterByType()
        {
            var seed = FixedSeed16(0x22);
            var tA = AnyActivityType();
            var tB = AnotherType(tA);
            var s = AnyStatus();

            InsertOne(seed, 10, tA, s, "10");
            InsertOne(seed, 20, tB, s, "20");
            InsertOne(seed, 30, tA, s, "30");

            var onlyA = db.getActivitiesBySeedHashAndType(seed, tA, null, count: 50, descending: false);
            Assert.AreEqual(2, onlyA.Count, "Type filter should return 2");
            Assert.IsTrue(onlyA.All(x => x.type.Equals(tA)));
        }

        [TestMethod]
        public void Query_Descending_Order()
        {
            var seed = FixedSeed16(0x33);
            var t = AnyActivityType();
            var s = AnyStatus();

            var a1 = InsertOne(seed, 1, t, s, "1");
            var a2 = InsertOne(seed, 2, t, s, "2");
            var a3 = InsertOne(seed, 3, t, s, "3");

            var list = db.getActivitiesBySeedHashAndType(seed, null, null, count: 10, descending: true);
            Assert.AreEqual(3, list.Count);
            // descending by insertion time
            Assert.IsTrue(list[0].timestamp >= list[1].timestamp && list[1].timestamp >= list[2].timestamp, "Expected descending order by insertion time");
        }

        [TestMethod]
        public void Query_Pagination_FromKey_Exclusive()
        {
            var seed = FixedSeed16(0x44);
            var t = AnyActivityType();
            var s = AnyStatus();

            var a1 = InsertOne(seed, 11, t, s, "11");
            var a2 = InsertOne(seed, 12, t, s, "12");
            var a3 = InsertOne(seed, 13, t, s, "13");

            // start "after" a2 using fromKey = a2.id, ascending
            var page = db.getActivitiesBySeedHashAndType(seed, null, fromActivityId: a2.id, count: 10, descending: false);
            Assert.AreEqual(1, page.Count, "fromKey should be exclusive in ascending");
            Assert.IsTrue(page[0].id.SequenceEqual(a3.id), "Expected only item after a2 to be a3");
        }

        [TestMethod]
        public void Query_Pagination_FromKey_Exclusive_Descending()
        {
            var seed = FixedSeed16(0x44);
            var t = AnyActivityType();
            var s = AnyStatus();

            var a1 = InsertOne(seed, 11, t, s, "11");
            var a2 = InsertOne(seed, 12, t, s, "12");
            var a3 = InsertOne(seed, 13, t, s, "13");

            // start "after" a2 using fromKey = a2.id, descending
            var page = db.getActivitiesBySeedHashAndType(seed, null, fromActivityId: a2.id, count: 10, descending: true);
            Assert.AreEqual(1, page.Count, "fromKey should be exclusive in descending");
            Assert.IsTrue(page[0].id.SequenceEqual(a1.id), "Expected only item after a2 to be a1");
        }

        [TestMethod]
        public void UpdateStatus_Updates_Block_And_MinMax()
        {
            var seed = FixedSeed16(0x55);
            var t = AnyActivityType();
            var s0 = AnyStatus();
            var s1 = AnotherStatus(s0);

            var a = InsertOne(seed, 1000, t, s0, "100");

            // highest should be >= 1000
            var highestBefore = (db as ActivityStorage).getHighestBlockInStorage();
            Assert.IsTrue(highestBefore >= 1000UL);

            // update to higher block, set timestamp as well
            var newBlock = highestBefore + 5;
            long newTs = Clock.getTimestamp() + 1234;

            var ok = db.updateStatus(a.id, s1, newBlock, newTs);
            Assert.IsTrue(ok, "updateStatus failed");

            // re-read and verify
            var list = db.getActivitiesBySeedHashAndType(seed, null, null, 10, false);
            Assert.AreEqual(1, list.Count);
            Assert.AreEqual(s1, list[0].status);
            Assert.AreEqual(newBlock, list[0].blockHeight);
            Assert.AreEqual(newTs, list[0].timestamp);

            // highest should bump
            var highestAfter = (db as ActivityStorage).getHighestBlockInStorage();
            Assert.AreEqual(newBlock, highestAfter);
        }

        [TestMethod]
        public void UpdateValue_Persists_New_Value()
        {
            var seed = FixedSeed16(0x66);
            var t = AnyActivityType();
            var s = AnyStatus();

            var a = InsertOne(seed, 77, t, s, "42");
            var ok = db.updateValue(a.id, new IxiNumber("1337"));
            Assert.IsTrue(ok, "updateValue failed");

            var list = db.getActivitiesBySeedHashAndType(seed, null, null, 10, false);
            Assert.AreEqual(1, list.Count);
            Assert.AreEqual(new IxiNumber("1337"), list[0].value.ToString());
        }

        [TestMethod]
        public void Lowest_And_Highest_Block_Tracking()
        {
            var seed = FixedSeed16(0x77);
            var t = AnyActivityType();
            var s = AnyStatus();

            InsertOne(seed, 500, t, s, "1");
            InsertOne(seed, 250, t, s, "2");
            InsertOne(seed, 750, t, s, "3");

            var highest = (db as ActivityStorage).getHighestBlockInStorage();
            var lowest = (db as ActivityStorage).getLowestBlockInStorage();

            Assert.AreEqual(750UL, highest, "Highest block should be 750");
            Assert.AreEqual(250UL, lowest, "Lowest block should be 250");
        }

        [TestMethod]
        public void Cleanup_Reopen_Smoke()
        {
            // Ensure that after cleanup (auto-close), we can still query (it must reopen).
            var asConcrete = (ActivityStorage)db;
            asConcrete.closeAfterSeconds = 1;

            var seed = FixedSeed16(0x88);
            var t = AnyActivityType();
            var s = AnyStatus();

            InsertOne(seed, 1, t, s, "6");

            Thread.Sleep(1200);
            asConcrete.cleanupCache(); // triggers closure due to inactivity

            // Should still be able to read (db reopens transparently)
            var list = db.getActivitiesBySeedHashAndType(seed, null, null, 10, false);
            Assert.AreEqual(1, list.Count);
        }

        [TestMethod]
        public void Fuzz_PrefixBounds_NoBleed_And_Order()
        {
            var rnd = new Random(1337);
            int seedCount = 5;
            int perSeed = 200;

            // Prepare distinct seeds
            var seeds = Enumerable.Range(0, seedCount)
                                  .Select(i => FixedSeed16((byte)(0xA0 + i)))
                                  .ToArray();

            // Gather ground truth per seed in insertion order (we’ll control ts)
            var enumTypes = Enum.GetValues(typeof(ActivityType)).Cast<ActivityType>().ToArray();
            var enumStatuses = Enum.GetValues(typeof(ActivityStatus)).Cast<ActivityStatus>().ToArray();

            var truth = new Dictionary<string, List<ActivityObject>>();

            long tsBase = Clock.getTimestamp();
            ulong block = 1;

            foreach (var s in seeds)
            {
                var list = new List<ActivityObject>(perSeed);
                for (int i = 0; i < perSeed; i++)
                {
                    var t = enumTypes[rnd.Next(enumTypes.Length)];
                    var st = enumStatuses[rnd.Next(enumStatuses.Length)];

                    // strictly increasing ts per seed
                    long ts = tsBase + i + rnd.Next(0, 2); // tiny jitter but monotonic by i
                    var ao = MakeActivity(s, block++, t, st, (i + 1).ToString(), ts: ts);
                    Assert.IsTrue(db.insertActivity(ao));
                    Thread.Sleep(2);
                    list.Add(ao);
                }
                truth[Convert.ToBase64String(s)] = list;
                tsBase += 10000; // separate per-seed time ranges
            }

            // 1) Asc/Desc full scans per seed: count and order must match ground truth
            foreach (var s in seeds)
            {
                var key = Convert.ToBase64String(s);
                var expectedAsc = truth[key];
                var asc = db.getActivitiesBySeedHashAndType(s, null, null, 10000, false);
                Assert.AreEqual(expectedAsc.Count, asc.Count, "asc count mismatch");
                for (int i = 0; i < asc.Count; i++)
                {
                    Assert.IsTrue(asc[i].id.SequenceEqual(expectedAsc[i].id), $"asc order mismatch at {i}");
                    // guard against bleed
                    Assert.IsTrue(asc[i].seedHash.SequenceEqual(s), "asc seed bleed detected");
                }

                var expectedDesc = expectedAsc.AsEnumerable().Reverse().ToList();
                var desc = db.getActivitiesBySeedHashAndType(s, null, null, 10000, true);
                Assert.AreEqual(expectedDesc.Count, desc.Count, "desc count mismatch");
                for (int i = 0; i < desc.Count; i++)
                {
                    Assert.IsTrue(desc[i].id.SequenceEqual(expectedDesc[i].id), $"desc order mismatch at {i}");
                    Assert.IsTrue(desc[i].seedHash.SequenceEqual(s), "desc seed bleed detected");
                }
            }

            // 2) Pagination from a middle key (exclusive), both directions
            foreach (var s in seeds)
            {
                var key = Convert.ToBase64String(s);
                var expected = truth[key];
                int mid = expected.Count / 2;
                var from = expected[mid];

                var ascPage = db.getActivitiesBySeedHashAndType(s, null, fromActivityId: from.id, count: 10000, descending: false);
                var expAscPage = expected.Skip(mid + 1).ToList();
                Assert.AreEqual(expAscPage.Count, ascPage.Count, "asc page size mismatch");
                for (int i = 0; i < ascPage.Count; i++)
                    Assert.IsTrue(ascPage[i].id.SequenceEqual(expAscPage[i].id), $"asc page mismatch at {i}");

                var descPage = db.getActivitiesBySeedHashAndType(s, null, fromActivityId: from.id, count: 10000, descending: true);
                var expDescPage = expected.Take(mid).Reverse().ToList();
                Assert.AreEqual(expDescPage.Count, descPage.Count, "desc page size mismatch");
                for (int i = 0; i < descPage.Count; i++)
                    Assert.IsTrue(descPage[i].id.SequenceEqual(expDescPage[i].id), $"desc page mismatch at {i}");
            }

            // 3) Type filter correctness
            foreach (var s in seeds)
            {
                var key = Convert.ToBase64String(s);
                var expected = truth[key];

                var anyType = expected[rnd.Next(expected.Count)].type;
                var expFiltered = expected.Where(x => x.type == anyType).ToList();

                var got = db.getActivitiesBySeedHashAndType(s, anyType, null, 10000, false);
                Assert.AreEqual(expFiltered.Count, got.Count, "type filter count mismatch");
                for (int i = 0; i < got.Count; i++)
                    Assert.IsTrue(got[i].id.SequenceEqual(expFiltered[i].id), $"type filter order mismatch at {i}");
            }

            // 4) fromKey from a DIFFERENT seed should be ignored (start at range edge)
            var s0 = seeds[0];
            var s1 = seeds[1];
            var foreignFrom = truth[Convert.ToBase64String(s1)][truth[Convert.ToBase64String(s1)].Count / 2].id;

            var ascForeign = db.getActivitiesBySeedHashAndType(s0, null, fromActivityId: foreignFrom, count: 3, descending: false);
            var expectFirst3 = truth[Convert.ToBase64String(s0)].Take(3).ToList();
            Assert.AreEqual(expectFirst3.Count, ascForeign.Count);
            for (int i = 0; i < ascForeign.Count; i++)
                Assert.IsTrue(ascForeign[i].id.SequenceEqual(expectFirst3[i].id), $"asc foreign fromKey mismatch at {i}");

            var descForeign = db.getActivitiesBySeedHashAndType(s0, null, fromActivityId: foreignFrom, count: 3, descending: true);
            var expectLast3 = truth[Convert.ToBase64String(s0)].AsEnumerable().Reverse().Take(3).ToList();
            Assert.AreEqual(expectLast3.Count, descForeign.Count);
            for (int i = 0; i < descForeign.Count; i++)
                Assert.IsTrue(descForeign[i].id.SequenceEqual(expectLast3[i].id), $"desc foreign fromKey mismatch at {i}");
        }

        [TestMethod]
        public void Fuzz_Small_Pagination_Window()
        {
            var seed = FixedSeed16(0xF1);
            var t = AnyActivityType();
            var s = AnyStatus();

            var inserted = new List<ActivityObject>();
            for (int i = 0; i < 25; i++)
            {
                long ts = Clock.getTimestamp() + i;
                var ao = MakeActivity(seed, (ulong)(1000 + i), t, s, i.ToString(), ts: ts);
                Assert.IsTrue(db.insertActivity(ao));
                Thread.Sleep(3);
                inserted.Add(ao);
            }

            var ordered = inserted.OrderBy(x => x.timestamp)
                                  .ThenBy(x => (short)x.type)
                                  .ThenBy(x => BitConverter.ToString(x.id))
                                  .ToList();

            // page size 7 forward
            byte[] cursor = null;
            int offset = 0;
            for (int round = 0; round < 4; round++)
            {
                var page = db.getActivitiesBySeedHashAndType(seed, null, fromActivityId: cursor, count: 7, descending: false);
                var expected = ordered.Skip(offset + (cursor == null ? 0 : 1)).Take(7).ToList();
                Assert.AreEqual(expected.Count, page.Count);
                for (int i = 0; i < page.Count; i++)
                    Assert.IsTrue(page[i].id.SequenceEqual(expected[i].id));
                if (page.Count == 0) break;
                cursor = page.Last().id;
                offset = ordered.FindIndex(x => x.id.SequenceEqual(cursor));
            }

            // page size 5 backward
            cursor = ordered[12].id; // pick a middle item as exclusive start
            var backwardExpected = ordered.Take(12).Reverse().ToList(); // items before it
            int consumed = 0;
            while (consumed < backwardExpected.Count)
            {
                var page = db.getActivitiesBySeedHashAndType(seed, null, fromActivityId: cursor, count: 5, descending: true);
                var exp = backwardExpected.Skip(consumed).Take(5).ToList();
                Assert.AreEqual(exp.Count, page.Count);
                for (int i = 0; i < page.Count; i++)
                    Assert.IsTrue(page[i].id.SequenceEqual(exp[i].id));
                if (page.Count == 0) break;
                cursor = page.Last().id;
                consumed += page.Count;
            }
        }

    }
}

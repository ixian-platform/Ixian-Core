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
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

#if ANDROID
using Android.App;
using Android.Content;
#endif

#if IOS || MACCATALYST
using Foundation;
#endif
namespace IXICore.Utils
{
    public interface IMemoryInfoProvider
    {
        /// <summary>
        /// Returns total system RAM in bytes.
        /// Returns 0 if not supported.
        /// </summary>
        long GetTotalRAM();
    }

    public class MemoryInfoProvider : IMemoryInfoProvider
    {
        public long GetTotalRAM()
        {
#if WINDOWS
            return GetWindowsTotalRAM();
#elif LINUX
        return GetLinuxTotalRAM();
#elif OSX
        return GetMacTotalRAM();
#elif ANDROID
        return GetAndroidTotalRAM();
#elif IOS || MACCATALYST
        return GetIOSTotalRAM();
#else
            return 0; // fallback
#endif
        }

#if WINDOWS
        private static long GetWindowsTotalRAM()
        {
            var memStatus = new MEMORYSTATUSEX();
            return GlobalMemoryStatusEx(memStatus) ? (long)memStatus.ullTotalPhys : 0;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private class MEMORYSTATUSEX
        {
            public uint dwLength = (uint)Marshal.SizeOf(typeof(MEMORYSTATUSEX));
            public uint dwMemoryLoad;
            public ulong ullTotalPhys;
            public ulong ullAvailPhys;
            public ulong ullTotalPageFile;
            public ulong ullAvailPageFile;
            public ulong ullTotalVirtual;
            public ulong ullAvailVirtual;
            public ulong ullAvailExtendedVirtual;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GlobalMemoryStatusEx([In, Out] MEMORYSTATUSEX buffer);
#endif

#if LINUX
    private static long GetLinuxTotalRAM()
    {
        try
        {
            foreach (var line in File.ReadLines("/proc/meminfo"))
            {
                if (line.StartsWith("MemTotal:"))
                {
                    var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    if (long.TryParse(parts[1], out long kb))
                        return kb * 1024;
                }
            }
        }
        catch { }
        return 0;
    }
#endif

#if OSX
    private static long GetMacTotalRAM()
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "sysctl",
                Arguments = "hw.memsize",
                RedirectStandardOutput = true
            };
            using var proc = Process.Start(psi)!;
            string output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit();

            if (output.Contains(":") &&
                long.TryParse(output.Split(':')[1].Trim(), out long bytes))
            {
                return bytes;
            }
        }
        catch { }
        return 0;
    }
#endif

#if ANDROID
    private static long GetAndroidTotalRAM()
    {
        try
        {
            ActivityManager.MemoryInfo mi = new ActivityManager.MemoryInfo();
            var activityManager = (ActivityManager)Android.App.Application.Context.GetSystemService(Context.ActivityService)!;
            activityManager.GetMemoryInfo(mi);
            return mi.TotalMem;
        }
        catch { return 0; }
    }
#endif

#if IOS || MACCATALYST
    private static long GetIOSTotalRAM()
    {
        try
        {
            return (long)NSProcessInfo.ProcessInfo.PhysicalMemory;
        }
        catch { return 0; }
    }
#endif
    }
}

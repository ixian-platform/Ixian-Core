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
        // Windows 10+ supports this
        return new Microsoft.VisualBasic.Devices.ComputerInfo().TotalPhysicalMemory;
    }
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
            var activityManager = (ActivityManager)Application.Context.GetSystemService(Context.ActivityService)!;
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

// Copyright (C) 2017-2020 Ixian OU
// This file is part of Ixian Core - www.github.com/ProjectIxian/Ixian-Core
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
using System.IO;
using System.Runtime.InteropServices;

namespace IXICore
{
    /// <summary>
    ///  Platform-specific utilities.
    /// </summary>
    class Platform
    {
        /// <summary>
        /// Get the Operating System name and Version.
        /// Example: "Microsoft Windows 10.0.10586"
        /// Example: "Linux 5.15.0-46-generic #49-Ubuntu SMP Thu Aug 4 18:03:25 UTC 2022"
        /// </summary>
        /// <returns>OS name and version</returns>
        public static string getOSNameAndVersion()
        {
            return RuntimeInformation.OSDescription;
        }

        /// <summary>
        /// Checks if the DLT is running on a Windows operating system.
        /// </summary>
        /// <returns>True, if the program is executing on Windows</returns>
        public static bool onWindows()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
        }

        /// <summary>
        /// Checks if the DLT is running on a Linux operating system.
        /// </summary>
        /// <returns>True, if the program is executing on Linux</returns>
        public static bool onLinux()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Linux);
        }

        /// <summary>
        /// Checks if the DLT is running on a BSD operating system.
        /// </summary>
        /// <returns>True, if the program is executing on BSD</returns>
        public static bool onBSD()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.FreeBSD);
        }

        /// <summary>
        /// Checks if the DLT is running on a Mac operating system.
        /// </summary>
        /// <returns>True, if the program is executing on Mac</returns>
        public static bool onMac()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.OSX);
        }

        /// <summary>
        ///  Checks if the DLT is running on Mono.
        /// </summary>
        /// <remarks>
        ///  This is useful when certain features of the .NET framework are not implemented, or work differently on Mono vs. Microsoft.NET.
        /// </remarks>
        /// <returns>True, if the program is executing under Mono.</returns>
        public static bool onMono()
        {
            return Type.GetType("Mono.Runtime") != null;
        }

        /// <summary>
        ///  Returns the number of available disk space bytes for the specified directory.
        /// </summary>
        /// <remarks>
        ///  This function detects the specified folder's root path disk and returns the available free space
        /// </remarks>
        /// <returns>Number of available disk space bytes as a long or -1 on error</returns>
        public static long getAvailableDiskSpace(string directory)
        {
            try
            {
                string root = Path.GetPathRoot(Path.GetFullPath(directory));

                var drive = new DriveInfo(root);
                if (drive.IsReady)
                {
                    return drive.AvailableFreeSpace > 0 ? drive.AvailableFreeSpace : 0;
                }
            }
            catch
            {
            }
            return -1;
        }
    }
}

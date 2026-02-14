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

using IXICore.Meta;
using Mono.Nat;
using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace IXICore
{
    public class UPnP
    {
        private INatDevice? _routerDevice;
        private int _mappedPublicPort;

        private bool AcquireRouterDevice()
        {
            if (_routerDevice != null)
            {
                return true;
            }

            try
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                _routerDevice = DiscoverAsync(cts.Token).GetAwaiter().GetResult();

                if (_routerDevice != null)
                {
                    Logging.info($"Found UPnP device: {_routerDevice}");
                    return true;
                }
            }
            catch { }

            return false;
        }

        private static Task<INatDevice> DiscoverAsync(CancellationToken ct)
        {
            var tcs = new TaskCompletionSource<INatDevice>(
                TaskCreationOptions.RunContinuationsAsynchronously);

            void Handler(object? sender, DeviceEventArgs e)
            {
                NatUtility.DeviceFound -= Handler;
                NatUtility.StopDiscovery();
                tcs.TrySetResult(e.Device);
            }

            NatUtility.DeviceFound += Handler;
            NatUtility.StartDiscovery();

            ct.Register(() =>
            {
                NatUtility.DeviceFound -= Handler;
                NatUtility.StopDiscovery();
                tcs.TrySetCanceled(ct);
            });

            return tcs.Task;
        }

        private Mapping? GetPublicPortMappingInternal(int publicPort)
        {
            if (!AcquireRouterDevice())
            {
                return null;
            }

            try
            {
                foreach (var m in _routerDevice.GetAllMappings())
                {
                    if (m.PublicPort == publicPort)
                    {
                        return m;
                    }
                }
            }
            catch (Exception ex)
            {
                Logging.warn($"Error while obtaining current port mapping: {ex.Message}");
            }

            return null;
        }

        public async Task<IPAddress?> GetExternalIPAddress()
        {
            Logging.info("Attempting to discover external address via UPnP...");
            Logging.info("This may take up to 10 seconds...");

            if (!AcquireRouterDevice())
            {
                Logging.info("UPnP router not present or incompatible.");
                return null;
            }

            try
            {
                IPAddress externalIP = await _routerDevice!.GetExternalIPAsync();
                Logging.info($"Found external IP address: {externalIP}");
                return await Task.FromResult(externalIP);
            }
            catch (Exception ex)
            {
                Logging.warn($"Error while retrieving the external IP: {ex}");
                return null;
            }
        }

        public Mapping? GetPublicPortMapping(int publicPort)
        {
            if (publicPort <= 0 || publicPort > 65535)
            {
                Logging.error($"Invalid port number: {publicPort}");
                return null;
            }

            Logging.info($"Attempting to discover existing NAT port mapping for port {publicPort}.");

            return GetPublicPortMappingInternal(publicPort);
        }

        public bool MapPublicPort(int publicPort, IPAddress localIP)
        {
            if (publicPort <= 0 || publicPort > 65535)
            {
                Logging.error($"Invalid port number: {publicPort}");
                return false;
            }

            Logging.info($"Attempting to map external port {publicPort} to local IP {localIP}");

            if (!AcquireRouterDevice())
            {
                Logging.info("UPnP router not present or incompatible.");
                return false;
            }

            try
            {
                var mapping = new Mapping(
                    Protocol.Tcp,
                    publicPort,
                    publicPort,
                    0,
                    "Ixian DLT automatic port mapping"
                );

                _routerDevice.CreatePortMap(mapping);

                Logging.info($"External port {publicPort} mapped to {localIP}:{publicPort}");
                _mappedPublicPort = publicPort;
                return true;
            }
            catch (Exception ex)
            {
                Logging.error($"Error while mapping public port {publicPort}: {ex.Message}");
                return false;
            }
        }

        public void RemoveMapping()
        {
            if (_routerDevice == null)
            {
                return;
            }

            Logging.info($"Removing previously mapped: {_mappedPublicPort} -> {_mappedPublicPort}");

            try
            {
                var m = GetPublicPortMappingInternal(_mappedPublicPort);
                if (m != null)
                {
                    _routerDevice.DeletePortMap(m);
                    _mappedPublicPort = 0;
                }
            }
            catch (Exception ex)
            {
                Logging.error(
                    $"Unable to remove port mapping for public port {_mappedPublicPort}: {ex.Message}");
            }
        }
    }
}

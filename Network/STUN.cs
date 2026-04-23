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

using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace IXICore.Network
{
    public class STUN
    {
        private int port;
        private CancellationTokenSource? cts;
        private Task? serverTask;

        public STUN(int port = 3478)
        {
            this.port = port;
        }

        public async Task StartServer()
        {
            if (cts != null)
            {
                return;
            }

            cts = new CancellationTokenSource();
            serverTask = Task.Run(() => ServerLoop(cts.Token));
        }

        public async Task StopServer()
        {
            if (cts == null)
            {
                return;
            }

            Task? serverTaskCopy = serverTask;
            var ctsCopy = cts;
            ctsCopy?.Cancel();
            cts = null;
            serverTask = null;

            try
            {
                serverTaskCopy?.GetAwaiter().GetResult();
            }
            catch (OperationCanceledException) { }
            finally
            {
                ctsCopy?.Dispose();
            }

        }

        public async Task ServerLoop(CancellationToken ct)
        {
            using var udpClient = new UdpClient(port);

            while (!ct.IsCancellationRequested)
            {
                var received = await udpClient.ReceiveAsync(ct);
                var buffer = received.Buffer;

                // 1. Basic STUN Header Validation (RFC 5389)
                if (buffer.Length < 20 || buffer[0] != 0x00 || buffer[1] != 0x01) continue;

                // 2. Extract Transaction ID (12 bytes starting at index 8)
                byte[] transactionId = new byte[12];
                Array.Copy(buffer, 8, transactionId, 0, 12);

                // 3. Construct XOR-MAPPED-ADDRESS (Type: 0x0020)
                // Magic Cookie (0x2112A442) used for XOR-ing
                byte[] magicCookie = new byte[] { 0x21, 0x12, 0xA4, 0x42 };
                var remoteIp = received.RemoteEndPoint.Address.GetAddressBytes();
                var remotePort = BitConverter.GetBytes((ushort)received.RemoteEndPoint.Port);
                if (BitConverter.IsLittleEndian) Array.Reverse(remotePort);

                // XOR Port and IP
                byte[] xorPort = new byte[] { (byte)(remotePort[0] ^ magicCookie[0]), (byte)(remotePort[1] ^ magicCookie[1]) };
                byte[] xorIp = new byte[4];
                for (int i = 0; i < 4; i++) xorIp[i] = (byte)(remoteIp[i] ^ magicCookie[i]);

                // 4. Build Response Packet
                // Header: Type (0x0101 = Success), Length (12 bytes payload), Cookie, TransID
                var response = new List<byte> { 0x01, 0x01, 0x00, 0x0C };
                response.AddRange(magicCookie);
                response.AddRange(transactionId);

                // Attribute: Type (0x0020), Length (8), Reserved (0x00), Family (0x01 = IPv4), XOR Port, XOR IP
                response.AddRange(new byte[] { 0x00, 0x20, 0x00, 0x08, 0x00, 0x01 });
                response.AddRange(xorPort);
                response.AddRange(xorIp);

                await udpClient.SendAsync(response.ToArray(), received.RemoteEndPoint, ct);
            }
        }
    }
}

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

using Force.Crc32;
using IXICore.Inventory;
using IXICore.Meta;
using IXICore.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace IXICore.Network
{
    public enum MessagePriority
    {
        auto = 0,
        low = 10,
        medium = 20,
        high = 30
    }

    public class TimeSyncData
    {
        public long timeDifference = 0;
        public long remoteTime = 0;
        public long processedTime = 0;
    }

    public class RemoteEndpoint : IAsyncDisposable
    {
        class MessageHeader
        {
            public ProtocolMessageCode code;
            public uint dataLen;
            public uint dataChecksum;
            public byte[]? legacyDataChecksum;
        }

        public string fullAddress = "127.0.0.1:0";
        public string address = "127.0.0.1";
        public int incomingPort = 0;

        public long connectionStartTime = 0;

        public long timeDifference = 0;
        public bool timeSyncComplete = false;

        public bool helloReceived = false;
        public ulong blockHeight = 0;

        protected long lastDataReceivedTime = 0;
        protected long lastDataSentTime = 0;

        public IPEndPoint? remoteIP;
        public Socket? clientSocket;

        private object startLock = new();

        private CancellationTokenSource? cts;

        // Maintain tasks for handling data receiving and sending
        protected Task? recvTask = null;
        protected Task? sendTask = null;
        protected Task? parseTask = null;

        public Presence? presence = null;
        public PresenceAddress? presenceAddress = null;

        public bool running { get; protected set; } = false;

        // Maintain a list of subscribed event addresses with event type
        private Dictionary<NetworkEvents.Type, Cuckoo> subscribedFilters = new Dictionary<NetworkEvents.Type, Cuckoo>();

        private readonly int capacity;

        // Maintain a queue of messages to send
        private Channel<QueueMessage>? sendQueueMessagesHighPriority;
        private Channel<QueueMessage>? sendQueueMessagesNormalPriority;
        private Channel<QueueMessage>? sendQueueMessagesLowPriority;

        private const int dedupSize = 10;
        private readonly Queue<long> recentIds = new();
        private readonly HashSet<long> recentIdsSet = new();

        private long requestedIdsSize = CoreConfig.maximumRequestedMessageIds;
        private readonly Queue<long> requestedIds = new();
        private readonly HashSet<long> requestedIdsSet = new();

        // Maintain a queue of raw received data
        private Channel<QueueMessageRaw?>? recvRawQueueMessages;

        private Memory<byte> socketReadBuffer;

        protected List<TimeSyncData> timeSyncs = new List<TimeSyncData>();

        protected bool enableSendTimeSyncMessages = true;

        private List<InventoryItem> inventory = new List<InventoryItem>();
        private long inventoryLastSent = 0;

        public Address? serverWalletAddress = null;
        public byte[]? serverPubKey = null;

        public byte[]? challenge = null;

        public int version = 6;

        public bool reconnectOnFailure = true;

        protected Action<QueueMessageRaw, MessagePriority, RemoteEndpoint>? messageHandler;

        public IxianKeyPair? ephemeralKeyPair = null;

        public RemoteEndpoint(Action<QueueMessageRaw, MessagePriority, RemoteEndpoint>? handler = null,
                              int capacityPerQueue = 10000)
        {
            messageHandler = handler;
            capacity = capacityPerQueue;
            socketReadBuffer = new Memory<byte>(new byte[64 * 1024]);
        }

        protected void prepareSocket(Socket socket)
        {
            // The socket will linger for 3 seconds after 
            // Socket.Close is called.
            socket.LingerState = new LingerOption(true, 3);

            // Disable the Nagle Algorithm for this tcp socket.
            socket.NoDelay = true;

            socket.ReceiveTimeout = 120000;
            //socket.ReceiveBufferSize = 1024 * 64;
            //socket.SendBufferSize = 1024 * 64;
            socket.SendTimeout = 120000;

            socket.Blocking = true;
        }

        public void start(Socket socket)
        {
            lock (startLock)
            {
                if (running)
                {
                    throw new InvalidOperationException("Can't start already running RemoteEndpoint");
                }

                clientSocket = socket ?? throw new ArgumentNullException("Could not start NetworkRemoteEndpoint, socket is null");

                cts = new CancellationTokenSource();

                recvRawQueueMessages = CreateBoundedChannel<QueueMessageRaw?>(capacity);
                sendQueueMessagesHighPriority = CreateBoundedChannel<QueueMessage>(capacity);
                sendQueueMessagesNormalPriority = CreateBoundedChannel<QueueMessage>(capacity);
                sendQueueMessagesLowPriority = CreateBoundedChannel<QueueMessage>(capacity);

                prepareSocket(clientSocket);

                remoteIP = (IPEndPoint)clientSocket.RemoteEndPoint;
                address = remoteIP.Address.ToString();
                if (remoteIP.Address.IsIPv4MappedToIPv6 && address.StartsWith("::FFFF:", StringComparison.OrdinalIgnoreCase))
                {
                    address = address.Substring(7);
                }
                fullAddress = address + ":" + remoteIP.Port;
                presence = null;
                presenceAddress = null;

                connectionStartTime = Clock.getTimestamp();

                lock (subscribedFilters)
                {
                    subscribedFilters.Clear();
                }

                lastDataReceivedTime = Clock.getTimestamp();
                lastDataSentTime = Clock.getTimestamp();

                timeDifference = 0;
                timeSyncComplete = false;
                timeSyncs.Clear();

                running = true;

                // Start parse thread
                parseTask = Task.Run(() => parseLoop(cts.Token));

                // Start send thread
                sendTask = Task.Run(() => sendLoop(cts.Token));

                // Start receive thread
                recvTask = Task.Run(() => recvLoop(cts.Token));
            }
        }

        // Aborts all related endpoint threads and data
        public virtual async Task stopAsync()
        {
            List<Task> tasks = new();
            Socket? socket = clientSocket;
            var ctsCopy = cts;
            lock (startLock)
            {
                if (!running)
                {
                    Logging.warn("Attempting to stop a RemoteEndpoint that is not running.");
                    return;
                }

                running = false;

                cts?.Cancel();
                cts = null;
                recvRawQueueMessages?.Writer.TryComplete();
                sendQueueMessagesHighPriority?.Writer.TryComplete();
                sendQueueMessagesNormalPriority?.Writer.TryComplete();
                sendQueueMessagesLowPriority?.Writer.TryComplete();
                recvRawQueueMessages = null;
                sendQueueMessagesHighPriority = null;
                sendQueueMessagesNormalPriority = null;
                sendQueueMessagesLowPriority = null;

                if (sendTask != null)
                {
                    tasks.Add(sendTask);
                    sendTask = null;
                }
                if (parseTask != null)
                {
                    tasks.Add(parseTask);
                    parseTask = null;
                }
                if (recvTask != null)
                {
                    tasks.Add(recvTask);
                    recvTask = null;
                }

                lock (subscribedFilters)
                {
                    subscribedFilters.Clear();
                }

                lock (inventory)
                {
                    inventory.Clear();
                }

                cts = null;
                clientSocket = null;
            }

            try
            {
                await Task.WhenAll(tasks).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // expected
            }
            finally
            {
                ctsCopy?.Dispose();
            }

            // Close the client socket
            try
            {
                if (socket != null
                    && socket.Connected)
                {
                    socket.Shutdown(SocketShutdown.Both);
                }
            }
            catch (ObjectDisposedException)
            {
                // Already disposed, ignore
            }
            catch (Exception e)
            {
                Logging.warn("Disconnect: Socket error during shutdown: {0}", e.Message);
            }

            try
            {
                socket?.Close();
            }
            catch (Exception e)
            {
                Logging.warn("Disconnect: Error closing client socket: {0}", e.Message);
            }
        }

        protected void requestStop()
        {
            lock (startLock)
            {
                cts?.Cancel();
                recvRawQueueMessages?.Writer.TryComplete();
            }
        }

        // Receive thread
        protected async Task recvLoop(CancellationToken ct)
        {
            var socket = clientSocket!;
            var recvWriter = recvRawQueueMessages!.Writer;
            try
            {
                long lastReceivedMessageStatTime = Clock.getTimestampMillis();
                while (!ct.IsCancellationRequested)
                {
                    // Let the protocol handler receive and handle messages
                    bool message_received = false;
                    QueueMessageRaw? raw_msg = await readSocketData(ct).ConfigureAwait(false);
                    if (raw_msg != null)
                    {
                        message_received = true;
                        recvWriter.TryWrite(raw_msg);
                    }

                    // Check if the client disconnected
                    if (ct.IsCancellationRequested)
                    {
                        break;
                    }

                    // Sleep a while to throttle the client
                    // Check if there are too many messages
                    // TODO TODO TODO this can be handled way better
                    int total_message_count = NetworkQueue.getQueuedMessageCount();
                    if (total_message_count > 10000)
                    {
                        await Task.Delay(1000).ConfigureAwait(false);
                    }
                    else if (total_message_count > 5000)
                    {
                        await Task.Delay(500).ConfigureAwait(false);
                    }
                    else if (!message_received)
                    {
                        await Task.Delay(10).ConfigureAwait(false);
                    }
                }
            }
            catch (SocketException se)
            {
                if (isConnected())
                {
                    if (se.SocketErrorCode != SocketError.ConnectionAborted
                        && se.SocketErrorCode != SocketError.NotConnected
                        && se.SocketErrorCode != SocketError.ConnectionReset
                        && se.SocketErrorCode != SocketError.Interrupted)
                    {
                        Logging.warn("recvRE: Disconnected client {0} with socket exception {1} {2} {3}", getFullAddress(), se.SocketErrorCode, se.ErrorCode, se);
                    }
                }
            }
            catch (OperationCanceledException)
            {
                // Normal shutdown
            }
            catch (Exception e)
            {
                Logging.warn("recvRE: Disconnected client {0} with exception {1}", getFullAddress(), e);
            }
            requestStop();
        }

        protected virtual void onInitialized()
        {

        }

        protected async Task sendTimeSyncMessages(Socket socket, CancellationToken ct)
        {
            byte[] buffer = new byte[1 + 8]; // 0x02 + timestamp

            buffer[0] = 0x02;

            for (int i = 0; i < 5 && !ct.IsCancellationRequested; i++)
            {
                long ts = Clock.getNetworkTimestampMillis();

                // write timestamp (little endian)
                buffer[1] = (byte)ts;
                buffer[2] = (byte)(ts >> 8);
                buffer[3] = (byte)(ts >> 16);
                buffer[4] = (byte)(ts >> 24);
                buffer[5] = (byte)(ts >> 32);
                buffer[6] = (byte)(ts >> 40);
                buffer[7] = (byte)(ts >> 48);
                buffer[8] = (byte)(ts >> 56);

                int sent = 0;

                while (sent < buffer.Length)
                {
                    sent += await socket.SendAsync(
                        new ArraySegment<byte>(buffer, sent, buffer.Length - sent),
                        SocketFlags.None,
                        ct).ConfigureAwait(false);
                }
            }
        }

        // Send thread
        protected async Task sendLoop(CancellationToken ct)
        {
            var socket = clientSocket!;
            var highReader = sendQueueMessagesHighPriority!.Reader;
            var mediumReader = sendQueueMessagesNormalPriority!.Reader;
            var lowReader = sendQueueMessagesLowPriority!.Reader;
            try
            {
                if (enableSendTimeSyncMessages)
                {
                    await sendTimeSyncMessages(socket, ct).ConfigureAwait(false);
                }

                int messageCount = 0;

                lastDataReceivedTime = Clock.getTimestamp();
                lastDataSentTime = Clock.getTimestamp();

                onInitialized();

                bool moreInventoryItemsPending = false;

                while (!ct.IsCancellationRequested)
                {
                    long curTime = Clock.getTimestamp();
                    if (helloReceived == false && curTime - connectionStartTime > 10)
                    {
                        // haven't received hello message for 10 seconds, stop running
                        Logging.info("Node {0} hasn't received hello data from remote endpoint for over 10 seconds, disconnecting.", getFullAddress());
                        break;
                    }
                    if (curTime - lastDataReceivedTime > CoreConfig.pingTimeout)
                    {
                        // haven't received any data for 10 seconds, stop running
                        Logging.warn("Node {0} hasn't received any data from remote endpoint for over {1} seconds, disconnecting.", getFullAddress(), CoreConfig.pingTimeout);
                        break;
                    }
                    if (curTime - lastDataSentTime > CoreConfig.pongInterval)
                    {
                        await socket.SendAsync(new byte[1] { 1 }, SocketFlags.None, ct).ConfigureAwait(false);
                        lastDataSentTime = curTime;
                        continue;
                    }

                    bool messageFound = false;
                    QueueMessage msg;

                    if ((messageCount % 5 == 0) &&
                        lowReader.TryRead(out msg))
                    {
                        messageFound = true;
                    }
                    else if ((messageCount % 3 == 0) &&
                             mediumReader.TryRead(out msg))
                    {
                        messageFound = true;

                    }
                    else if (highReader.TryRead(out msg) ||
                             mediumReader.TryRead(out msg) ||
                             lowReader.TryRead(out msg))
                    {
                        messageFound = true;

                    }

                    if (messageFound)
                    {
                        messageCount++;

                        await sendDataInternal(socket, msg.code, msg.data, msg.checksum, ct).ConfigureAwait(false);

                        if (msg.code == ProtocolMessageCode.bye)
                        {
                            reconnectOnFailure = false;
                            requestStop();
                            break;
                        }
                    }
                    else if (!moreInventoryItemsPending)
                    {
                        // wait until ANY channel has data OR timeout for housekeeping
                        var waitTask = Task.WhenAny(
                            highReader.WaitToReadAsync(ct).AsTask(),
                            mediumReader.WaitToReadAsync(ct).AsTask(),
                            lowReader.WaitToReadAsync(ct).AsTask(),
                            Task.Delay(1000, ct)
                        );

                        await waitTask.ConfigureAwait(false);
                    }

                    moreInventoryItemsPending = await sendInventory(socket, ct).ConfigureAwait(false);

                    if (messageCount > 100)
                    {
                        messageCount = 0;
                    }
                }
            }
            catch (SocketException se)
            {
                if (isConnected())
                {
                    if (se.SocketErrorCode != SocketError.ConnectionAborted
                        && se.SocketErrorCode != SocketError.NotConnected
                        && se.SocketErrorCode != SocketError.ConnectionReset
                        && se.SocketErrorCode != SocketError.Interrupted)
                    {
                        Logging.warn("recvRE: Disconnected client {0} with socket exception {1} {2} {3}", getFullAddress(), se.SocketErrorCode, se.ErrorCode, se);
                    }
                }
            }
            catch (OperationCanceledException)
            {
                // Normal shutdown
            }
            catch (Exception e)
            {
                Logging.error("SendLoop exception: {0}", e);
            }
            requestStop();
        }

        public void addInventoryItem(InventoryItem item)
        {
            lock (inventory)
            {
                inventory.Add(item);
            }
        }

        protected async Task<bool> sendInventory(Socket socket, CancellationToken ct)
        {
            List<InventoryItem> itemsToSend;
            bool morePending = false;
            lock (inventory)
            {
                int count = inventory.Count;
                if (count == 0)
                    return false;

                long curTime = Clock.getTimestamp();

                if (count < CoreConfig.maxInventoryItems &&
                    inventoryLastSent > curTime - CoreConfig.inventoryInterval)
                    return false;

                inventoryLastSent = curTime;

                int takeCount = Math.Min(count, CoreConfig.maxInventoryItems);

                itemsToSend = inventory.GetRange(0, takeCount);
                inventory.RemoveRange(0, takeCount);

                if (inventory.Count > 0)
                {
                    morePending = true;
                }
            }

            // Rough size estimate to reduce reallocations
            int estimatedSize = 3 + itemsToSend.Count * 140;
            byte[] buffer = new byte[estimatedSize];
            int offset = 0;

            // Write item count (varint)
            offset += IxiVarInt.WriteIxiVarInt(buffer.AsSpan(offset), itemsToSend.Count);

            foreach (var item in itemsToSend)
            {
                byte[] itemBytes = item.getBytes();

                // Ensure capacity
                if (offset + itemBytes.Length + 3 > buffer.Length)
                {
                    Array.Resize(ref buffer, Math.Max(buffer.Length * 2, offset + itemBytes.Length + 3));
                }

                offset += IxiVarInt.WriteIxiVarInt(buffer.AsSpan(offset), itemBytes.Length);

                itemBytes.CopyTo(buffer, offset);
                offset += itemBytes.Length;
            }

            await sendDataInternal(socket, ProtocolMessageCode.inventory2, buffer.AsMemory(0, offset), 0, ct).ConfigureAwait(false);

            return morePending;
        }

        // Parse thread
        protected async Task parseLoop(CancellationToken ct)
        {
            var reader = recvRawQueueMessages!.Reader;
            try
            {
                while (await reader.WaitToReadAsync(ct))
                {
                    while (reader.TryRead(out QueueMessageRaw? active_message_task))
                    {
                        if (!active_message_task.HasValue)
                        {
                            continue;
                        }

                        QueueMessageRaw active_message = active_message_task.Value;

                        // Active message set, add it to Network Queue
                        MessagePriority priority = MessagePriority.auto;
                        long msg_id = 0;
                        ulong last_bh = IxianHandler.getLastBlockHeight();
                        switch (active_message.code)
                        {
                            case ProtocolMessageCode.blockData2:
                                ulong bh = active_message.data.GetIxiVarUInt(active_message.data.GetIxiVarUInt(0).bytesRead).num;
                                if (bh == last_bh + 1)
                                {
                                    priority = MessagePriority.medium;
                                }
                                msg_id = (long)active_message.data.GetIxiVarUInt(active_message.data.GetIxiVarUInt(0).bytesRead).num;
                                break;

                            case ProtocolMessageCode.blockSignature2:
                            case ProtocolMessageCode.signaturesChunk2:
                                priority = MessagePriority.medium;
                                break;

                            case ProtocolMessageCode.transactionsChunk3:
                                msg_id = active_message.data.GetIxiVarInt(0).num;
                                if (msg_id == (long)last_bh + 1)
                                {
                                    priority = MessagePriority.medium;
                                }
                                break;

                            case ProtocolMessageCode.bye:
                                reconnectOnFailure = false;
                                requestStop();
                                break;
                        }

                        if (msg_id != 0)
                        {
                            if (!requestedIdsSet.Contains(msg_id > 0 ? msg_id : -msg_id))
                            {
                                Logging.warn("Received message with code {0}, message id {1} which was not requested.", active_message.code, msg_id);
                            }
                            else
                            {
                                priority = MessagePriority.medium;
                                if (msg_id > 0)
                                {
                                    requestedIdsSet.Remove(msg_id);
                                }
                            }
                        }
                        handleMessage(active_message, priority);
                    }
                }
            }
            catch (OperationCanceledException)
            {
                // Normal shutdown
            }
            catch (Exception e)
            {
                Logging.error("Exception occurred for client {0} in parseLoopRE: {1} ", getFullAddress(), e);
            }
            requestStop();
        }

        protected virtual void handleMessage(QueueMessageRaw message, MessagePriority priority)
        {
            if (messageHandler != null)
            {
                messageHandler(message, priority, this);
                return;
            }

            CoreProtocolMessage.readProtocolMessage(message, priority, this);
        }

        // Internal function that sends data through the socket
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        protected async ValueTask sendDataInternal(Socket socket,
                                                   ProtocolMessageCode code,
                                                   ReadOnlyMemory<byte> data,
                                                   uint checksum,
                                                   CancellationToken ct)
        {
            ArraySegment<byte> buffer = prepareProtocolMessage(code, data, version, checksum);

            int totalSent = 0;

            while (totalSent < buffer.Count)
            {
                ValueTask<int> sendTask = socket.SendAsync(
                    buffer.Slice(totalSent),
                    SocketFlags.None,
                    ct
                );

                int sent = sendTask.IsCompletedSuccessfully
                    ? sendTask.Result
                    : await sendTask.ConfigureAwait(false);

                if (sent == 0)
                    throw new SocketException((int)SocketError.ConnectionReset);

                totalSent += sent;

                lastDataSentTime = Clock.getTimestamp();
            }
        }

        // Sends data over the network
        public void sendData(ProtocolMessageCode code, byte[] data, long msgId = 0, MessagePriority priority = MessagePriority.auto)
        {
            if (data == null)
            {
                Logging.warn(string.Format("Invalid protocol message data for {0}", code));
                return;
            }

            QueueMessage message = getQueueMessage(code, data);
            sendData(message, msgId, priority);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private ChannelWriter<QueueMessage> GetAutoWriter(ProtocolMessageCode code)
        {
            return code switch
            {
                ProtocolMessageCode.bye or
                ProtocolMessageCode.keepAlivePresence or
                ProtocolMessageCode.getPresence2 or
                ProtocolMessageCode.getKeepAlives or
                ProtocolMessageCode.keepAlivesChunk or
                ProtocolMessageCode.updatePresence or
                ProtocolMessageCode.rejected or
                ProtocolMessageCode.getNameRecord or
                ProtocolMessageCode.nameRecord or
                ProtocolMessageCode.getSectorNodes or
                ProtocolMessageCode.sectorNodes or
                ProtocolMessageCode.s2data
                    => sendQueueMessagesHighPriority.Writer,

                ProtocolMessageCode.blockData2 or
                ProtocolMessageCode.blockHeaders4 or
                ProtocolMessageCode.transactionsChunk3 or
                ProtocolMessageCode.transactionData2 or
                ProtocolMessageCode.pitData2
                    => sendQueueMessagesLowPriority.Writer,

                _ => sendQueueMessagesNormalPriority.Writer
            };
        }


        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private bool TryCheckDuplicateMessage(long id)
        {
            if (id == 0) return true;

            if (recentIdsSet.Contains(id))
                return false;

            recentIds.Enqueue(id);
            recentIdsSet.Add(id);

            if (recentIds.Count > dedupSize)
            {
                var old = recentIds.Dequeue();
                recentIdsSet.Remove(old);
            }

            return true;
        }


        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private bool TryAddRequestedMessageId(long id)
        {
            if (id == 0) return false;

            if (requestedIdsSet.Contains(id))
                return false;

            requestedIds.Enqueue(id);
            requestedIdsSet.Add(id);

            if (requestedIds.Count > requestedIdsSize)
            {
                var old = requestedIds.Dequeue();
                requestedIdsSet.Remove(old);
            }

            return true;
        }

        public void sendData(QueueMessage message, long msgId = 0, MessagePriority priority = MessagePriority.auto)
        {
            if (!isConnected())
            {
                return;
            }

            if (message.code == ProtocolMessageCode.getBlock3)
            {
                msgId = message.data.GetIxiVarInt(0).num;
                priority = MessagePriority.high;
            }

            if (!TryCheckDuplicateMessage((long)message.code * message.checksum))
            {
                // Just check for now to catch any bugs with sending duplicate messages, we might want to remove this check later
                Logging.warn("Attempting to add a duplicate message (code: {0}) to the send queue for {1}", message.code, getFullAddress());
            }

            TryAddRequestedMessageId(msgId);

            var writer = priority switch
            {
                MessagePriority.high => sendQueueMessagesHighPriority.Writer,
                MessagePriority.medium => sendQueueMessagesNormalPriority.Writer,
                MessagePriority.low => sendQueueMessagesLowPriority.Writer,
                _ => GetAutoWriter(message.code)
            };

            writer.TryWrite(message);
        }

        static public QueueMessage getQueueMessage(ProtocolMessageCode code, byte[] data)
        {
            QueueMessage message = new QueueMessage();
            message.code = code;
            message.data = data;
            message.checksum = Crc32CAlgorithm.Compute(data);
            message.skipEndpoint = null;

            return message;
        }

        public int getHighPriorityMessageCount()
        {
            return sendQueueMessagesHighPriority!.Reader.Count;
        }

        public int getMediumPriorityMessageCount()
        {
            return sendQueueMessagesNormalPriority!.Reader.Count;
        }

        public int getLowPriorityMessageCount()
        {
            return sendQueueMessagesLowPriority!.Reader.Count;
        }

        public int getQueuedMessageCount()
        {
            return getLowPriorityMessageCount() + getMediumPriorityMessageCount() + getHighPriorityMessageCount();
        }

        public bool isConnected()
        {
            try
            {
                if (clientSocket == null)
                {
                    return false;
                }

                return clientSocket.Connected && running && cts != null && !cts.IsCancellationRequested;
            }
            catch (Exception)
            {
                return false;
            }
        }

        // Get the ip/hostname and port
        public string getFullAddress(bool useIncomingPorts = false)
        {
            if (useIncomingPorts)
            {
                return address + ":" + incomingPort;
            }
            return fullAddress;
        }

        private MessageHeader? parseHeader(byte[] buffer, int offset, int length)
        {
            if (buffer == null)
                return null;

            int startOffset = offset;

            byte start = buffer[offset++];

            var header = new MessageHeader();

            if (start == 0xEA)
            {
                // v6 header (12 bytes)
                if (length < 12)
                    return null;

                header.code = (ProtocolMessageCode)ReadUInt16(buffer, ref offset);
                uint dataLength = ReadUInt32(buffer, ref offset);
                header.dataLen = dataLength;

                header.dataChecksum = ReadUInt32(buffer, ref offset);

                byte checksum = buffer[offset++];

                // checksum over first 11 bytes
                if (getHeaderChecksum(buffer, startOffset, 11) != checksum)
                {
                    Logging.warn("Header checksum mismatch");
                    return null;
                }

                if (dataLength == 0 || dataLength > CoreConfig.maxMessageSize)
                {
                    Logging.warn("Invalid data length {0}, code {1}", dataLength, header.code);
                    return null;
                }
            }
            else if (start == (byte)'X')
            {
                // v5 header (43 bytes) - deprecated
                if (length < 43)
                    return null;

                header.code = (ProtocolMessageCode)ReadInt32(buffer, ref offset);

                int dataLength = ReadInt32(buffer, ref offset);
                if (dataLength <= 0 || dataLength > CoreConfig.maxMessageSize)
                {
                    Logging.warn("Invalid data length {0}, code {1}", dataLength, header.code);
                    return null;
                }

                header.dataLen = (uint)dataLength;
                header.legacyDataChecksum = new byte[32];
                Buffer.BlockCopy(buffer, offset, header.legacyDataChecksum, 0, 32);

                offset += 32;

                byte checksum = buffer[offset++];
                byte endByte = buffer[offset++];

                if (endByte != (byte)'I')
                {
                    Logging.warn("Header end byte was not 'I'");
                    return null;
                }

                // checksum over first 41 bytes
                if (getHeaderChecksum(buffer, startOffset, 41) != checksum)
                {
                    Logging.warn("Header checksum mismatch");
                    return null;
                }
            }
            else
            {
                // unknown start byte
                Logging.warn("Unknown start byte {0}", (int)start);
                return null;
            }

            return header;
        }

        protected async Task readTimeSyncData(CancellationToken ct)
        {
            if (timeSyncComplete)
            {
                return;
            }

            Socket socket = clientSocket!;

            int rcv_count = 8;
            for (int i = 0; i < rcv_count && !ct.IsCancellationRequested;)
            {
                int rcvd_count = await socket.ReceiveAsync(socketReadBuffer.Slice(i, rcv_count - i), SocketFlags.None, ct);
                i += rcvd_count;
                if (rcvd_count <= 0)
                {
                    await Task.Delay(1).ConfigureAwait(false);
                }
            }
            lock (timeSyncs)
            {
                long my_cur_time = Clock.getTimestampMillis();
                long cur_remote_time = BitConverter.ToInt64(socketReadBuffer.Slice(0, 8).ToArray(), 0);
                long time_difference = my_cur_time - cur_remote_time;
                if (timeSyncs.Count > 0)
                {
                    TimeSyncData prev_tsd = timeSyncs.Last();
                    time_difference -= my_cur_time - prev_tsd.processedTime;
                }
                TimeSyncData tsd = new TimeSyncData() { timeDifference = time_difference, remoteTime = cur_remote_time, processedTime = my_cur_time };
                timeSyncs.Add(tsd);
                if (timeSyncs.Count >= 5)
                {
                    timeSyncComplete = true;
                }
            }
        }

        // Reads data from a socket and returns a byte array
        protected async Task<QueueMessageRaw?> readSocketData(CancellationToken ct)
        {
            Socket socket = clientSocket!;

            // Check for socket availability
            if (socket.Connected == false)
            {
                throw new SocketException((int)SocketError.NotConnected);
            }

            // Read multi-packet messages
            int old_header_len = 43; // old - start byte + message code (int32 4 bytes) + payload length (int32 4 bytes) + checksum (32 bytes) + header checksum (1 byte) + end byte = 43 bytes
            int new_header_len = 12; // new - start byte + message code (uint16 2 bytes) + payload length (uint32 4 bytes) + crc32 (uint32 4 bytes) + header checksum (1 byte) = 12 bytes
            byte[] header = new byte[old_header_len];
            int cur_header_len = 0;
            MessageHeader? last_message_header = null;

            byte[]? data = null;
            int cur_data_len = 0;

            int expected_data_len = 0;
            int expected_header_len = 0;
            int bytes_to_read = 1;
            while (socket.Connected && !ct.IsCancellationRequested)
            {
                int bytes_received = await socket.ReceiveAsync(socketReadBuffer.Slice(0, bytes_to_read), SocketFlags.None, ct);
                if (bytes_received <= 0)
                {
                    continue;
                }

                lastDataReceivedTime = Clock.getTimestamp();
                if (cur_header_len == 0)
                {
                    switch (socketReadBuffer.Span[0])
                    {
                        case 0xEA: // 0xEA is the message start byte of v6 base protocol
                            header[0] = socketReadBuffer.Span[0];
                            cur_header_len = 1;
                            bytes_to_read = new_header_len - 1; // header length - start byte
                            expected_header_len = new_header_len;
                            version = 6;
                            break;

                        case 0x02: // 0x02 is the timesync
                            if (timeSyncComplete == false)
                            {
                                await readTimeSyncData(ct).ConfigureAwait(false);
                            }
                            break;

                            /*case 0x01: // 0x01 is ping; doesn't need any special handling
                                break;*/
                    }
                    continue;
                }

                if (cur_header_len < expected_header_len)
                {
                    Buffer.BlockCopy(socketReadBuffer.Slice(0, bytes_received).ToArray(), 0, header, cur_header_len, bytes_received);
                    cur_header_len += bytes_received;
                    if (cur_header_len == expected_header_len)
                    {
                        last_message_header = parseHeader(header, 0, header.Length);
                        if (last_message_header != null)
                        {
                            cur_data_len = 0;
                            expected_data_len = (int)last_message_header.dataLen;
                            if (expected_data_len > CoreConfig.maxMessageSize)
                            {
                                throw new Exception(string.Format("Message size ({0}B) received from the client is higher than the maximum message size allowed ({1}B) - protocol code: {2}.", expected_data_len, CoreConfig.maxMessageSize, last_message_header.code));
                            }
                            data = new byte[expected_data_len];
                            bytes_to_read = expected_data_len;
                            if (bytes_to_read > 64000)
                            {
                                bytes_to_read = 64000;
                            }
                        }
                        else
                        {
                            cur_header_len = 0;
                            expected_data_len = 0;
                            data = null;
                            bytes_to_read = 1;
                            // Find next start byte if available
                            for (int i = cur_header_len - 1; i > 1; i--)
                            {
                                if (header[i] == 0xEA)
                                {
                                    cur_header_len = cur_header_len - i;
                                    Buffer.BlockCopy(header, i, header, 0, cur_header_len);
                                    expected_header_len = new_header_len;
                                    bytes_to_read = expected_header_len - cur_header_len;
                                    version = 6;
                                    break;
                                }
                            }
                        }
                    }
                    else if (cur_header_len < expected_header_len)
                    {
                        bytes_to_read = expected_header_len - cur_header_len;
                    }
                }
                else
                {
                    Buffer.BlockCopy(socketReadBuffer.Slice(0, bytes_received).ToArray(), 0, data, cur_data_len, bytes_received);
                    cur_data_len += bytes_received;
                    if (cur_data_len == expected_data_len)
                    {
                        QueueMessageRaw raw_message = new QueueMessageRaw()
                        {
                            checksum = last_message_header.dataChecksum,
                            code = last_message_header.code,
                            data = data,
                            legacyChecksum = last_message_header.legacyDataChecksum,
                            endpoint = this
                        };
                        return raw_message;
                    }
                    else if (cur_data_len > expected_data_len)
                    {
                        throw new Exception(string.Format("Unhandled edge case occurred in RemoteEndPoint:readSocketData for node {0}", getFullAddress()));
                    }
                    bytes_to_read = expected_data_len - cur_data_len;
                    if (bytes_to_read > 64000)
                    {
                        bytes_to_read = 64000;
                    }
                }
            }
            return null;
        }

        // Subscribe to event
        public bool attachEvent(NetworkEvents.Type type, byte[] filter)
        {
            if (address == null)
                return false;

            lock (subscribedFilters)
            {
                // Check the quota
                int num_subscribed_addresses = subscribedFilters.Values.Aggregate(0, (acc, f) => acc + f.numItems);
                if (num_subscribed_addresses > CoreConfig.maximumSubscribableEvents)
                {
                    return false;
                }
            }
            Cuckoo cuckoo_filter;
            try
            {
                cuckoo_filter = new Cuckoo(filter);
            }
            catch (Exception e)
            {
                Logging.warn("Cannot attach event {0} to Remote Endpoint {1}: {2}",
                    type.ToString(),
                    getFullAddress(),
                    e
                    );
                return false;
            }

            lock (subscribedFilters)
            {
                // Subscribing a new cuckoo for a particular event type will replace the old one
                subscribedFilters.AddOrReplace(type, cuckoo_filter);
            }

            return true;
        }


        // Unsubscribe from event
        public bool detachEventType(NetworkEvents.Type type)
        {
            lock (subscribedFilters)
            {
                // Check if we're subscribed already to this address
                if (subscribedFilters.ContainsKey(type) == true)
                {
                    subscribedFilters.Remove(type);
                }
            }

            return true;
        }

        public bool detachEventAddress(NetworkEvents.Type type, byte[] address)
        {
            if (address == null)
            {
                return true;
            }
            lock (subscribedFilters)
            {
                if (subscribedFilters.ContainsKey(type) == true)
                {
                    subscribedFilters[type].Delete(address);
                }
            }
            return true;
        }

        // Check if the remote endpoint is subscribed to an event for a specific address
        // Returns true if subscribed
        public bool isSubscribedToAddress(NetworkEvents.Type type, byte[] address)
        {
            if (address == null)
                return false;

            lock (subscribedFilters)
            {
                if (subscribedFilters.ContainsKey(type) == true)
                {
                    return subscribedFilters[type].Contains(address);
                }
            }

            return false;
        }

        public long calculateTimeDifference()
        {
            lock (timeSyncs)
            {
                if (timeSyncs.Count == 0)
                {
                    return 0;
                }
                long time_diff = timeSyncs.OrderBy(x => x.timeDifference).First().timeDifference;
                return time_diff / 1000;
            }
        }

        /// <summary>
        ///  Prepares (serializes) a protocol message from the given Ixian message code and appropriate data. Checksum can be supplied, but 
        ///  if it isn't, this function will calculate it using the default method.
        /// </summary>
        /// <remarks>
        ///  This function can be used from the server and client side.
        ///  Please note: This function does not validate that the payload `data` conforms to the expected message for `code`. It is the 
        ///  caller's job to ensure that.
        /// </remarks>
        /// <param name="code">Message code.</param>
        /// <param name="data">Payload for the message.</param>
        /// <param name="version">Protocol version to use for message preparation. If not supplied, the current version of the endpoint will be used.</param>
        /// <param name="checksum">Optional checksum. If not supplied, or if null, this function will calculate it with the default method.</param>
        /// <returns>Serialized message as a byte-field</returns>
        public static ArraySegment<byte> prepareProtocolMessage(
            ProtocolMessageCode code,
            ReadOnlyMemory<byte> data,
            int version,
            uint checksum)
        {
            int dataLength = data.Length;

            if (dataLength > CoreConfig.maxMessageSize)
            {
                throw new Exception($"Tried to send data bigger than max allowed message size - {dataLength} with code {code}.");
            }

            bool isV5 = version == 5;

            // Header sizes:
            // v5: 1 + 4 + 4 + 32 + 1 + 1 = 43 bytes
            // vX: 1 + 2 + 4 + 4 + 1 = 12 bytes
            int headerSize = isV5 ? 43 : 12;

            int totalSize = headerSize + dataLength;

            byte[] buffer = new byte[totalSize];
            int offset = 0;

            if (isV5)
            {
                // deprecated v5 header, kept for compatibility with older nodes
                buffer[offset++] = (byte)'X';

                WriteInt32(buffer, ref offset, (int)code);
                WriteInt32(buffer, ref offset, dataLength);

                // SHA512 truncated (32 bytes)
                var hash = Crypto.sha512sqTrunc(data.ToArray(), 0, 0, 32);
                Buffer.BlockCopy(hash, 0, buffer, offset, 32);
                offset += 32;
            }
            else
            {
                buffer[offset++] = 0xEA;

                WriteUInt16(buffer, ref offset, (ushort)code);
                WriteUInt32(buffer, ref offset, (uint)dataLength);

                uint crc = checksum != 0 ? checksum : Crc32CAlgorithm.Compute(data.ToArray());
                WriteUInt32(buffer, ref offset, crc);
            }

            byte headerChecksum = getHeaderChecksum(buffer, 0, offset);
            buffer[offset++] = headerChecksum;

            // Optional end byte
            if (isV5)
            {
                buffer[offset++] = (byte)'I';
            }

            Buffer.BlockCopy(data.ToArray(), 0, buffer, offset, dataLength);

            return new ArraySegment<byte>(buffer, 0, totalSize);
        }

        /// <summary>
        ///  Calculates a single-byte checksum from the given header.
        /// </summary>
        /// <remarks>
        ///  A single byte of checksum is not extremely robust, but it is simple and fast.
        /// </remarks>
        /// <param name="header">Message header.</param>
        /// <returns>Checksum byte.</returns>
        private static byte getHeaderChecksum(byte[] header, int offset, int length)
        {
            byte sum = 0x7F;
            for (int i = 0; i < length; i++)
            {
                sum ^= header[offset + i];
            }
            return sum;
        }

        public async ValueTask DisposeAsync()
        {
            await stopAsync().ConfigureAwait(false);
        }

        private Channel<T> CreateBoundedChannel<T>(int capacity)
        {
            return Channel.CreateBounded<T>(new BoundedChannelOptions(capacity)
            {
                SingleReader = true,
                SingleWriter = false,
                FullMode = BoundedChannelFullMode.Wait
            });
        }


        private static void WriteInt32(byte[] buffer, ref int offset, int value)
        {
            buffer[offset++] = (byte)value;
            buffer[offset++] = (byte)(value >> 8);
            buffer[offset++] = (byte)(value >> 16);
            buffer[offset++] = (byte)(value >> 24);
        }

        private static void WriteUInt32(byte[] buffer, ref int offset, uint value)
        {
            buffer[offset++] = (byte)value;
            buffer[offset++] = (byte)(value >> 8);
            buffer[offset++] = (byte)(value >> 16);
            buffer[offset++] = (byte)(value >> 24);
        }

        private static void WriteUInt16(byte[] buffer, ref int offset, ushort value)
        {
            buffer[offset++] = (byte)value;
            buffer[offset++] = (byte)(value >> 8);
        }

        private static ushort ReadUInt16(byte[] buffer, ref int offset)
        {
            ushort value =
                (ushort)(buffer[offset] |
                        (buffer[offset + 1] << 8));

            offset += 2;
            return value;
        }

        private static uint ReadUInt32(byte[] buffer, ref int offset)
        {
            uint value =
                (uint)(buffer[offset] |
                      (buffer[offset + 1] << 8) |
                      (buffer[offset + 2] << 16) |
                      (buffer[offset + 3] << 24));

            offset += 4;
            return value;
        }

        private static int ReadInt32(byte[] buffer, ref int offset)
        {
            int value =
                buffer[offset] |
                (buffer[offset + 1] << 8) |
                (buffer[offset + 2] << 16) |
                (buffer[offset + 3] << 24);

            offset += 4;
            return value;
        }
    }
}

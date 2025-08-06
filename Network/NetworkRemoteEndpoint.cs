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

using Force.Crc32;
using IXICore.Inventory;
using IXICore.Meta;
using IXICore.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;

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

    public class RemoteEndpoint
    {
        class MessageHeader
        {
            public ProtocolMessageCode code;
            public uint dataLen;
            public uint dataChecksum;
            public byte[] legacyDataChecksum;
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

        public bool fullyStopped = false;

        public IPEndPoint remoteIP;
        public Socket clientSocket;
        public RemoteEndpointState state;

        // Maintain two threads for handling data receiving and sending
        protected Task recvTask = null;
        protected Task sendTask = null;
        protected Task parseTask = null;

        public Presence presence = null;
        public PresenceAddress presenceAddress = null;

        protected bool running = false;

        // Maintain a list of subscribed event addresses with event type
        private Dictionary<NetworkEvents.Type, Cuckoo> subscribedFilters = new Dictionary<NetworkEvents.Type, Cuckoo>();

        // Maintain a queue of messages to send
        private List<QueueMessage> sendQueueMessagesHighPriority = new List<QueueMessage>();
        private List<QueueMessage> sendQueueMessagesNormalPriority = new List<QueueMessage>();
        private List<QueueMessage> sendQueueMessagesLowPriority = new List<QueueMessage>();

        // Maintain a queue of raw received data
        private Channel<QueueMessageRaw?> recvRawQueueMessages = Channel.CreateUnbounded<QueueMessageRaw?>();

        private byte[] socketReadBuffer = null;

        protected List<TimeSyncData> timeSyncs = new List<TimeSyncData>();

        protected bool enableSendTimeSyncMessages = true;

        private ThreadLiveCheck TLC;

        private List<InventoryItem> inventory = new List<InventoryItem>();
        private long inventoryLastSent = 0;

        private List<long> requestedMessageIds = new List<long>();

        public Address serverWalletAddress = null;
        public byte[] serverPubKey = null;

        public byte[] challenge = null;

        public int version = 6;

        public bool reconnectOnFailure = true;

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

        public void start(Socket socket = null)
        {
            if (fullyStopped)
            {
                Logging.error("Can't start a fully stopped RemoteEndpoint");
                return;
            }

            if (running)
            {
                Logging.error("Can't start already running RemoteEndpoint");
                return;
            }

            running = true;

            if (socket != null)
            {
                clientSocket = socket;
            }
            if (clientSocket == null)
            {
                Logging.error("Could not start NetworkRemoteEndpoint, socket is null");
                return;
            }

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

            state = RemoteEndpointState.Established;

            timeDifference = 0;
            timeSyncComplete = false;
            timeSyncs.Clear();

            try
            {
                TLC = new ThreadLiveCheck();

                // Start receive thread
                recvTask = recvLoop();
                recvTask.ContinueWith(t =>
                {
                    Logging.error("Exception in task: " + t.Exception);
                }, TaskContinuationOptions.OnlyOnFaulted);

                // Start send thread
                sendTask = sendLoop();
                sendTask.ContinueWith(t =>
                {
                    Logging.error("Exception in task: " + t.Exception);
                }, TaskContinuationOptions.OnlyOnFaulted);

                // Start parse thread
                parseTask = parseLoop();
                parseTask.ContinueWith(t =>
                {
                    Logging.error("Exception in task: " + t.Exception);
                }, TaskContinuationOptions.OnlyOnFaulted);
            }
            catch (Exception e)
            {
                Logging.error("Error starting remote endpoint: {0}", e.Message);
                stop();
            }
        }

        // Aborts all related endpoint threads and data
        public void stop(bool fully_stopped = true)
        {
            fullyStopped = fully_stopped;

            if (sendTask != null)
            {
                Thread.Sleep(50);
            }

            state = RemoteEndpointState.Closed;
            running = false;

            try
            {
                recvRawQueueMessages.Writer.WriteAsync(null);
            }
            catch (Exception e)
            {
                Logging.error("Error while stopping " + e);
            }

            disconnect();

            if (sendTask != null)
            {
                try
                {
                    sendTask.Wait();
                }
                catch (Exception e)
                {
                    Logging.error("Error while stopping " + e);
                }
                sendTask = null;
            }

            if (parseTask != null)
            {
                try
                {
                    parseTask.Wait();
                }
                catch (Exception e)
                {
                    Logging.error("Error while stopping " + e);
                }
                parseTask = null;
            }

            if (recvTask != null)
            {
                try
                {
                    recvTask.Wait();
                }
                catch (Exception e)
                {
                    Logging.error("Error while stopping " + e);
                }
                recvTask = null;
            }

            lock (sendQueueMessagesHighPriority)
            {
                sendQueueMessagesHighPriority.Clear();
            }

            lock (sendQueueMessagesNormalPriority)
            {
                sendQueueMessagesNormalPriority.Clear();
            }

            lock (sendQueueMessagesLowPriority)
            {
                sendQueueMessagesLowPriority.Clear();
            }

            lock (subscribedFilters)
            {
                subscribedFilters.Clear();
            }

            lock (inventory)
            {
                inventory.Clear();
            }
        }

        // Receive thread
        protected async Task recvLoop()
        {
            try
            {
                socketReadBuffer = new byte[8192];
                long lastReceivedMessageStatTime = Clock.getTimestampMillis();
                int messageCount = 0;
                while (running)
                {
                    TLC.Report();
                    // Let the protocol handler receive and handle messages
                    bool message_received = false;
                    try
                    {
                        QueueMessageRaw? raw_msg = await readSocketData();
                        if (raw_msg != null)
                        {
                            message_received = true;
                            await parseDataInternal((QueueMessageRaw)raw_msg);
                            messageCount++;
                        }
                    }
                    catch (SocketException se)
                    {
                        if (running)
                        {
                            if (se.SocketErrorCode != SocketError.ConnectionAborted
                                && se.SocketErrorCode != SocketError.NotConnected
                                && se.SocketErrorCode != SocketError.ConnectionReset
                                && se.SocketErrorCode != SocketError.Interrupted)
                            {
                                Logging.warn("recvRE: Disconnected client {0} with socket exception {1} {2} {3}", getFullAddress(), se.SocketErrorCode, se.ErrorCode, se);
                            }
                        }
                        state = RemoteEndpointState.Closed;
                    }
                    catch (Exception e)
                    {
                        if (running)
                        {
                            Logging.warn("recvRE: Disconnected client {0} with exception {1}", getFullAddress(), e);
                        }
                        state = RemoteEndpointState.Closed;
                    }

                    // Check if the client disconnected
                    if (state == RemoteEndpointState.Closed)
                    {
                        running = false;
                        break;
                    }

                    // Sleep a while to throttle the client
                    // Check if there are too many messages
                    // TODO TODO TODO this can be handled way better
                    int total_message_count = NetworkQueue.getQueuedMessageCount();
                    if (total_message_count > 10000)
                    {
                        await Task.Delay(1000);
                    }
                    else if (total_message_count > 5000)
                    {
                        await Task.Delay(500);
                    }
                    else if (messageCount > 100)
                    {
                        long cur_time = Clock.getTimestampMillis();
                        long time_diff = cur_time - lastReceivedMessageStatTime;
                        if (time_diff < 100)
                        {
                            // sleep to throttle the client to 1000 messages/second
                            await Task.Delay(100 - (int)time_diff);
                            cur_time = Clock.getTimestampMillis();
                        }
                        lastReceivedMessageStatTime = cur_time;
                        messageCount = 0;
                    }
                    else if (!message_received)
                    {
                        await Task.Delay(10);
                    }
                }
            }
            catch (Exception e)
            {
                Logging.error("RecvLoop exception: {0}", e);
            }
            state = RemoteEndpointState.Closed;
            running = false;
        }

        protected virtual void disconnect()
        {
            // Close the client socket
            if (clientSocket == null)
            {
                return;
            }
            try
            {
                clientSocket.Shutdown(SocketShutdown.Both);
                clientSocket.Disconnect(false);
                clientSocket.Close();
                clientSocket = null;
            }
            catch (Exception e)
            {
                Logging.warn("recvRE: Could not shutdown client socket: {0}", e.ToString());
            }
        }

        protected void sendTimeSyncMessages()
        {
            // send 5 messages with current network timestamp
            List<byte> time_sync_data = new List<byte>();
            for (int i = 0; i < 5 && running; i++)
            {
                time_sync_data.Clear();
                time_sync_data.Add(2);
                time_sync_data.AddRange(BitConverter.GetBytes(Clock.getNetworkTimestampMillis()));
                try
                {
                    int time_sync_data_len = time_sync_data.ToArray().Length;
                    for (int sent = 0; sent < time_sync_data_len && running;)
                    {
                        sent += clientSocket.Send(time_sync_data.ToArray(), sent, time_sync_data_len, SocketFlags.None);
                    }
                }
                catch (Exception)
                {
                    state = RemoteEndpointState.Closed;
                    running = false;
                }
            }
        }

        protected virtual void onInitialized()
        {

        }

        // Send thread
        protected async Task sendLoop()
        {
            try
            {
                // Prepare an special message object to use while sending, without locking up the queue messages
                QueueMessage active_message = new QueueMessage();

                if (enableSendTimeSyncMessages)
                {
                    sendTimeSyncMessages();
                }

                long lastSentMessageStatTime = Clock.getTimestampMillis();

                int messageCount = 0;

                lastDataReceivedTime = Clock.getTimestamp();
                lastDataSentTime = Clock.getTimestamp();

                onInitialized();

                while (running)
                {
                    TLC.Report();
                    long curTime = Clock.getTimestamp();
                    if (helloReceived == false && curTime - connectionStartTime > 10)
                    {
                        // haven't received hello message for 10 seconds, stop running
                        Logging.info("Node {0} hasn't received hello data from remote endpoint for over 10 seconds, disconnecting.", getFullAddress());
                        state = RemoteEndpointState.Closed;
                        running = false;
                        break;
                    }
                    if (curTime - lastDataReceivedTime > CoreConfig.pingTimeout)
                    {
                        // haven't received any data for 10 seconds, stop running
                        Logging.warn("Node {0} hasn't received any data from remote endpoint for over {1} seconds, disconnecting.", getFullAddress(), CoreConfig.pingTimeout);
                        state = RemoteEndpointState.Closed;
                        running = false;
                        break;
                    }
                    if (curTime - lastDataSentTime > CoreConfig.pongInterval)
                    {
                        try
                        {
                            clientSocket.Send(new byte[1] { 1 }, SocketFlags.None);
                            lastDataSentTime = curTime;
                            continue;
                        }
                        catch (Exception)
                        {
                            state = RemoteEndpointState.Closed;
                            running = false;
                            break;
                        }
                    }

                    bool message_found = false;
                    lock (sendQueueMessagesHighPriority)
                    {
                        lock (sendQueueMessagesNormalPriority)
                        {
                            if ((messageCount > 0 && messageCount % 5 == 0) || (sendQueueMessagesNormalPriority.Count == 0 && sendQueueMessagesHighPriority.Count == 0))
                            {
                                lock (sendQueueMessagesLowPriority)
                                {
                                    if (sendQueueMessagesLowPriority.Count > 0)
                                    {
                                        // Pick the oldest message
                                        active_message = sendQueueMessagesLowPriority[0];
                                        // Remove it from the queue
                                        sendQueueMessagesLowPriority.RemoveAt(0);
                                        message_found = true;
                                    }
                                }
                            }

                            if (message_found == false && ((messageCount > 0 && messageCount % 3 == 0) || sendQueueMessagesHighPriority.Count == 0))
                            {
                                if (sendQueueMessagesNormalPriority.Count > 0)
                                {
                                    // Pick the oldest message
                                    active_message = sendQueueMessagesNormalPriority[0];
                                    // Remove it from the queue
                                    sendQueueMessagesNormalPriority.RemoveAt(0);
                                    message_found = true;
                                }
                            }

                            if (message_found == false && sendQueueMessagesHighPriority.Count > 0)
                            {
                                // Pick the oldest message
                                active_message = sendQueueMessagesHighPriority[0];
                                // Remove it from the queue
                                sendQueueMessagesHighPriority.RemoveAt(0);
                                message_found = true;
                            }
                        }
                    }

                    if (message_found)
                    {
                        messageCount++;
                        // Active message set, attempt to send it
                        await sendDataInternal(active_message.code, active_message.data, active_message.checksum);
                        if (active_message.code == ProtocolMessageCode.bye)
                        {
                            await Task.Delay(500); // grace sleep to get the message through
                            state = RemoteEndpointState.Closed;
                            running = false;
                            fullyStopped = true;
                        }
                    }
                    await sendInventory();

                    if (messageCount > 100)
                    {
                        long cur_time = Clock.getTimestampMillis();
                        long time_diff = cur_time - lastSentMessageStatTime;
                        if (time_diff < 100)
                        {
                            // sleep to throttle the client to 1000 messages/second
                            await Task.Delay(100 - (int)time_diff);
                            cur_time = Clock.getTimestampMillis();
                        }
                        lastSentMessageStatTime = cur_time;
                        messageCount = 0;
                    }
                    else if (!message_found)
                    {
                        await Task.Delay(10);
                    }
                }
            }
            catch (Exception e)
            {
                Logging.error("SendLoop exception: {0}", e);
            }
            state = RemoteEndpointState.Closed;
            running = false;
        }

        public void addInventoryItem(InventoryItem item)
        {
            lock(inventory)
            {
                inventory.Add(item);
            }
        }

        protected async Task sendInventory()
        {
            try
            {
                IEnumerable<InventoryItem> items_to_send = null;
                lock (inventory)
                {
                    if (inventory.Count() == 0)
                    {
                        return;
                    }
                    long cur_time = Clock.getTimestamp();
                    if (inventory.Count() < CoreConfig.maxInventoryItems && inventoryLastSent > cur_time - CoreConfig.inventoryInterval)
                    {
                        return;
                    }
                    inventoryLastSent = cur_time;
                    items_to_send = inventory.Take(CoreConfig.maxInventoryItems);
                    inventory = inventory.Skip(CoreConfig.maxInventoryItems).ToList();
                }
                using (MemoryStream m = new MemoryStream())
                {
                    using (BinaryWriter writer = new BinaryWriter(m))
                    {
                        writer.WriteIxiVarInt(items_to_send.Count());
                        foreach (var item in items_to_send)
                        {
                            byte[] item_bytes = item.getBytes();
                            writer.WriteIxiVarInt(item_bytes.Length);
                            writer.Write(item_bytes);
                        }
                    }
                    await sendDataInternal(ProtocolMessageCode.inventory2, m.ToArray(), 0);
                }
            }
            catch(Exception e)
            {
                Logging.error("Exception occurred in sendInventory: " + e);
            }
        }

        // Parse thread
        protected async Task parseLoop()
        {
            while (running)
            {
                TLC.Report();
                try
                {
                    QueueMessageRaw? active_message_task = await recvRawQueueMessages.Reader.ReadAsync();

                    if (!active_message_task.HasValue)
                    {
                        continue;
                    }

                    QueueMessageRaw active_message = active_message_task.Value;

                    // Active message set, add it to Network Queue
                    MessagePriority priority = MessagePriority.auto;
                    lock (requestedMessageIds)
                    {
                        long msg_id = 0;
                        ulong last_bh = IxianHandler.getLastBlockHeight();
                        switch (active_message.code)
                        {
                            case ProtocolMessageCode.blockData2:
                                ulong bh = active_message.data.GetIxiVarUInt(active_message.data.GetIxiVarUInt(0).bytesRead).num;
                                if (bh == last_bh || bh == last_bh + 1)
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
                                if (msg_id == (long)last_bh + 1)
                                {
                                    priority = MessagePriority.medium;
                                }
                                msg_id = active_message.data.GetIxiVarInt(0).num;
                                break;
                        }

                        if (msg_id != 0)
                        {
                            if (!requestedMessageIds.Contains(msg_id > 0 ? msg_id : -msg_id))
                            {
                                Logging.warn("Received message with code {0}, message id {1} which was not requested.", active_message.code, msg_id);
                            }
                            else
                            {
                                priority = MessagePriority.medium;
                                if (msg_id > 0)
                                {
                                    requestedMessageIds.Remove(msg_id);
                                }
                            }
                        }
                    }
                    CoreProtocolMessage.readProtocolMessage(active_message, priority, this);
                }
                catch (Exception e)
                {
                    state = RemoteEndpointState.Closed;
                    running = false;
                    Logging.error("Exception occurred for client {0} in parseLoopRE: {1} ", getFullAddress(), e);
                }
            }
        }

        protected async Task parseDataInternal(QueueMessageRaw message)
        {
            await recvRawQueueMessages.Writer.WriteAsync(message);
        }

        // Internal function that sends data through the socket
        protected async Task sendDataInternal(ProtocolMessageCode code, byte[] data, uint checksum)
        {
            try
            {
                byte[] ba = prepareProtocolMessage(code, data, version, checksum);
                NetDump.Instance.appendSent(clientSocket, ba, ba.Length);
                for (int sentBytes = 0; sentBytes < ba.Length && running;)
                {
                    int bytesToSendCount = ba.Length - sentBytes;
                    if (bytesToSendCount > 8000)
                    {
                        bytesToSendCount = 8000;
                    }


                    int curSentBytes = clientSocket.Send(ba, sentBytes, bytesToSendCount, SocketFlags.None);

                    if(curSentBytes > 0)
                    {
                        lastDataSentTime = Clock.getTimestamp();
                    }

                    // Sleep a bit to allow other threads to do their thing
                    if (curSentBytes < bytesToSendCount)
                    {
                        await Task.Delay(1);
                    }

                    sentBytes += curSentBytes;
                    // TODO TODO TODO timeout
                }
                if (clientSocket.Connected == false)
                {
                    if (running)
                    {
                        Logging.warn(String.Format("sendRE: Failed senddata to remote endpoint {0}, Closing.", getFullAddress()));
                    }
                    state = RemoteEndpointState.Closed;
                    running = false;
                }
            }
            catch (SocketException se)
            {
                if (running)
                {
                    if (se.SocketErrorCode != SocketError.ConnectionAborted
                        && se.SocketErrorCode != SocketError.NotConnected
                        && se.SocketErrorCode != SocketError.ConnectionReset
                        && se.SocketErrorCode != SocketError.Interrupted)
                    {
                        Logging.warn("sendRE: Disconnected client {0} with socket exception {1} {2} {3}", getFullAddress(), se.SocketErrorCode, se.ErrorCode, se);
                    }
                }
                state = RemoteEndpointState.Closed;
                running = false;
            }
            catch (Exception e)
            {
                if (running)
                {
                    Logging.warn("sendRE: Socket exception for {0}, closing. {1}", getFullAddress(), e);
                }
                state = RemoteEndpointState.Closed;
                running = false;
            }
        }

        private void addMessageToSendQueue(List<QueueMessage> message_queue, QueueMessage message)
        {
            if (message.helperData != null)
            {
                if (message_queue.Exists(x => x.code == message.code && x.helperData != null && message.helperData.SequenceEqual(x.helperData)))
                {
                    int msg_index = message_queue.FindIndex(x => x.code == message.code && x.helperData != null && message.helperData.SequenceEqual(x.helperData));
                    message_queue[msg_index] = message;
                    return;
                }
            }
            else
            {
                bool duplicate = message_queue.Exists(x => x.code == message.code && message.checksum == x.checksum);
                if (duplicate)
                {
                    Logging.warn(string.Format("Attempting to add a duplicate message (code: {0}) to the network queue for {1}", message.code, getFullAddress()));
                    return;
                }
            }
            // Check if there are too many messages
            if (message_queue.Count > CoreConfig.maxSendQueue)
            {
                message_queue.RemoveAt(10);
            }

            message_queue.Add(message);
        }


        // Sends data over the network
        public void sendData(ProtocolMessageCode code, byte[] data, byte[] helper_data = null, long msg_id = 0, MessagePriority priority = MessagePriority.auto)
        {
            if (data == null)
            {
                Logging.warn(string.Format("Invalid protocol message data for {0}", code));
                return;
            }

            QueueMessage message = getQueueMessage(code, data, helper_data);
            sendData(message, msg_id, priority);
        }

        public void sendData(QueueMessage message, long msg_id = 0,  MessagePriority priority = MessagePriority.auto)
        {
            //Logging.trace("Sending {0} id: {1}", message.code, msg_id);

            if (message.code == ProtocolMessageCode.getBlock3)
            {
                msg_id = message.data.GetIxiVarInt(0).num;
                priority = MessagePriority.high;
            }
            if(msg_id != 0)
            {
                lock(requestedMessageIds)
                {
                    if(!requestedMessageIds.Contains(msg_id))
                    {
                        requestedMessageIds.Add(msg_id);
                        if (requestedMessageIds.Count > CoreConfig.maximumRequestedMessageIds)
                        {
                            requestedMessageIds.RemoveAt(0);
                        }
                    }
                }
            }

            switch(priority)
            {
                case MessagePriority.low:
                    lock (sendQueueMessagesLowPriority)
                    {
                        addMessageToSendQueue(sendQueueMessagesLowPriority, message);
                    }
                    return;

                case MessagePriority.medium:
                    lock (sendQueueMessagesNormalPriority)
                    {
                        addMessageToSendQueue(sendQueueMessagesNormalPriority, message);
                    }
                    return;

                case MessagePriority.high:
                    lock (sendQueueMessagesHighPriority)
                    {
                        addMessageToSendQueue(sendQueueMessagesHighPriority, message);
                    }
                    return;
            }

            ProtocolMessageCode code = message.code;
            switch (code)
            {
                case ProtocolMessageCode.bye:
                case ProtocolMessageCode.keepAlivePresence:
                case ProtocolMessageCode.getPresence2:
                case ProtocolMessageCode.getKeepAlives:
                case ProtocolMessageCode.keepAlivesChunk:
                case ProtocolMessageCode.updatePresence:
                case ProtocolMessageCode.rejected:
                case ProtocolMessageCode.getNameRecord:
                case ProtocolMessageCode.nameRecord:
                case ProtocolMessageCode.getSectorNodes:
                case ProtocolMessageCode.sectorNodes:
                    lock (sendQueueMessagesHighPriority)
                    {
                        addMessageToSendQueue(sendQueueMessagesHighPriority, message);
                    }

                    break;

                case ProtocolMessageCode.transactionsChunk3:
                case ProtocolMessageCode.transactionData2:
                    lock (sendQueueMessagesLowPriority)
                    {
                        addMessageToSendQueue(sendQueueMessagesLowPriority, message);
                    }
                    break;

                default:
                    lock (sendQueueMessagesNormalPriority)
                    {
                        addMessageToSendQueue(sendQueueMessagesNormalPriority, message);
                    }
                    break;
            }
        }

        static public QueueMessage getQueueMessage(ProtocolMessageCode code, byte[] data, byte[] helper_data)
        {
            QueueMessage message = new QueueMessage();
            message.code = code;
            message.data = data;
            message.checksum = Crc32CAlgorithm.Compute(data);
            message.skipEndpoint = null;
            message.helperData = helper_data;

            return message;
        }

        public int getHighPriorityMessageCount()
        {
            lock (sendQueueMessagesHighPriority)
            {
                return sendQueueMessagesHighPriority.Count;
            }
        }

        public int getMediumPriorityMessageCount()
        {
            lock (sendQueueMessagesNormalPriority)
            {
                return sendQueueMessagesNormalPriority.Count;
            }
        }

        public int getLowPriorityMessageCount()
        {
            lock (sendQueueMessagesLowPriority)
            {
                return sendQueueMessagesLowPriority.Count;
            }
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

                return clientSocket.Connected && running;
            }
            catch (Exception)
            {
                return false;
            }
        }

        // Get the ip/hostname and port
        public string getFullAddress(bool useIncomingPorts = false)
        {
            if(useIncomingPorts)
            {
                return address + ":" + incomingPort;
            }
            return fullAddress;
        }

        private MessageHeader parseHeader(byte[] header_bytes)
        {
            MessageHeader header = new MessageHeader();
            // we should have the full header, save the data length
            using (MemoryStream m = new MemoryStream(header_bytes))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    byte start = reader.ReadByte(); // skip start byte
                    if(start == 0xEA)
                    {
                        ProtocolMessageCode code = (ProtocolMessageCode)reader.ReadUInt16(); // skip message code
                        header.code = code;
                        uint data_length = reader.ReadUInt32(); // read data length
                        header.dataLen = data_length;
                        header.dataChecksum = reader.ReadUInt32(); // checksum crc32
                        
                        byte checksum = reader.ReadByte(); // header checksum byte

                        byte[] header_for_crc = new byte[11];
                        Array.Copy(header_bytes, header_for_crc, 11);

                        if (getHeaderChecksum(header_for_crc) != checksum)
                        {
                            Logging.warn("Header checksum mismatch");
                            return null;
                        }

                        if (data_length <= 0)
                        {
                            Logging.warn("Data length was {0}, code {1}", data_length, code);
                            return null;
                        }
                    }
                    else // 'X'
                    {
                        ProtocolMessageCode code = (ProtocolMessageCode)reader.ReadInt32(); // read message code
                        header.code = code;
                        int data_length = reader.ReadInt32(); // read data length
                        header.dataLen = (uint)data_length;
                        header.legacyDataChecksum = reader.ReadBytes(32); // read checksum sha512qu/sha512sq, 32 bytes

                        byte checksum = reader.ReadByte(); // header checksum byte
                        byte endByte = reader.ReadByte(); // end byte

                        if (endByte != 'I')
                        {
                            Logging.warn("Header end byte was not 'I'");
                            return null;
                        }

                        if (getHeaderChecksum(header_bytes.Take(41).ToArray()) != checksum)
                        {
                            Logging.warn("Header checksum mismatch");
                            return null;
                        }

                        if (data_length <= 0)
                        {
                            Logging.warn("Data length was {0}, code {1}", data_length, code);
                            return null;
                        }
                    }

                }
            }
            return header;
        }

        protected async Task readTimeSyncData()
        {
            if(timeSyncComplete)
            {
                return;
            }

            Socket socket = clientSocket;

            int rcv_count = 8;
            for (int i = 0; i < rcv_count && running;)
            {
                int rcvd_count = socket.Receive(socketReadBuffer, i, rcv_count - i, SocketFlags.None);
                i += rcvd_count;
                if (rcvd_count <= 0)
                {
                    await Task.Delay(1);
                }
            }
            lock (timeSyncs)
            {
                long my_cur_time = Clock.getTimestampMillis();
                long cur_remote_time = BitConverter.ToInt64(socketReadBuffer, 0);
                long time_difference = my_cur_time - cur_remote_time;
                if (timeSyncs.Count > 0)
                {
                    TimeSyncData prev_tsd = timeSyncs.Last();
                    time_difference -= my_cur_time - prev_tsd.processedTime;
                }
                TimeSyncData tsd = new TimeSyncData() { timeDifference = time_difference, remoteTime = cur_remote_time, processedTime = my_cur_time };
                timeSyncs.Add(tsd);
                if(timeSyncs.Count() >= 5)
                {
                    timeSyncComplete = true;
                }
            }
        }

        // Reads data from a socket and returns a byte array
        protected async Task<QueueMessageRaw?> readSocketData()
        {
            Socket socket = clientSocket;

            // Check for socket availability
            if (socket.Connected == false)
            {
                throw new SocketException((int)SocketError.NotConnected);
            }

            if (socket.Available < 1)
            {
                return null;
            }

            // Read multi-packet messages
            int old_header_len = 43; // old - start byte + message code (int32 4 bytes) + payload length (int32 4 bytes) + checksum (32 bytes) + header checksum (1 byte) + end byte = 43 bytes
            int new_header_len = 12; // new - start byte + message code (uint16 2 bytes) + payload length (uint32 4 bytes) + crc32 (uint32 4 bytes) + header checksum (1 byte) = 12 bytes
            byte[] header = new byte[old_header_len];
            int cur_header_len = 0;
            MessageHeader last_message_header = null;

            byte[] data = null;
            int cur_data_len = 0;

            try
            {
                int expected_data_len = 0;
                int expected_header_len = 0;
                int bytes_to_read = 1;
                while (socket.Connected && running)
                {
                    int bytes_received = socket.Receive(socketReadBuffer, bytes_to_read, SocketFlags.None);
                    NetDump.Instance.appendReceived(socket, socketReadBuffer, bytes_received);
                    if (bytes_received <= 0)
                    {
                        // sleep a litte while waiting for bytes
                        await Task.Delay(1);
                        // TODO should return null if a timeout occurs
                        continue;
                    }

                    lastDataReceivedTime = Clock.getTimestamp();
                    if (cur_header_len == 0)
                    {
                        switch(socketReadBuffer[0])
                        {
                            case 0xEA: // 0xEA is the message start byte of v6 base protocol
                                header[0] = socketReadBuffer[0];
                                cur_header_len = 1;
                                bytes_to_read = new_header_len - 1; // header length - start byte
                                expected_header_len = new_header_len;
                                version = 6;
                                break;

                            case 0x02: // 0x02 is the timesync
                                if (timeSyncComplete == false)
                                {
                                    await readTimeSyncData();
                                }
                                break;

                            /*case 0x01: // 0x01 is ping; doesn't need any special handling
                                break;*/
                        }
                        continue;
                    }

                    if(cur_header_len < expected_header_len)
                    {
                        Array.Copy(socketReadBuffer, 0, header, cur_header_len, bytes_received);
                        cur_header_len += bytes_received;
                        if (cur_header_len == expected_header_len)
                        {
                            last_message_header = parseHeader(header);
                            if(last_message_header != null)
                            {
                                cur_data_len = 0;
                                expected_data_len = (int)last_message_header.dataLen;
                                if(expected_data_len > CoreConfig.maxMessageSize)
                                {
                                    throw new Exception(string.Format("Message size ({0}B) received from the client is higher than the maximum message size allowed ({1}B) - protocol code: {2}.", expected_data_len, CoreConfig.maxMessageSize, last_message_header.code));
                                }
                                data = new byte[expected_data_len];
                                bytes_to_read = expected_data_len;
                                if (bytes_to_read > 8000)
                                {
                                    bytes_to_read = 8000;
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
                                        Array.Copy(header, i, header, 0, cur_header_len);
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
                    }else
                    {
                        Array.Copy(socketReadBuffer, 0, data, cur_data_len, bytes_received);
                        cur_data_len += bytes_received;
                        if (cur_data_len == expected_data_len)
                        {
                            QueueMessageRaw raw_message = new QueueMessageRaw() { 
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
                        if (bytes_to_read > 8000)
                        {
                            bytes_to_read = 8000;
                        }
                    }
                }
            }
            catch (SocketException)
            {
                if (running)
                {
                    throw;
                }
            }
            catch (Exception)
            {
                if (running)
                {
                    throw;
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
            Cuckoo cuckoo_filter = null;
            try
            {
                cuckoo_filter = new Cuckoo(filter);
            } catch(Exception)
            {
                Logging.warn("Error while attempting to replace {0} filter for endpoint {1}",
                    type.ToString(),
                    getFullAddress()
                    );
                return false;
            }

            if (cuckoo_filter == null)
            {
                Logging.warn("Cannot attach event {0} to Remote Endpoint {1}, cuckoo filter is null.",
                    type.ToString(),
                    getFullAddress()
                    );
                return false;
            }


            lock (subscribedFilters) {
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
            if(address == null)
            {
                return true;
            }
            lock(subscribedFilters)
            {
                if(subscribedFilters.ContainsKey(type) == true)
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
                if(subscribedFilters.ContainsKey(type) == true)
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
                if(timeSyncs.Count == 0)
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
        /// <param name="checksum">Optional checksum. If not supplied, or if null, this function will calculate it with the default method.</param>
        /// <returns>Serialized message as a byte-field</returns>
        public static byte[] prepareProtocolMessage(ProtocolMessageCode code, byte[] data,int version, uint checksum)
        {
            byte[] result = null;

            // Prepare the protocol sections
            int data_length = data.Length;

            if (data_length > CoreConfig.maxMessageSize)
            {
                Logging.error("Tried to send data bigger than max allowed message size - {0} with code {1}.", data_length, code);
                return null;
            }

            using (MemoryStream m = new MemoryStream(12))
            {
                using (BinaryWriter writer = new BinaryWriter(m))
                {
                    // Protocol sections are code, length, checksum, data
                    // Write each section in binary, in that specific order
                    bool add_end_byte = false;
                    if(version == 5)
                    {
                        writer.Write((byte)'X');
                        writer.Write((int)code);
                        writer.Write(data_length);
                        writer.Write(Crypto.sha512sqTrunc(data, 0, 0, 32));
                        add_end_byte = true;
                    }else
                    {
                        writer.Write((byte)0xEA);
                        writer.Write((ushort)code);
                        writer.Write((uint)data_length);
                        if(checksum == 0)
                        {
                            writer.Write(Crc32CAlgorithm.Compute(data));
                        }else
                        {
                            writer.Write(checksum);
                        }
                    }

                    writer.Flush();
                    m.Flush();

                    byte header_checksum = getHeaderChecksum(m.ToArray());
                    writer.Write(header_checksum);

                    if(add_end_byte)
                    {
                        writer.Write((byte)'I');
                    }
                    writer.Write(data);
#if TRACE_MEMSTREAM_SIZES
                    Logging.info(String.Format("CoreProtocolMessage::prepareProtocolMessage: {0}", m.Length));
#endif
                }
                result = m.ToArray();
            }

            return result;
        }

        /// <summary>
        ///  Calculates a single-byte checksum from the given header.
        /// </summary>
        /// <remarks>
        ///  A single byte of checksum is not extremely robust, but it is simple and fast.
        /// </remarks>
        /// <param name="header">Message header.</param>
        /// <returns>Checksum byte.</returns>
        private static byte getHeaderChecksum(byte[] header)
        {
            byte sum = 0x7F;
            for (int i = 0; i < header.Length; i++)
            {
                sum ^= header[i];
            }
            return sum;
        }
    }
}
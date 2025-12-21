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

using IXICore.Meta;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace IXICore.Network
{
    public struct QueueMessage
    {
        public ProtocolMessageCode code;
        public byte[] data;
        public uint checksum;
        public RemoteEndpoint skipEndpoint;
        public byte[] helperData;
    }

    public struct QueueMessageRaw
    {
        public ProtocolMessageCode code;
        public byte[] data;
        public byte[] legacyChecksum;
        public uint checksum;
        public RemoteEndpoint endpoint;
    }

    class NetworkQueue
    {
        private static bool shouldStop = false; // flag to signal shutdown of threads
        private static ThreadLiveCheck TLC;

        private static bool running = false;

        // Internal queue message entity with socket and remoteendpoint support
        struct QueueMessageRecv
        {
            public ProtocolMessageCode code;
            public byte[] data;
            public int length;
            public uint checksum;
            public RemoteEndpoint endpoint;
            public byte[] helperData;
        }

        // Maintain a queue of messages to receive
        private static List<QueueMessageRecv> queueHighPriority = new List<QueueMessageRecv>(); // all other messages that don't belong to normal or low priority (keep alives, hello, etc...)
        private static List<QueueMessageRecv> queueMediumPriority = new List<QueueMessageRecv>(); // current block, sig and tx related to current block messages
        private static List<QueueMessageRecv> queueLowPriority = new List<QueueMessageRecv>(); // tx related messages

        private static Thread queueHighPriorityThread;
        private static Thread queueMediumPriorityThread;
        private static Thread queueLowPriorityThread;


        public static int getHighPriorityMessageCount()
        {
            lock (queueHighPriority)
            {
                return queueHighPriority.Count;
            }
        }

        public static int getMediumPriorityMessageCount()
        {
            lock (queueMediumPriority)
            {
                return queueMediumPriority.Count;
            }
        }

        public static int getLowPriorityMessageCount()
        {
            lock (queueLowPriority)
            {
                return queueLowPriority.Count;
            }
        }

        public static int getQueuedMessageCount()
        {
            return getLowPriorityMessageCount() + getMediumPriorityMessageCount() + getHighPriorityMessageCount();
        }

        private static byte[] extractHelperData(ProtocolMessageCode code, byte[] data)
        {
            if (code == ProtocolMessageCode.blockData2)
            {
                return data.Take(8).ToArray();
            }
            return null;
        }

        public static void receiveProtocolMessage(ProtocolMessageCode code, byte[] data, uint checksum, MessagePriority priority, RemoteEndpoint endpoint)
        {
            QueueMessageRecv message = new QueueMessageRecv
            {
                code = code,
                data = data,
                length = data.Length,
                checksum = checksum,
                endpoint = endpoint,
                helperData = extractHelperData(code, data)
            };

            if (priority == MessagePriority.medium)
            {
                lock(queueMediumPriority)
                {
                    if (message.helperData != null)
                    {
                        if (queueMediumPriority.Exists(x => x.code == message.code && x.helperData.SequenceEqual(message.helperData)))
                        {
                            int msg_index = queueMediumPriority.FindIndex(x => x.code == message.code && message.helperData.SequenceEqual(x.helperData));
                            if (queueMediumPriority[msg_index].length < message.length)
                            {
                                queueMediumPriority[msg_index] = message;
                            }
                            return;
                        }
                    }

                    if (queueMediumPriority.Exists(x => x.code == message.code && x.checksum == message.checksum))
                    {
                        Logging.trace("Attempting to add a duplicate message (code: {0}) to the network queue", code);
                        return;
                    }

                    queueMediumPriority.Add(message);
                }
                return;
            }

            lock (queueLowPriority)
            {
                // Move block related messages to txqueue
                bool found_get_request = false;
                bool found_tx_request = false;
                switch (code)
                {
#pragma warning disable CS0618 // Type or member is obsolete
                    case ProtocolMessageCode.getTransaction3:
                    case ProtocolMessageCode.getTransactions2:
                    case ProtocolMessageCode.getBlock3:
                    case ProtocolMessageCode.getBlockHeaders3:
                    case ProtocolMessageCode.getRelevantBlockTransactions:
                    case ProtocolMessageCode.getSignatures2:
                    case ProtocolMessageCode.getSignatures3:
                    case ProtocolMessageCode.getBlockSignatures2:
                    case ProtocolMessageCode.getPIT2:
#pragma warning restore CS0618 // Type or member is obsolete
                        found_get_request = true;
                        found_tx_request = true;
                        break;

#pragma warning disable CS0618 // Type or member is obsolete
                    case ProtocolMessageCode.transactionsChunk3:
                    case ProtocolMessageCode.transactionData2:
                    case ProtocolMessageCode.blockHeaders3:
                    case ProtocolMessageCode.compactBlockHeaders1:
                    case ProtocolMessageCode.blockData2:
                    case ProtocolMessageCode.pitData2:
                    case ProtocolMessageCode.inventory2:
#pragma warning restore CS0618 // Type or member is obsolete
                        found_get_request = false;
                        found_tx_request = true;
                        break;
                }
                if(found_tx_request)
                {
                    if(found_get_request)
                    {
                        if (message.helperData != null)
                        {
                            if (queueLowPriority.Exists(x => x.code == message.code && x.helperData.SequenceEqual(message.helperData) && x.endpoint == message.endpoint))
                            {
                                int msg_index = queueLowPriority.FindIndex(x => x.code == message.code && message.helperData.SequenceEqual(x.helperData));
                                if (queueLowPriority[msg_index].length < message.length)
                                {
                                    queueLowPriority[msg_index] = message;
                                }
                                return;
                            }
                        }

                        if (queueLowPriority.Exists(x => x.code == message.code && x.checksum == message.checksum && x.endpoint == message.endpoint))
                        {
                            Logging.trace("Attempting to add a duplicate message (code: {0}) to the network queue", code);
                            return;
                        }
                    }
                    else
                    {
                        if (message.helperData != null)
                        {
                            if (queueLowPriority.Exists(x => x.code == message.code && x.helperData.SequenceEqual(message.helperData)))
                            {
                                int msg_index = queueLowPriority.FindIndex(x => x.code == message.code && message.helperData.SequenceEqual(x.helperData));
                                if (queueLowPriority[msg_index].length < message.length)
                                {
                                    queueLowPriority[msg_index] = message;
                                }
                                return;
                            }
                        }

                        if (queueLowPriority.Exists(x => x.code == message.code && x.checksum == message.checksum))
                        {
                            Logging.trace("Attempting to add a duplicate message (code: {0}) to the network queue", code);
                            return;
                        }
                    }

                    bool add = true;
                    if (queueLowPriority.Count > 20)
                    {
                        switch (code)
                        {
#pragma warning disable CS0618 // Type or member is obsolete
                            case ProtocolMessageCode.getTransaction3:
                            case ProtocolMessageCode.getTransactions2:
                            case ProtocolMessageCode.getBlock3:
                            case ProtocolMessageCode.getBlockHeaders3:
                            case ProtocolMessageCode.getRelevantBlockTransactions:
                            case ProtocolMessageCode.blockData2:
                            case ProtocolMessageCode.getSignatures2:
                            case ProtocolMessageCode.getSignatures3:
                            case ProtocolMessageCode.getBlockSignatures2:
                            case ProtocolMessageCode.getPIT2:
                            case ProtocolMessageCode.inventory2:
#pragma warning restore CS0618 // Type or member is obsolete
                                {
                                    queueLowPriority.Insert(5, message);
                                    add = false;
                                    break;
                                }
                        }
                    }
                    if (add)
                    {
                        // Add it to the tx queue
                        queueLowPriority.Add(message);
                    }
                    return;
                }
            }

            lock (queueHighPriority)
            {
                // ignore duplicates
                if (queueHighPriority.Exists(x => x.code == message.code && x.checksum == message.checksum && x.endpoint == message.endpoint))
                {
                    Logging.trace("Attempting to add a duplicate message (code: {0}) to the network queue", code);
                    return;
                }

                // Handle normal messages, but prioritize block-related messages
                switch (code)
                {
                    case ProtocolMessageCode.bye:
                    case ProtocolMessageCode.hello:
                    case ProtocolMessageCode.helloData:
                        queueHighPriority.Insert(0, message);
                        return;

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
                        // Prioritize if queue is large
                        if (queueHighPriority.Count > 10)
                        {
                            queueHighPriority.Insert(5, message);
                            return;
                        }

                        break;
                }

                // Add it to the normal queue
                queueHighPriority.Add(message);
            }
        }


        // Start the network queue
        public static void start()
        {
            if (running)
            {
                Logging.info("Network queue already running.");
                return;
            }

            running = true;

            shouldStop = false;
            queueHighPriority.Clear();
            queueMediumPriority.Clear();
            queueLowPriority.Clear();

            TLC = new ThreadLiveCheck();

            queueHighPriorityThread = new Thread(queueHighPriorityLoop);
            queueHighPriorityThread.Name = "Network_Queue_High_Priority_Thread";
            queueHighPriorityThread.Start();

            queueMediumPriorityThread = new Thread(queueMediumPriorityLoop);
            queueMediumPriorityThread.Name = "Network_Queue_Medium_Priority_Thread";
            queueMediumPriorityThread.Start();

            queueLowPriorityThread = new Thread(queueLowPriorityLoop);
            queueLowPriorityThread.Name = "Network_Queue_Low_Priority_Thread";
            queueLowPriorityThread.Start();

            Logging.info("Network queue thread started.");
        }

        // Signals all the queue threads to stop
        public static bool stop()
        {
            shouldStop = true;
            running = false;

            if (queueHighPriorityThread != null)
            {
                queueHighPriorityThread.Interrupt();
                queueHighPriorityThread.Join();
                queueHighPriorityThread = null;
            }

            if (queueMediumPriorityThread != null)
            {
                queueMediumPriorityThread.Interrupt();
                queueMediumPriorityThread.Join();
                queueMediumPriorityThread = null;
            }

            if (queueLowPriorityThread != null)
            {
                queueLowPriorityThread.Interrupt();
                queueLowPriorityThread.Join();
                queueLowPriorityThread = null;
            }

            return true;
        }

        // Resets the network queues
        public static void reset()
        {
            lock (queueHighPriority)
            {
                queueHighPriority.Clear();
            }

            lock (queueMediumPriority)
            {
                queueMediumPriority.Clear();
            }

            lock (queueLowPriority)
            {
                queueLowPriority.Clear();
            }
        }

        private static void queueLoop(List<QueueMessageRecv> queue)
        {
            // Prepare an special message object to use while receiving and parsing, without locking up the queue messages
            QueueMessageRecv active_message = new QueueMessageRecv();
            try
            {
                while (!shouldStop)
                {
                    TLC.Report();
                    bool message_found = false;
                    lock (queue)
                    {
                        if (queue.Count > 0)
                        {
                            // Pick the oldest message
                            active_message = queue[0];
                            message_found = true;
                            // Remove it from the queue
                            queue.RemoveAt(0);
                        }
                    }

                    if (message_found)
                    {
                        Logging.trace("Received {0} ({1}B) - {2}...", active_message.code, active_message.data.Length, Crypto.hashToString(active_message.data.Take(60).ToArray()));
                        // Active message set, attempt to parse it
                        IxianHandler.parseProtocolMessage(active_message.code, active_message.data, active_message.endpoint);
                    }
                    else
                    {
                        // Sleep for 10ms to prevent cpu waste
                        Thread.Sleep(10);
                    }
                }
            } catch (ThreadInterruptedException)
            {
                // Thread interrupted, exit
            }

            Logging.info("Network queue thread stopped.");
        }

        public static void queueHighPriorityLoop()
        {
            queueLoop(queueHighPriority);
        }

        public static void queueMediumPriorityLoop()
        {
            queueLoop(queueMediumPriority);
        }

        public static void queueLowPriorityLoop()
        {
            queueLoop(queueLowPriority);
        }
    }
}

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

namespace IXICore
{
    /// <summary>
    /// Basic Ixian (compile-time) configuration values.
    /// </summary>
    class CoreConfig
    {
        /// <summary>
        /// Current version of IxiCore.
        /// </summary>
        public static readonly string version = "xcore-0.9.7d";

        /// <summary>
        /// Current version of the Ixian network protocol.
        /// </summary>
        public static readonly int protocolVersion = 6;

        /// <summary>
        /// Mainnet block height at which the current version of IxiCore was generated
        /// Useful for optimized block header sync
        /// Note: Always round last block height to 1000 and subtract 1 (i.e. if last block height is 33234, the correct value is 32999)
        /// </summary>
        public static ulong bakedBlockHeight = 5360999;

        /// <summary>
        /// Mainnet block checksum (paired with bakedBlockHeight) of bakedBlockHeight
        /// Useful for optimized block header sync
        /// </summary>
        public static byte[] bakedBlockChecksum = Crypto.stringToHash("35f7390ce56c84aac4212606be0a3a5ce24d6432976df5643f9cf3f61f5481263f4390adf1dc64b53114d644e914f27a0d156bc36a44fb1cb4805f7c22116781");

        /// <summary>
        /// Number of wallets to send in each chunk of data when synchronizing new Master Nodes.
        /// </summary>
        public static readonly int walletStateChunkSplit = 10000;

        /// <summary>
        ///  This value is used when clients subscribe to events on their connected Master Nodes.
        /// </summary>
        /// <remarks>
        ///  The best privacy would be achieved if the Master Node forwards all Transactions to all clients, who then sort out the 'interesting' ones.
        ///  In this way, the Master Node does not know which addresses are the client's. This, however, is impractical due to the number of transactions and clients each
        ///  Master node should support.
        ///  On the other hand, if a client specifies which addresses it's interested in, this could be a potential leak of information, allowing Master Nodes
        ///  to infer which Wallets are associated with each other and reduce the privacy element of the Ixian DLT Network.
        ///  A specialized algorithm has been developed which allows the client to subscribe to *some* Wallet addresses, but not all, with potential false positives to further obscure the details.
        ///  This will reduce the required bandwidth on the Master Node, while preventing the Master Node from immediately knowing which addresses belong to the client
        ///  (until a transaction for that address appears on the blockchain).
        ///  The setting `matcherBytesPerAddress` selects how precise this matching is and how many false positives it creates. Better precision decreases privacy, but lower precision increases the
        ///  Master Node bandwidth requirements. A balanced default value is chosen here.
        /// </remarks>
        public static readonly int matcherBytesPerAddress = 4;


        /// <summary>
        ///  Maximum number of messages in the incoming network queue, before the connection are throttled.
        /// </summary>
        public static readonly int maxNetworkQueue = 10000;
        /// <summary>
        ///  Maximum number of outgoing messages in the queue per each remote endpoint.
        /// </summary>
        public static readonly int maxSendQueue = 10000;
        /// <summary>
        ///  Maximum size of a network message in bytes.
        /// </summary>
        public static readonly int maxMessageSize = 50000000;
        /// <summary>
        ///  Pong interval (in seconds) - if no data has been received from connected remote client for this time, a special packet will be sent instead to 'wake up' the receiver.
        /// </summary>
        public static readonly int pongInterval = 2;
        /// <summary>
        ///  Timeout (in seconds) before a remote client is disconnected if no data is received from it.
        /// </summary>
        public static readonly int pingTimeout = 10;
        /// <summary>
        /// Duration (in milliseconds) between reconnection attempts to remote clients.
        /// </summary>
        public static readonly int networkClientReconnectInterval = 2 * 1000;
        
        /// <summary>
        /// Interval (in seconds) how often to send a 'Keep-Alive' presence packet into the network for server (M, H) nodes.
        /// </summary>
        public static readonly int serverKeepAliveInterval = 100;

        /// <summary>
        /// Interval (in seconds) how often to send a 'Keep-Alive' presence packet into the network for relay (R) nodes.
        /// </summary>
        public static readonly int relayKeepAliveInterval = 200;

        /// <summary>
        /// Interval (in seconds) how often to send a 'Keep-Alive' presence packet into the network for client nodes.
        /// </summary>
        public static readonly int clientKeepAliveInterval = 100;
        
        /// <summary>
        /// Presence list entry expiration time (in seconds) for server presences
        /// </summary>
        public static readonly int serverPresenceExpiration = 300;

        /// <summary>
        /// Presence list entry expiration time (in seconds) for client presences
        /// </summary>
        public static int clientPresenceExpiration = 300;

        /// <summary>
        /// Number of retries when connecting to a neighbor node, before giving up.
        /// </summary>
        public static int maximumNeighborReconnectCount = 3;
        /// <summary>
        /// Maximum number of events a client can be subscribed to.
        /// </summary>
        public static int maximumSubscribableEvents = 500;
        /// <summary>
        /// Maximum number of neighbor Master Nodes this server can accept (used in DLT Node executable).
        /// </summary>
        public static int maximumServerMasterNodes = 200;
        /// <summary>
        /// Maximum number of client connections this server can accept (used in DLT Node executable).
        /// </summary>
        public static int maximumServerClients = 200;

        /// <summary>
        ///  If set to true, all threads will report liveness periodically, thus enabling checking for deadlocks.
        /// </summary>
        /// <remarks>
        ///  See class `ThreadLiveCheck` for details.
        /// </remarks>
        public static readonly bool threadLiveCheckEnabled = false;

        /// <summary>
        /// Unique node identifier
        /// </summary>
        public static byte[] device_id = System.Guid.NewGuid().ToByteArray();

        /// <summary>
        /// Product version.
        /// </summary>
        public static string productVersion = "";

        /// <summary>
        /// Number of block headers to save in a single file.
        /// </summary>
        public static ulong maxBlockHeadersPerDatabase = 1000;

        /// <summary>
        /// Prevents client/server network operations. Useful for offline data verification and other offline tests.
        /// </summary>
        public static bool preventNetworkOperations = false;

        /// <summary>
        /// Maximum time difference adjustment in seconds. Clock.networkTime value will not be adjusted to above this number.
        /// </summary>
        public static long maxTimeDifferenceAdjustment = 30;

        /// <summary>
        /// Minimum blockheight activity to store
        /// </summary>
        public static long minActivityBlockHeight = 30000;

        /// <summary>
        /// Time in seconds of how long the node will remain on the blacklist, once blacklisted
        /// </summary>
        public static long NodeBlacklistExpiration = 43200;

        /// <summary>
        /// Maximum number of items to be read from inventory.
        /// </summary>
        public static int maxInventoryItems = 500;

        /// <summary>
        /// Interval at which to send inventory packets in seconds.
        /// </summary>
        public static int inventoryInterval = 1;

        /// <summary>
        /// Maximum number of keep alives to be included in the keep alive chunk.
        /// </summary>
        public static int maximumKeepAlivesPerChunk = 500;

        /// <summary>
        /// Maximum number of transactions sent in each chunk when a fresh DLT Node is synchronizing. (Used in DLT Node executable.)
        /// </summary>
        public static int maximumTransactionsPerChunk = 500;

        /// <summary>
        /// Maximum number of transactions to be included in the tx chunk.
        /// </summary>
        public static int maximumBlockHeadersPerChunk = 1000;

        /// <summary>
        /// Maximum number of requested message ids to keep in memory.
        /// </summary>
        public static long maximumRequestedMessageIds = 100000;

        /// <summary>
        /// Number of seconds to check block signature's inclusion in PL.
        /// </summary>
        public static int blockSignaturePlCheckTimeout = 450;

        /// <summary>
        /// Relay sector levels for indexing. Higher value increases performance at the cost of memory.
        /// </summary>
        public static int relaySectorLevels = 4;

        public static int maxRelaySectorNodesToRequest = 6;
        public static int contactSectorNodeIntervalSeconds = clientPresenceExpiration / 2;
        public static int requestPresenceTimeout = 30;

        public static int messageExpirationSeconds = 86400 * 5; // 5 Days
    }
}

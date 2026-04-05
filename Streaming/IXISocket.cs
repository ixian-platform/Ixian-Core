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
using IXICore.Network;
using IXICore.Streaming.Models;
using IXICore.Utils;
using System.Threading.Channels;

namespace IXICore.Streaming
{
    /// <summary>
    /// Provider responsible for fetching sector nodes for a friend.
    /// Uses CoreStreamProcessor.fetchFriendsPresence to retrieve sector nodes.
    /// </summary>
    public class ClientSectorProvider : ISectorProvider
    {
        private readonly int _timeoutMs;

        public ClientSectorProvider(int timeoutMs = 5000)
        {
            _timeoutMs = timeoutMs;
        }

        /// <summary>
        /// Fetches sector nodes for the friend. Initiates a fetch request and waits for the nodes to be populated.
        /// </summary>
        /// <param name="friend">Friend for which to fetch sector nodes</param>
        /// <returns>List of sector nodes, or empty list if timeout occurs</returns>
        public async Task<List<Peer>> FetchSectorNodesAsync(Friend friend)
        {
            if (friend.sectorNodes.Count > 0)
            {
                return friend.sectorNodes;
            }

            // Initiate the fetch
            CoreProtocolMessage.fetchSectorNodes(friend.walletAddress, CoreConfig.maxRelaySectorNodesToRequest);

            // Wait for sector nodes to be populated
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            while (friend.sectorNodes.Count == 0 && stopwatch.ElapsedMilliseconds < _timeoutMs)
            {
                await Task.Delay(100).ConfigureAwait(false);
            }
            stopwatch.Stop();

            return friend.sectorNodes;
        }
    }

    /// <summary>
    /// Provider responsible for fetching presence information from sector nodes.
    /// Manages direct NetworkClient connections to sector nodes and retrieves presence data with retry logic.
    /// </summary>
    public class PresenceProvider
    {
        private readonly Friend _friend;
        private readonly int _timeoutPerNodeMs;
        private readonly int _maxRetries;
        private readonly int _helloTimeoutMs;

        public PresenceProvider(Friend friend, int timeoutPerNodeMs = 1000, int maxRetries = 3, int helloTimeoutMs = 2000)
        {
            _friend = friend ?? throw new ArgumentNullException(nameof(friend));
            _timeoutPerNodeMs = timeoutPerNodeMs;
            _maxRetries = maxRetries;
            _helloTimeoutMs = helloTimeoutMs;
        }

        /// <summary>
        /// Attempts to fetch presence information from sector nodes with retry logic.
        /// </summary>
        /// <returns>True if presence information was successfully obtained, false otherwise</returns>
        public async Task<bool> FetchPresenceAsync()
        {
            if (_friend.sectorNodes.Count == 0)
            {
                return false;
            }

            // Try to fetch presence from available sector nodes
            for (int attempt = 0; attempt < _maxRetries; attempt++)
            {
                // Try each sector node
                foreach (var sectorNode in _friend.sectorNodes)
                {
                    if (await TryFetchPresenceFromNodeAsync(sectorNode).ConfigureAwait(false))
                    {
                        return true;
                    }
                }

                // If all nodes failed and we have retries left, wait before retrying
                if (attempt < _maxRetries - 1)
                {
                    await Task.Delay(200).ConfigureAwait(false);
                }
            }

            return false;
        }

        /// <summary>
        /// Attempts to fetch presence from a single sector node with timeout.
        /// Creates a direct NetworkClient connection, waits for hello handshake, and requests presence information.
        /// </summary>
        private async Task<bool> TryFetchPresenceFromNodeAsync(Peer sectorNode)
        {
            NetworkClient? client = null;

            Channel<QueueMessageRaw> presenceQueue = Channel.CreateUnbounded<QueueMessageRaw>();

            try
            {
                // Create a custom handler to capture presence response
                Action<QueueMessageRaw, MessagePriority, RemoteEndpoint> handler = (message, priority, endpoint) =>
                {
                    if (!endpoint.isConnected())
                    {
                        return;
                    }
                    // Check if this is a presence response
                    if (message.code == ProtocolMessageCode.updatePresence)
                    {
                        Logging.trace("Received presence response from sector node {0}", sectorNode.hostname);

                        Presence? p = PresenceList.updateFromBytes(message.data, IxianHandler.getMinSignerPowDifficulty(IxianHandler.getLastBlockHeight(), IxianHandler.getLastBlockVersion(), 0));
                        if (p == null)
                        {
                            p = PresenceList.getPresenceByAddress(_friend.walletAddress);
                        }
                        if (p != null && p.wallet.SequenceEqual(_friend.walletAddress))
                        {
                            // TODO use actual wallet address once Presence hostname contains such address
                            _friend.relayNode = new Peer(p.addresses[0].address, null, p.addresses[0].lastSeenTime, 0, 0, 0);
                            Logging.warn("Setting relay node to {0}", _friend.relayNode.hostname);
                            _friend.setPublicKey(p.pubkey);
                            presenceQueue.Writer.TryWrite(message);
                        }
                    }
                    else if (message.code == ProtocolMessageCode.helloData)
                    {
                        using (MemoryStream m = new MemoryStream(message.data))
                        {
                            using (BinaryReader reader = new BinaryReader(m))
                            {
                                if (!CoreProtocolMessage.processHelloMessageV6(endpoint, reader))
                                {
                                    return;
                                }

                                endpoint.helloReceived = true;
                            }
                        }
                    } else
                    {
                        Logging.trace("Unhandled message code {0} from sector node {1}", message.code, sectorNode.hostname);
                    }
                };

                // Create a direct NetworkClient connection with the custom handler
                client = new NetworkClient(null, handler);
                client.reconnectOnFailure = false;

                // Connect to the sector node
                Logging.trace("Connecting to sector node {0}", sectorNode.hostname);
                string[] server = sectorNode.hostname.Split(':');
                if (!await client.connectToServer(server[0], int.Parse(server[1]), sectorNode.walletAddress).ConfigureAwait(false))
                {
                    Logging.trace("Failed to establish connection to sector node {0}", sectorNode.hostname);
                    return false;
                }

                // Wait for hello handshake to complete (NetworkClient sends hello data automatically)
                var helloStopwatch = System.Diagnostics.Stopwatch.StartNew();
                while (!client.helloReceived && helloStopwatch.ElapsedMilliseconds < _helloTimeoutMs)
                {
                    await Task.Delay(50).ConfigureAwait(false);
                }
                helloStopwatch.Stop();

                if (!client.helloReceived)
                {
                    Logging.trace("Hello handshake timeout for sector node {0}", sectorNode.hostname);
                    return false;
                }

                Logging.trace("Hello handshake complete with sector node {0}", sectorNode.hostname);

                // Request presence information from the sector node
                RequestPresenceFromClient(client);

                // Wait for presence response or timeout
                Task presenceTask = presenceQueue.Reader.ReadAsync().AsTask();
                var completed = await Task.WhenAny(presenceTask, Task.Delay(_timeoutPerNodeMs)).ConfigureAwait(false);

                if (completed == presenceTask && presenceTask.IsCompletedSuccessfully)
                {
                    if (_friend.relayNode != null)
                    {
                        Logging.trace("Successfully obtained presence information from sector node {0}", sectorNode.hostname);
                        return true;
                    }
                }

                Logging.trace("Did not receive presence information from sector node {0} within timeout", sectorNode.hostname);
                return false;
            }
            catch (Exception e)
            {
                Logging.warn("Failed to fetch presence from sector node {0}: {1}", sectorNode.hostname, e.Message);
                return false;
            }
            finally
            {
                // Clean up the connection
                if (client != null)
                {
                    try
                    {
                        CoreProtocolMessage.sendBye(client, ProtocolByeCode.bye, "", "", false);
                        client.stopAsync();
                    }
                    catch (Exception e)
                    {
                        Logging.warn("Error stopping sector node connection {0}: {1}", sectorNode.hostname, e.Message);
                    }
                }
            }
        }

        /// <summary>
        /// Requests presence information for the friend from the given client.
        /// </summary>
        private void RequestPresenceFromClient(NetworkClient client)
        {
            try
            {
                using (var mw = new MemoryStream())
                {
                    using (var writer = new BinaryWriter(mw))
                    {
                        writer.WriteIxiBytes(_friend.walletAddress.addressNoChecksum);
                    }

                    Logging.trace("Requesting presence for {0} from sector node", _friend.walletAddress.ToString());
                    client.sendData(ProtocolMessageCode.getPresence2, mw.ToArray());
                }
            }
            catch (Exception e)
            {
                Logging.warn("Failed to request presence from sector node: {0}", e.Message);
            }
        }
    }

    /// <summary>
    /// IXI Socket for establishing connections to remote IXI addresses.
    /// Orchestrates the complete connection flow: fetch sector nodes, get presence info, and connect to relay node.
    /// </summary>
    public class IXISocket : IDisposable
    {
        private readonly Friend _friend;
        private readonly ISectorProvider _sectorProvider;
        private readonly PresenceProvider _presenceProvider;
        private NetworkClient? _relayConnection;
        private bool _isConnected;
        public IxianKeyPair _keyPair { get; private set; }

        private readonly object _connectionLock = new object();
        private Channel<StreamMessage> _responseQueue = Channel.CreateUnbounded<StreamMessage>();

        public event EventHandler<ConnectionStateChangedEventArgs>? ConnectionStateChanged;

        public IXISocket(Friend friend, ISectorProvider sectorProvider, PresenceProvider presenceProvider, IxianKeyPair? keyPair = null)
        {
            _friend = friend ?? throw new ArgumentNullException(nameof(friend));
            _sectorProvider = sectorProvider;
            _presenceProvider = presenceProvider;
            _isConnected = false;
            _keyPair = keyPair ?? CryptoManager.lib.generateKeys(ConsensusConfig.defaultRsaKeySize, 1);
        }

        /// <summary>
        /// Gets the current connection status.
        /// </summary>
        public bool IsConnected
        {
            get
            {
                lock (_connectionLock)
                {
                    return _isConnected && _relayConnection != null && _relayConnection.isConnected();
                }
            }
        }

        /// <summary>
        /// Establishes a connection to the IXI address through relay nodes.
        /// Follows the complete connection flow.
        /// </summary>
        /// <returns>True if connection was successful, false otherwise</returns>
        public async Task<bool> ConnectAsync()
        {
            lock (_connectionLock)
            {
                if (_isConnected && _relayConnection != null && _relayConnection.isConnected())
                {
                    Logging.info("Already connected to {0}", _friend.walletAddress.ToString());
                    return true;
                }
            }

            try
            {
                Logging.info("Starting IXI Socket connection to {0}", _friend.walletAddress.ToString());

                // Step 1: Fetch sector nodes
                Logging.trace("Fetching sector nodes for {0}", _friend.walletAddress.ToString());
                var sectorNodes = await _sectorProvider.FetchSectorNodesAsync(_friend).ConfigureAwait(false);
                if (sectorNodes.Count == 0)
                {
                    Logging.warn("Failed to fetch sector nodes for {0}", _friend.walletAddress.ToString());
                    OnConnectionStateChanged(false, "Failed to fetch sector nodes");
                    return false;
                }

                Logging.trace("Fetched {0} sector nodes for {1}", sectorNodes.Count, _friend.walletAddress.ToString());

                // Step 2: Fetch presence information from sector nodes
                Logging.trace("Fetching presence information");
                bool presenceFetched = await _presenceProvider.FetchPresenceAsync().ConfigureAwait(false);
                if (!presenceFetched || _friend.relayNode == null)
                {
                    Logging.warn("Failed to fetch presence information for {0}", _friend.walletAddress.ToString());
                    OnConnectionStateChanged(false, "Failed to fetch presence information");
                    return false;
                }

                Logging.trace("Successfully fetched presence, relay node: {0}", _friend.relayNode.hostname);

                // Step 3: Connect to the relay node and exchange keys
                Logging.trace("Connecting to relay node {0}:{1}", _friend.relayNode.hostname, _friend.relayNode.walletAddress);
                if (!await ConnectToRelayNodeAsync().ConfigureAwait(false))
                {
                    Logging.warn("Failed to connect to relay node for {0}", _friend.walletAddress.ToString());
                    OnConnectionStateChanged(false, "Failed to connect to relay node");
                    return false;
                }

                lock (_connectionLock)
                {
                    _isConnected = true;
                }

                OnConnectionStateChanged(true, "Connected successfully");
                Logging.info("Successfully connected to {0}", _friend.walletAddress.ToString());

                return true;
            }
            catch (Exception e)
            {
                Logging.error("Exception in IXISocket.ConnectAsync: {0}", e);
                OnConnectionStateChanged(false, $"Exception: {e.Message}");
                return false;
            }
        }

        /// <summary>
        /// Connects to the relay node specified in the friend's presence information.
        /// Establishes connection and awaits key exchange completion.
        /// </summary>
        private async Task<bool> ConnectToRelayNodeAsync()
        {
            if (_friend.relayNode == null)
            {
                return false;
            }

            TaskCompletionSource<bool>? keyExchangeCompleteTcs = new TaskCompletionSource<bool>();

            try
            {
                // Create a custom handler to capture key exchange and data responses
                Action<QueueMessageRaw, MessagePriority, RemoteEndpoint> handler = (message, priority, endpoint) =>
                {
                    if (!endpoint.isConnected())
                    {
                        return;
                    }

                    // Check if this is a key exchange message
                    if (message.code == ProtocolMessageCode.s2data)
                    {
                        var streamMessage = new StreamMessage(message.data);
                        if (streamMessage.encryptionType == StreamMessageEncryptionCode.none
                            && streamMessage.type != StreamMessageCode.error)
                        {
                            Logging.warn("Received unencrypted message from relay node {0}, which is not supported. Message type: {1}", _friend.relayNode.hostname, streamMessage.type);
                            Disconnect();
                            return;
                        }

                        if (streamMessage.encryptionType == StreamMessageEncryptionCode.rsa
                            || streamMessage.encryptionType == StreamMessageEncryptionCode.rsa2)
                        {
                            if (!streamMessage.verifySignature(_friend.publicKey))
                            {
                                Logging.warn("Failed to verify signature of RSA encrypted message from relay node {0}", _friend.relayNode.hostname);
                                Disconnect();
                                return;
                            }
                        }

                        if (!streamMessage.decrypt(_keyPair.privateKeyBytes, _friend.aesKey, _friend.chachaKey)
                            || streamMessage.type == StreamMessageCode.error)
                        {
                            Logging.warn("Received error stream message from relay node {0}", _friend.relayNode.hostname);
                            Disconnect();
                            return;
                        }

                        var spixiMessage = new SpixiMessage(streamMessage.data);
                        if (spixiMessage.type == SpixiMessageCode.acceptAdd2)
                        {
                            Logging.trace("Received key accept add from relay node {0}", _friend.relayNode.hostname);
                            CoreStreamProcessor.handleAcceptAdd2(_friend, new AcceptAdd2Message(spixiMessage.data), endpoint);
                            return;
                        }
                        else if (spixiMessage.type == SpixiMessageCode.msgReceived)
                        {
                            if (keyExchangeCompleteTcs != null
                                && spixiMessage.data.SequenceEqual(new byte[] { 2 }))
                            {
                                Logging.trace("Received key exchange response from relay node {0}", _friend.relayNode.hostname);
                                _friend.handshakeStatus = 3;
                                keyExchangeCompleteTcs.TrySetResult(true);
                            }
                            return;
                        }
                        _responseQueue.Writer.TryWrite(streamMessage);
                    }
                    else if (message.code == ProtocolMessageCode.helloData)
                    {
                        using (MemoryStream m = new MemoryStream(message.data))
                        {
                            using (BinaryReader reader = new BinaryReader(m))
                            {
                                if (!CoreProtocolMessage.processHelloMessageV6(endpoint, reader))
                                {
                                    return;
                                }

                                endpoint.helloReceived = true;
                            }
                        }
                    }
                };

                // Create a direct NetworkClient connection with custom handler
                var client = new NetworkClient(null, handler);
                client.reconnectOnFailure = false;
                client.ephemeralKeyPair = _keyPair;

                string[] server = _friend.relayNode.hostname.Split(':');
                if (!await client.connectToServer(server[0], int.Parse(server[1]), _friend.relayNode.walletAddress).ConfigureAwait(false))
                {
                    Logging.warn("Failed to establish connection to relay node {0}", _friend.relayNode.hostname);
                    return false;
                }

                // Wait for hello handshake (NetworkClient sends hello data automatically)
                var helloStopwatch = System.Diagnostics.Stopwatch.StartNew();
                while (!client.helloReceived && helloStopwatch.ElapsedMilliseconds < 2000)
                {
                    await Task.Delay(50).ConfigureAwait(false);
                }
                helloStopwatch.Stop();

                if (!client.helloReceived)
                {
                    Logging.warn("Hello handshake timeout with relay node {0}", _friend.relayNode.hostname);
                    return false;
                }

                Logging.trace("Hello handshake complete with relay node {0}, sending connect request", _friend.relayNode.hostname);

                // Send the connect request to initiate key exchange
                CoreStreamProcessor.sendOpenSecureConnection(client, _friend);

                // Wait for key exchange to complete with timeout
                var keyExchangeTask = keyExchangeCompleteTcs.Task;
                var completed = await Task.WhenAny(keyExchangeTask, Task.Delay(5000)).ConfigureAwait(false);

                if (completed == keyExchangeTask && keyExchangeTask.IsCompletedSuccessfully)
                {
                    keyExchangeCompleteTcs = null;
                    Logging.trace("Key exchange completed with target node {0}", _friend.relayNode.hostname);
                    lock (_connectionLock)
                    {
                        _relayConnection = client;
                    }
                    return true;
                }

                Logging.warn("Key exchange timeout with target node {0}", _friend.relayNode.hostname);
                keyExchangeCompleteTcs.TrySetCanceled();
                keyExchangeCompleteTcs = null;
                CoreProtocolMessage.sendBye(client, ProtocolByeCode.bye, "", "", false);
                client.stopAsync();
                return false;
            }
            catch (Exception e)
            {
                Logging.error("Failed to connect to relay node {0}: {1}", _friend.relayNode.hostname, e);
                return false;
            }
        }

        /// <summary>
        /// Sends S2 data through the established relay connection and awaits the response.
        /// </summary>
        /// <param name="data">The S2 data to send</param>
        /// <param name="timeoutMs">Timeout in milliseconds to wait for response (default: 10000ms)</param>
        /// <returns>The response data received from the relay, or null if failed or timeout</returns>
        public async Task<StreamMessage?> SendDataAsync(byte[] data, int timeoutMs = 10000)
        {
            lock (_connectionLock)
            {
                if (!_isConnected || _relayConnection == null || !_relayConnection.isConnected())
                {
                    Logging.warn("Cannot send data: not connected to {0}", _friend.walletAddress.ToString());
                    return null;
                }

                try
                {
                    Logging.trace("Sending S2 data to {0}", _friend.walletAddress.ToString());
                    _relayConnection.sendData(ProtocolMessageCode.s2data, data);
                }
                catch (Exception e)
                {
                    Logging.error("Error sending data to {0}: {1}", _friend.walletAddress.ToString(), e.Message);
                    return null;
                }
            }

            try
            {
                // Wait for response with timeout
                var responseTask = _responseQueue.Reader.ReadAsync().AsTask();
                var completed = await Task.WhenAny(responseTask, Task.Delay(timeoutMs)).ConfigureAwait(false);

                if (completed == responseTask && responseTask.IsCompletedSuccessfully)
                {
                    Logging.trace("Received response from {0}", _friend.walletAddress.ToString());
                    return responseTask.Result;
                }

                Logging.warn("Response timeout from {0}", _friend.walletAddress.ToString());
                return null;
            }
            catch (Exception e)
            {
                Logging.error("Error awaiting response from {0}: {1}", _friend.walletAddress.ToString(), e.Message);
                return null;
            }
        }

        /// <summary>
        /// Disconnects from the relay node and cleans up resources.
        /// </summary>
        public void Disconnect()
        {
            lock (_connectionLock)
            {
                if (_relayConnection != null)
                {
                    try
                    {
                        CoreStreamProcessor.sendCloseSecureConnection(_relayConnection, _friend);
                        CoreProtocolMessage.sendBye(_relayConnection, ProtocolByeCode.bye, "", "", false);
                        _relayConnection.stopAsync();
                    }
                    catch (Exception e)
                    {
                        Logging.warn("Error disconnecting relay connection: {0}", e.Message);
                    }
                    finally
                    {
                        _relayConnection = null;
                    }
                }

                _isConnected = false;
            }

            OnConnectionStateChanged(false, "Disconnected");
        }

        /// <summary>
        /// Raises the ConnectionStateChanged event.
        /// </summary>
        private void OnConnectionStateChanged(bool isConnected, string reason)
        {
            ConnectionStateChanged?.Invoke(this, new ConnectionStateChangedEventArgs(isConnected, reason));
        }

        public void Dispose()
        {
            Disconnect();
        }
    }

    /// <summary>
    /// Event arguments for connection state changes.
    /// </summary>
    public class ConnectionStateChangedEventArgs : EventArgs
    {
        public bool IsConnected { get; }
        public string Reason { get; }

        public ConnectionStateChangedEventArgs(bool isConnected, string reason)
        {
            IsConnected = isConnected;
            Reason = reason ?? string.Empty;
        }
    }
}

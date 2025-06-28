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
using System;
using System.Net.Sockets;

namespace IXICore.Network
{
    /// <summary>
    ///  Implementation of the `RemoteEndpoint` interface as an Ixian network client.
    /// </summary>
    public class NetworkClient : RemoteEndpoint
    {
        /// <summary>
        ///  Unerlying framework connection, if an operation must be performed directly on it.
        /// </summary>
        public TcpClient tcpClient = null;

        private string tcpHostname = "";
        private int tcpPort = 0;
        private int totalReconnects = 0;

        private object reconnectLock = new object();

        public string myAddress = ""; // My address as reported by the node

        public NetworkClient()
        {
            prepareClient();
        }

        // Prepare the client socket
        private void prepareClient()
        {
            tcpClient = new TcpClient();


            Socket tmpSocket = tcpClient.Client;

            // Don't allow another socket to bind to this port.
            tmpSocket.ExclusiveAddressUse = true;

            prepareSocket(tmpSocket);
        }

        /// <summary>
        ///  Establishes connection to the given hostname and port. An expected remote wallet address must be provided
        ///  before a connection to the Ixian network can be made safely.
        /// </summary>
        /// <param name="hostname">Hostname or IP address of the remote server</param>
        /// <param name="port">Port on which to connect</param>
        /// <param name="wallet_address">Expected wallet address of the remote server we are connecting to.</param>
        /// <returns>True, if the connection was successful.</returns>
        public bool connectToServer(string hostname, int port, Address wallet_address)
        {
            if (fullyStopped)
            {
                Logging.error("Can't start a fully stopped RemoteEndpoint");
                return false;
            }

            enableSendTimeSyncMessages = false;

            helloReceived = false;
            blockHeight = 0;

            tcpHostname = hostname;
            tcpPort = port;
            address = hostname;
            fullAddress = hostname + ":" + port;
            incomingPort = port;
            serverWalletAddress = wallet_address;

            // Prepare the TCP client
            prepareClient();

            try
            {
                totalReconnects++;
                if (!tcpClient.ConnectAsync(hostname, port).Wait(5000))
                {
                    Logging.info("Network client connection to {0}:{1} has failed.", hostname, port);

                    disconnect();

                    running = false;
                    return false;
                }

                Logging.info("Network client connected to {0}:{1}", hostname, port);

                start(tcpClient.Client);
            }
            catch (SocketException se)
            {
                SocketError errorCode = (SocketError)se.ErrorCode;

                switch (errorCode)
                {
                    case SocketError.IsConnected:
                        break;

                    case SocketError.AddressAlreadyInUse:
                        Logging.warn(string.Format("Socket exception for {0}:{1} has failed. Address already in use.", hostname, port));
                        break;

                    default:
                        {
                            Logging.warn(string.Format("Socket connection for {0}:{1} has failed.", hostname, port));
                        }
                        break;
                }

                disconnect();

                running = false;
                return false;
            }
            catch (Exception)
            {
                Logging.info("Network client connection to {0}:{1} has failed.", hostname, port);

                disconnect();

                running = false;
                return false;
            }

            return true;
        }

        /// <summary>
        ///  Disconnects (optionally) and reconnects to the same remote host as was given in `connectToServer()`.
        /// </summary>
        /// <returns>True, if the connection attempt was successful.</returns>
        public bool reconnect()
        {
            lock (reconnectLock)
            {
                if (tcpHostname.Length < 1)
                {
                    Logging.warn("Network client reconnect failed due to invalid hostname.");
                    return false;
                }

                // Safely close the threads
                running = false;

                disconnect();

                Logging.info(string.Format("--> Reconnecting to {0}, total reconnects: {1}", getFullAddress(true), totalReconnects));
                return connectToServer(tcpHostname, tcpPort, serverWalletAddress);
            }
        }

        // Receive thread
        protected override void onInitialized()
        {
            base.onInitialized();
            try
            {
                Random rnd = new Random();
                CoreProtocolMessage.sendHelloMessageV6(this, false, rnd.Next());
            }catch(Exception e)
            {
                if (running)
                {
                    Logging.warn(string.Format("recvRE: Disconnected client {0} with exception {1}", getFullAddress(), e.ToString()));
                }
                state = RemoteEndpointState.Closed;
                running = false;
            }
        }

        /// <summary>
        ///  Breaks the connection to the remote server.
        /// </summary>
        public override void disconnect()
        {
            base.disconnect();
            tcpClient.Close();
        }

        /// <summary>
        ///  Returns the number of times this connection was re-established (disconnected and reconnected).
        /// </summary>
        /// <returns>Number of connection attempts.</returns>
        public int getTotalReconnectsCount()
        {
            return totalReconnects;
        }
    }

}

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
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace IXICore.Network
{
    /// <summary>
    ///  Reason for disconnection.
    /// </summary>
    public enum ProtocolByeCode
    {
        /// <summary>
        ///  An invalid `Block` was sent.
        /// </summary>
        blockInvalid = 100,
        /// <summary>
        ///  Unspecified disconnection reason.
        /// </summary>
        bye = 200,
        /// <summary>
        ///  A Master Node was expected.
        /// </summary>
        expectingMaster = 400,
        /// <summary>
        ///  A deprecated protocol was used which is not supported.
        /// </summary>
        deprecated = 501,
        /// <summary>
        ///  The connecting node is on a different network (TestNet vs. MainNet).
        /// </summary>
        incorrectNetworkType = 502,
        /// <summary>
        ///  The connecting Master Node does not have sufficient funds int he wallet to participate in consensus.
        /// </summary>
        insufficientFunds = 599, // can be removed later
                                 /// <summary>
                                 ///  The IP address specified in the Hello message was invalid. (Not a public IP address.)
                                 /// </summary>
        incorrectIp = 600,
        /// <summary>
        ///  The IP address specified in the Hello message was not reachable for a connection test.
        /// </summary>
        notConnectable = 601,
        /// <summary>
        ///  The connecting node has fallen too far behind on the blockchain.
        /// </summary>
        tooFarBehind = 602,
        /// <summary>
        ///  The authentication value does not match the connecting node's address.
        /// </summary>
        authFailed = 603,
        /// <summary>
        ///  The remote node's address does not match the known address for that node.
        /// </summary>
        addressMismatch = 604,
        /// <summary>
        ///  The connecting node has been rejected.
        /// </summary>
        rejected = 605,
        /// <summary>
        ///  The serving node isn't ready yet
        /// </summary>
        notReady = 700
    }

    /// <summary>
    ///  Codes represent types of network messages accepted by the Ixian network.
    ///  Each code implies the expected following message structure.
    /// </summary>
    public enum ProtocolMessageCode
    {
        hello = 0,
        helloData = 1,
        bye = 2,
        rejected = 3,
        //[Obsolete("Use blockData2 instead")]
        //blockData = 4,
        [Obsolete("Use inventory instead")]
        blockHeight = 5,
        getKeepAlives = 6,
        keepAlivesChunk = 7,
        transactionData2 = 8,
        blockData2 = 9,
        //[Obsolete("Use transactionData2 instead")]
        //transactionData = 10,
        //[Obsolete("Use getSignatures2 instead")]
        //getSignatures = 11,
        //[Obsolete("Use signaturesChunk2 instead")]
        //signaturesChunk = 12,
        blockSignature2 = 13,
        getBlockSignatures2 = 14,
        //[Obsolete("Use transactionsChunk3 instead")]
        //transactionsChunk = 15,
        getSignatures2 = 16,
        signaturesChunk2 = 17,
        getSectorNodes = 18,
        sectorNodes = 19,
        //blockHeaders2 = 20,
        getPIT2 = 21,
        pitData2 = 22,
        //[Obsolete("Use getTransaction3 instead")]
        //getTransaction2 = 23,
        updatePresence = 24,
        //removePresence = 25,
        s2data = 26,
        s2failed = 27,
        s2signature = 28,
        //[Obsolete("Use inventory2 instead")]
        //inventory = 29,
        getBalance2 = 30,
        balance2 = 31,
        //[Obsolete("Use getBalance2 instead")]
        //getBalance = 32,
        //[Obsolete("Use balance2 instead")]
        //balance = 33,
        keepAlivePresence = 34,
        //[Obsolete("Use getPresence2 instead")]
        //getPresence = 35,
        getPresence2 = 36,
        //[Obsolete("Use transactionsChunk3 instead")]
        //blockTransactionsChunk = 37, // deprecated
        getUnappliedTransactions = 38,
        //extend = 39,
        attachEvent = 40,
        detachEvent = 41,
        //[Obsolete("Use blockSignature2 instead")]
        //blockSignature = 42,
        getNameRecord = 43,
        nameRecord = 44,
        getNextSuperBlock = 45,
        getBlockHeaders3 = 46,
        blockHeaders3 = 47,
        getRandomPresences = 48,
        // Temporary protocol message, until we fully enable p2p transactions
        getRelevantBlockTransactions = 49,
        compactBlockHeaders1 = 50,
        getWalletStateChunk = 51,
        walletStateChunk = 52,
        syncWalletState = 53,
        walletState = 54,
        getBlock3 = 55,
        getTransactions2 = 56,
        //[Obsolete("Use transactionsChunk3 instead")]
        //transactionsChunk2 = 57,
        getTransaction3 = 58,
        inventory2 = 59,
        transactionsChunk3 = 60
    }

    /// <summary>
    ///  Current stateus of the remote endpoint (server or client).
    /// </summary>
    public enum RemoteEndpointState
    {
        Initial,
        Established,
        Closed
    }

    /// <summary>
    ///  Helper class to help filter and classify IPv4 addresses
    /// </summary>
    public class IPv4Subnet
    {
        private IPAddress subnet;
        private IPAddress mask;

        // Well known subnets:
        public static readonly IPv4Subnet PrivateClassA = IPv4Subnet.FromCIDR("10.0.0.0/8");
        public static readonly IPv4Subnet SharedAddress = IPv4Subnet.FromCIDR("100.64.0.0/10");
        public static readonly IPv4Subnet Loopback = IPv4Subnet.FromCIDR("127.0.0.0/8");
        public static readonly IPv4Subnet LinkLocal = IPv4Subnet.FromCIDR("169.254.0.0/16");
        public static readonly IPv4Subnet PrivateClassB = IPv4Subnet.FromCIDR("172.16.0.0/12");
        public static readonly IPv4Subnet IETF = IPv4Subnet.FromCIDR("192.0.0.0/24");
        public static readonly IPv4Subnet Dummy = IPv4Subnet.FromCIDR("192.0.0.8/32");
        public static readonly IPv4Subnet PortControlAnycast = IPv4Subnet.FromCIDR("192.0.0.9/32");
        public static readonly IPv4Subnet NatAnycastTraversal = IPv4Subnet.FromCIDR("192.0.0.10/32");
        public static readonly IPv4Subnet Nat64Discovery = IPv4Subnet.FromCIDR("192.0.0.170/32");
        public static readonly IPv4Subnet DNS64Discovery = IPv4Subnet.FromCIDR("192.0.0.171/32");
        public static readonly IPv4Subnet TestNet1Documentation = IPv4Subnet.FromCIDR("192.0.2.0/24");
        public static readonly IPv4Subnet AS112 = IPv4Subnet.FromCIDR("192.31.196.0/24");
        public static readonly IPv4Subnet AMT = IPv4Subnet.FromCIDR("192.52.193.0/24");
        public static readonly IPv4Subnet Relay6to4 = IPv4Subnet.FromCIDR("192.88.99.0/24");
        public static readonly IPv4Subnet PrivateClassC = IPv4Subnet.FromCIDR("192.168.0.0/16");
        public static readonly IPv4Subnet AS112DirectDelegation = IPv4Subnet.FromCIDR("192.175.48.0/24");
        public static readonly IPv4Subnet Benchmarking = IPv4Subnet.FromCIDR("198.18.0.0/15");
        public static readonly IPv4Subnet TestNet2Documentation = IPv4Subnet.FromCIDR("198.51.100.0/24");
        public static readonly IPv4Subnet TestNet3Documentation = IPv4Subnet.FromCIDR("203.0.113.0/24");
        public static readonly IPv4Subnet Reserved = IPv4Subnet.FromCIDR("240.0.0.0/4");
        public static readonly IPv4Subnet Broadcast = IPv4Subnet.FromCIDR("255.255.255.255/32");

        private IPv4Subnet(IPAddress s, IPAddress m)
        {
            subnet = s;
            mask = m;
        }

        /// <summary>
        ///  Converts an address in a CIDR notation to the `IPv4Subnet` object.
        /// </summary>
        /// <param name="cidr">IP addrss in the format 1.2.3.4/5</param>
        /// <exception cref="ArgumentException">The provided CIDR is invalid.</exception>
        /// <returns>IPv4 network.</returns>
        public static IPv4Subnet FromCIDR(String cidr)
        {
            int delim = cidr.IndexOf('/');
            if (delim == -1)
            {
                throw new ArgumentException(String.Format("Invalid CIDR notation: {0}", cidr));
            }
            string subnet = cidr.Substring(0, delim);
            string mask = cidr.Substring(delim + 1);
            IPAddress s;
            if (IPAddress.TryParse(subnet, out s) == false)
            {
                throw new ArgumentException(String.Format("Invalid IP address: {0}", subnet));
            }
            if (s.AddressFamily != AddressFamily.InterNetwork)
            {
                throw new ArgumentException(String.Format("IPv4 address required: {0}", subnet));
            }
            int maskBits;
            if (int.TryParse(mask, out maskBits) == false)
            {
                throw new ArgumentException(String.Format("Mask bits is not a number: {0}", mask));
            }
            if (maskBits < 0 || maskBits > 32)
            {
                throw new ArgumentException(String.Format("Invalid mask bits: {0}", mask));
            }
            uint mask_ip = 0xFFFFFFFF << (32 - maskBits);
            byte[] maskBytes = new byte[]
            {
                    (byte)((mask_ip & 0xFF000000) >> 24),
                    (byte)((mask_ip & 0x00FF0000) >> 16),
                    (byte)((mask_ip & 0x0000FF00) >> 8),
                    (byte)((mask_ip & 0x000000FF))
            };
            return new IPv4Subnet(s, new IPAddress(maskBytes));
        }

        /// <summary>
        ///  Constructs an `IPv4Subnet` from a network address and subnet mask, given as strings.
        /// </summary>
        /// <param name="subnet">Network address.</param>
        /// <param name="mask">Subnet Mask</param>
        /// <returns>IPv4 network</returns>
        public static IPv4Subnet FromSubnet(String subnet, String mask)
        {
            IPAddress s, m;
            if (IPAddress.TryParse(subnet, out s) == false)
            {
                throw new ArgumentException(String.Format("Invalid IP address: {0}", subnet));
            }
            if (IPAddress.TryParse(mask, out m) == false)
            {
                throw new ArgumentException(String.Format("Invalid subnet mask: {0}", mask));
            }
            if (s.AddressFamily != AddressFamily.InterNetwork)
            {
                throw new ArgumentException(String.Format("IPv4 address required: {0}", subnet));
            }
            if (m.AddressFamily != AddressFamily.InterNetwork)
            {
                throw new ArgumentException(String.Format("IPv4 subnet mask required: {0}", mask));
            }
            return new IPv4Subnet(s, m);
        }

        /// <summary>
        ///  Constructs an `IPv4Subnet` from a network address and mask, given as `IPAddress`.
        /// </summary>
        /// <param name="subnet">Network address.</param>
        /// <param name="mask">Subnet mask.</param>
        /// <returns>IPv4 network</returns>
        public static IPv4Subnet FromSubnet(IPAddress subnet, IPAddress mask)
        {
            if (subnet.AddressFamily != AddressFamily.InterNetwork)
            {
                throw new ArgumentException(String.Format("IPv4 address required: {0}", subnet));
            }
            if (mask.AddressFamily != AddressFamily.InterNetwork)
            {
                throw new ArgumentException(String.Format("IPv4 subnet mask required: {0}", mask));
            }
            return new IPv4Subnet(subnet, mask);
        }

        /// <summary>
        ///  Verifies that the given address is on a public network. (It is not a special address or one of the reserved private subnets.)
        /// </summary>
        /// <param name="addr">IP address to check</param>
        /// <returns>True, if the given IP is a public, routable address.</returns>
        public static bool IsPublicIP(IPAddress addr)
        {
            if (addr.AddressFamily != AddressFamily.InterNetwork)
            {
                throw new ArgumentException(String.Format("IPv4 address is required: {0}", addr.ToString()));
            }
            bool unroutable = PrivateClassA.IsIPInSubnet(addr) ||
            PrivateClassB.IsIPInSubnet(addr) ||
            PrivateClassC.IsIPInSubnet(addr) ||
            Loopback.IsIPInSubnet(addr) ||
            LinkLocal.IsIPInSubnet(addr) ||
            SharedAddress.IsIPInSubnet(addr) ||
            IETF.IsIPInSubnet(addr) ||
            Dummy.IsIPInSubnet(addr) ||
            PortControlAnycast.IsIPInSubnet(addr) ||
            NatAnycastTraversal.IsIPInSubnet(addr) ||
            Nat64Discovery.IsIPInSubnet(addr) ||
            DNS64Discovery.IsIPInSubnet(addr) ||
            TestNet1Documentation.IsIPInSubnet(addr) ||
            AS112.IsIPInSubnet(addr) ||
            AMT.IsIPInSubnet(addr) ||
            Relay6to4.IsIPInSubnet(addr) ||
            AS112DirectDelegation.IsIPInSubnet(addr) ||
            Benchmarking.IsIPInSubnet(addr) ||
            TestNet2Documentation.IsIPInSubnet(addr) ||
            TestNet3Documentation.IsIPInSubnet(addr) ||
            Reserved.IsIPInSubnet(addr) ||
            Broadcast.IsIPInSubnet(addr);
            return !unroutable;
        }

        public static bool IsPublicIP(string ipAddrStr)
        {
            return IsPublicIP(IPAddress.Parse(ipAddrStr));
        }

        /// <summary>
        ///  Checks if the given IP address is a member of this IPv4 subnet.
        /// </summary>
        /// <param name="addr">IP address to check.</param>
        /// <returns>True, if the IP address is a part of the subnet this object represents.</returns>
        public bool IsIPInSubnet(IPAddress addr)
        {
            if (addr.AddressFamily != AddressFamily.InterNetwork)
            {
                throw new ArgumentException(String.Format("IPv4 address required: {0}", addr.ToString()));
            }
            byte[] addressBytes = addr.GetAddressBytes();
            byte[] subnetBytes = subnet.GetAddressBytes();
            byte[] maskBytes = mask.GetAddressBytes();
            for (int i = 0; i < addressBytes.Length; i++)
            {
                if ((addressBytes[i] & maskBytes[i]) != (subnetBytes[i] & maskBytes[i]))
                {
                    return false;
                }
            }
            return true;
        }

        /// <summary>
        ///  Checks if the given IP address, given as a string, is a member of this IPv4 subnet.
        /// </summary>
        /// <param name="ipaddr">IP address to check.</param>
        /// <returns>True, if the IP address is a part of the subnet this object represents.</returns>
        public bool IsIPInSubnet(String ipaddr)
        {
            if (IPAddress.TryParse(ipaddr, out IPAddress a))
            {
                return IsIPInSubnet(a);
            }
            else
            {
                throw new ArgumentException(String.Format("IPv4 address required: {0}", ipaddr));
            }
        }
    }

    /// <summary>
    ///  Represents an IP address and a subnet mask.
    /// </summary>
    public struct IPAndMask
    {
        public IPAddress Address;
        public IPAddress SubnetMask;
    }



    public class NetworkUtils
    {
        /// <summary>
        ///  List of Ixian MainNet seed nodes and their addresses.
        /// </summary>
        public static List<string[]> seedNodes = new List<string[]>
                    {
                        new string[2] { "seed1.ixian.io:10234", "1AAF8ZagTw6UqiQPUoiKjmoAN45jvR8tdmSmeev4uNzq45QWB" },
                        new string[2] { "seed2.ixian.io:10234", "1NpizdRi5rmw586Aw883CoQ7THUT528CU5JGhGomgaG9hC3EF" },
                        new string[2] { "seed3.ixian.io:10234", "1Dp9bEFkymhN8PcN7QBzKCg2buz4njjp4eJeFngh769H4vUWi" },
                        new string[2] { "seed4.ixian.io:10234", "1SWy7jYky8xkuN5dnr3aVMJiNiQVh4GSLggZ9hBD3q7ALVEYY" },
                        new string[2] { "seed5.ixian.io:10234", "1R2WxZ7rmQhMTt5mCFTPhPe9Ltw8pTPY6uTsWHCvVd3GvWupC" },
                        new string[2] { "mineixi.com:10234", "4vaRtN4sT7QCBuQKaxnAivcgcgfigfGJVrGgwbx9gLsJKU8CtmkhwfcJcjFd7QD5N" }
                    };

        /// <summary>
        ///  List of Ixian TestNet seed nodes and their addresses.
        /// </summary>
        public static List<string[]> seedTestNetNodes = new List<string[]>
                    {
                        new string[2] { "seedtest1.ixian.io:11234", null },
                        new string[2] { "seedtest2.ixian.io:11235", null },
                        new string[2] { "seedtest3.ixian.io:11236", null }
                    };

        /// <summary>
        ///  Helper function which returns a list of seed addresses based on the testnet parameter.
        /// </summary>
        /// <param name="type">Type of the network for which to return list of hardcoded seed nodes.</param>
        /// <returns>List of connectable seed addresses.</returns>
        public static List<string[]> getSeedNodes(NetworkType type)
        {
            switch(type)
            {
                case NetworkType.main:
                    return seedNodes;

                case NetworkType.test:
                case NetworkType.reg:
                    return seedTestNetNodes;
            }
            return new List<string[]>();
        }

        /// <summary>
        ///  Returns the first unicast, IPv4 network address on the local machine.
        /// </summary>
        /// <returns>IPv4 address as string.</returns>
        public static string GetLocalIPAddress()
        {
            NetworkInterface[] nics = NetworkInterface.GetAllNetworkInterfaces();
            foreach (NetworkInterface nic in nics)
            {
                if (nic.OperationalStatus == OperationalStatus.Up && nic.Supports(NetworkInterfaceComponent.IPv4))
                {
                    IPInterfaceProperties properties = nic.GetIPProperties();
                    UnicastIPAddressInformationCollection unicast = properties.UnicastAddresses;
                    foreach (UnicastIPAddressInformation unicastIP in unicast)
                    {
                        if (unicastIP.Address.AddressFamily == AddressFamily.InterNetwork)
                        {
                            return unicastIP.Address.ToString();
                        }
                    }
                }
            }
            throw new Exception("No network adapters with an IPv4 address in the system!");
        }

        /// <summary>
        ///  Retrieves all IPv4, unicast addresses on the local computer.
        /// </summary>
        /// <returns>List of all IP addresses of the local computer as strings.</returns>
        public static List<string> GetAllLocalIPAddresses()
        {
            List<String> ips = new List<string>();
            NetworkInterface[] nics = NetworkInterface.GetAllNetworkInterfaces();
            foreach (NetworkInterface nic in nics)
            {
                if (nic.OperationalStatus == OperationalStatus.Up && nic.Supports(NetworkInterfaceComponent.IPv4))
                {
                    IPInterfaceProperties properties = nic.GetIPProperties();
                    UnicastIPAddressInformationCollection unicast = properties.UnicastAddresses;
                    foreach (UnicastIPAddressInformation unicastIP in unicast)
                    {
                        if (unicastIP.Address.AddressFamily == AddressFamily.InterNetwork)
                        {
                            ips.Add(unicastIP.Address.ToString());
                        }
                    }
                }
            }
            return ips;
        }

        /// <summary>
        ///  Returns the first IPv4, unicast address on the local computer which has a gateway configured and is, therefore,
        ///  probably Internet-connectable.
        /// </summary>
        /// <returns>IP address object</returns>
        public static IPAddress GetPrimaryIPAddress()
        {
            // This is impossible to find, but we return the first IP which has a gateway configured
            List<IPAndMask> ips = new List<IPAndMask>();
            NetworkInterface[] nics = NetworkInterface.GetAllNetworkInterfaces();
            foreach (NetworkInterface nic in nics)
            {
                if (nic.OperationalStatus == OperationalStatus.Up && nic.Supports(NetworkInterfaceComponent.IPv4))
                {
                    IPInterfaceProperties properties = nic.GetIPProperties();
                    if (properties.GatewayAddresses.Count == 0)
                    {
                        continue;
                    }
                    UnicastIPAddressInformationCollection unicast = properties.UnicastAddresses;
                    foreach (UnicastIPAddressInformation unicastIP in unicast)
                    {
                        if (unicastIP.Address.AddressFamily == AddressFamily.InterNetwork)
                        {
                            IPv4Subnet subnet = IPv4Subnet.FromSubnet(unicastIP.Address, unicastIP.IPv4Mask);
                            foreach (GatewayIPAddressInformation gw_addr in properties.GatewayAddresses)
                            {
                                if (gw_addr.Address.AddressFamily == AddressFamily.InterNetwork)
                                {
                                    if (subnet.IsIPInSubnet(gw_addr.Address))
                                    {
                                        return unicastIP.Address;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            return null;
        }

        /// <summary>
        ///  Retrieves all locally configured IPv4 addresses and their subnet masks for the local computer.
        /// </summary>
        /// <returns>List of IP addresses and subnet masks.</returns>
        public static List<IPAndMask> GetAllLocalIPAddressesAndMasks()
        {
            List<IPAndMask> ips = new List<IPAndMask>();
            NetworkInterface[] nics = NetworkInterface.GetAllNetworkInterfaces();
            foreach (NetworkInterface nic in nics)
            {
                if (nic.OperationalStatus == OperationalStatus.Up && nic.Supports(NetworkInterfaceComponent.IPv4))
                {
                    IPInterfaceProperties properties = nic.GetIPProperties();
                    UnicastIPAddressInformationCollection unicast = properties.UnicastAddresses;
                    foreach (UnicastIPAddressInformation unicastIP in unicast)
                    {
                        if (unicastIP.Address.AddressFamily == AddressFamily.InterNetwork)
                        {
                            ips.Add(new IPAndMask { Address = unicastIP.Address, SubnetMask = unicastIP.IPv4Mask });
                        }
                    }
                }
            }
            return ips;
        }

        /// <summary>
        ///  Attempts to connect to the given host name or IP address and transmit some data.
        ///  Note: This function has a possible delay of about 2 seconds.
        /// </summary>
        /// <param name="full_hostname">Hostname or IP address of the remote endpoint.</param>
        /// <returns>True, if the IP address is reachable.</returns>
        public static bool PingAddressReachable(String full_hostname)
        {
            // TODO TODO TODO TODO move this to another thread

            if (String.IsNullOrWhiteSpace(full_hostname))
            {
                return false;
            }

            String[] hn_port = full_hostname.Split(':');
            if (hn_port.Length != 2)
            {
                return false;
            }
            String hostname = hn_port[0];
            if (!IXICore.Utils.IxiUtils.validateIPv4(hostname))
            {
                return false;
            }
            int port;
            if (int.TryParse(hn_port[1], out port) == false)
            {
                return false;
            }
            if (port <= 0)
            {
                return false;
            }

            TcpClient temp = new TcpClient();
            bool connected = false;
            try
            {
                Logging.info("Testing client connectivity for {0}.", full_hostname);
                if (!temp.ConnectAsync(hostname, port).Wait(1000))
                {
                    return false;
                }
                temp.Client.SendTimeout = 500;
                temp.Client.ReceiveTimeout = 500;
                temp.Client.Blocking = false;
                temp.Client.Send(new byte[1], 1, 0);
                connected = temp.Client.Connected;
                CoreProtocolMessage.sendBye(temp.Client, ProtocolByeCode.bye, "Test OK", "");
                temp.Client.Shutdown(SocketShutdown.Both);
                temp.Client.Disconnect(false);
                temp.Client.Close();
                temp.Close();
                temp.Dispose();
            }
            catch (Exception) { connected = false; }
            return connected;
        }

        /// <summary>
        /// Disconnects and reconnects the node to the network.
        /// </summary>
        static public void reconnect(bool resetNetworkQueue)
        {
            // Reconnect server and clients

            if (resetNetworkQueue)
            {
                // Reset the network receive queue
                NetworkQueue.reset();
            }

            NetworkServer.stopNetworkOperations();

            if (!IxianHandler.enableNetworkServer)
            {
                Logging.info("Network server is not enabled.");
            }
            else
            {
                NetworkServer.restartNetworkOperations();
            }

            NetworkClientManager.restartClients();
        }

        /// <summary>
        /// Isolates the node from the network.
        /// </summary>
        static public void isolate()
        {
            NetworkClientManager.pause();
            NetworkServer.pause();
        }


        public static string resolveHostname(string hostname)
        {
            // Check for IP
            IPAddress address;
            if (IPAddress.TryParse(hostname, out address))
            {
                switch (address.AddressFamily)
                {
                    case System.Net.Sockets.AddressFamily.InterNetwork:
                        return hostname;
                    case System.Net.Sockets.AddressFamily.InterNetworkV6:
                        return hostname;
                    default:
                        break;
                }
            }

            // Check DNS
            try
            {
                IPHostEntry hostEntry;
                hostEntry = Dns.GetHostEntry(hostname);

                // TODO: handle multi-ip hostnames
                foreach (var ip in hostEntry.AddressList)
                {
                    // TODO: handle IPv6 as well
                    if (ip.AddressFamily == AddressFamily.InterNetwork)
                    {
                        return ip.ToString();
                    }
                }
            }
            catch (Exception)
            {
                return hostname;
            }

            return "";
        }

        static public bool validateIP(string ip)
        {
            // TODO add local exceptions - 127.0.0.1, ::1, 0.0.0.0 etc...

            IPAddress addr;
            if (IPAddress.TryParse(ip, out addr) && addr.ToString() == ip)
            {
                return true;
            }
            return false;
        }


        static public void configureNetwork(string externalIp, int port)
        {
            // Network configuration
            UPnP upnp = new UPnP();

            IxianHandler.publicPort = port;

            if (externalIp != "" && IPAddress.TryParse(externalIp, out _))
            {
                IxianHandler.publicIP = externalIp;
            }
            else
            {
                IxianHandler.publicIP = "";
                List<IPAndMask> local_ips = NetworkUtils.GetAllLocalIPAddressesAndMasks();
                foreach (IPAndMask local_ip in local_ips)
                {
                    if (IPv4Subnet.IsPublicIP(local_ip.Address))
                    {
                        Logging.info(String.Format("Public IP detected: {0}, mask {1}.", local_ip.Address.ToString(), local_ip.SubnetMask.ToString()));
                        IxianHandler.publicIP = local_ip.Address.ToString();
                    }
                }
                if (IxianHandler.publicIP == "")
                {
                    IPAddress primary_local = NetworkUtils.GetPrimaryIPAddress();
                    if (primary_local == null)
                    {
                        Logging.warn("Unable to determine primary IP address.");
                    }
                    else
                    {
                        Logging.warn(String.Format("None of the locally configured IP addresses are public. Attempting UPnP..."));
                        Task<IPAddress> public_ip = upnp.GetExternalIPAddress();
                        if (public_ip.Wait(1000))
                        {
                            if (public_ip.Result != null)
                            {
                                Logging.info(String.Format("UPNP-determined public IP: {0}. Attempting to configure a port-forwarding rule.", public_ip.Result.ToString()));
                                if (upnp.MapPublicPort(port, primary_local))
                                {
                                    IxianHandler.publicIP = public_ip.Result.ToString(); //upnp.getMappedIP();
                                    Logging.info(string.Format("Network configured. Public IP is: {0}", IxianHandler.publicIP));
                                }
                                else
                                {
                                    Logging.warn("UPnP configuration failed, please set port forwarding for port {0} manually.", port);
                                }
                            }
                            else
                            {
                                Logging.warn("UPnP configuration failed, please set port forwarding for port {0} manually.", port);
                            }
                        }

                    }
                }
            }
        }
    }
}
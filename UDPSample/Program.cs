using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace UDPSample
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Press S to start a server OR Press C to start a client");
            var keyEntered = Console.ReadKey();
            if (keyEntered.Key == ConsoleKey.S )
            {
                CreateServerInstance();
            }
            else if (keyEntered.Key == ConsoleKey.C)
            {
                SendUDPPacket();
            }
            Console.Read();
        }

        // Simple UDP echo server
        private static void CreateServerInstance()
        {
            string data = "";
            UdpClient server = new UdpClient(1234);
            IPEndPoint remoteIPEndPoint = new IPEndPoint(IPAddress.Any, 0);

            Console.WriteLine("SERVER STARTED");
            Console.WriteLine("* Waiting for Client...");
            while (true)
            {
                try
                {
                    byte[] receivedBytes = server.Receive(ref remoteIPEndPoint);
                    Console.WriteLine("Message Received From Client, Size =" + receivedBytes.Length);
                    byte[] payLoad = new byte[receivedBytes.Length - 28]; // ip = 20, udp =8
                    Array.Copy(receivedBytes, 28,payLoad,0, receivedBytes.Length - 28);
                    //Array.Copy();
                    data = Encoding.ASCII.GetString(payLoad);
                    Console.WriteLine("Message Received From Client:" + data.TrimEnd());

                    server.Send(receivedBytes, receivedBytes.Length, remoteIPEndPoint);
                    Console.WriteLine("Message Echoed Back To Client");
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    //throw;
                    
                }
                
            }
        }
       

        /// <summary>
        /// To do checksum, need to define headers 
        /// </summary>
        private static void SendUDPPacket()
        {
            Console.WriteLine("Building the packet header...");
            byte[] builtPacket, payLoad ;
            ArrayList headerList = new ArrayList();
            Socket rawSocket = null;
            SocketOptionLevel socketLevel = SocketOptionLevel.IP;
            IPAddress bindAddress = IPAddress.Any;
            IPAddress sourceAddress = IPAddress.Parse("127.0.0.1");
            IPAddress destAddress = IPAddress.Parse("127.0.0.1");
            ushort sourcePort = 5150;
            ushort destPort = 1234;

            while (true)
            {
                headerList.Clear();
                Console.WriteLine("\nPlease enter a message to send to server and hit enter");
                var message = Console.ReadLine();
                Console.WriteLine("You enter - " + message);
                if (string.IsNullOrWhiteSpace(message))
                {
                    Console.WriteLine("OK, Try again.");
                    continue;
                }
                Console.WriteLine("Initialize the payload...");
                payLoad = Encoding.ASCII.GetBytes(message);

                // Fill out the UDP header first
                UdpHeader udpPacket = BuildUDPHeader(payLoad,sourcePort,destPort);
                Ipv4Header ipv4Packet = BuildIPV4Header(sourceAddress, destAddress, payLoad.Length);
                Console.WriteLine("Setting the IPv4 header for pseudo header checksum...");
                udpPacket.ipv4PacketHeader = ipv4Packet;

                Console.WriteLine("Adding the IPv4 header to the list of header, encapsulating packet...");
                headerList.Add(ipv4Packet);

                Console.WriteLine("Adding the UDP header to the list of header, after IP header...");
                headerList.Add(udpPacket);

                Console.WriteLine("Converting the header classes into the binary...");
                builtPacket = udpPacket.BuildPacket(headerList, payLoad);

                Console.WriteLine("Message Length ={0}, Total Packet Length = {1}", payLoad.Length,builtPacket.Length);

                Console.WriteLine("Creating the raw socket using Socket()...");
                rawSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

                Console.WriteLine("Binding the socket to the specified interface using Bind()...");
                rawSocket.Bind(new IPEndPoint(bindAddress, 0));

                Console.WriteLine("Setting the HeaderIncluded option for IP header...");

                try
                {
                    // Send the packet!
                    Console.WriteLine("Sending the packet...");
                    int rc = rawSocket.SendTo(builtPacket, new IPEndPoint(destAddress, destPort));
                    Console.WriteLine("send {0} bytes to {1}", rc, destAddress);

                    byte[] echoedDataFromServer = new byte[builtPacket.Length];
                    rawSocket.Receive(echoedDataFromServer);
                    
                    Console.WriteLine("Data Received from Server {0} bytes to {1}", rc, destAddress);

                    Console.WriteLine("Sent packet's checksum = {0}", udpPacket.Checksum);

                    // offset for checksum will be 26 and checksum size is 2 bytes
                    byte[] checksumArray = new byte[2];
                    Array.Copy(echoedDataFromServer, 26, checksumArray, 0, 2);

                    var checksumOfReceivedPacket =
                        (ushort)IPAddress.NetworkToHostOrder((short)BitConverter.ToUInt16(checksumArray, 0));

                    Console.WriteLine("Received packet's checksum = {0}", checksumOfReceivedPacket);

                    Console.WriteLine(udpPacket.Checksum != checksumOfReceivedPacket
                        ? "Checksum of sent packet and received packet don't match."
                        : "Checksum of sent packet and received packet match.");

                }
                catch (SocketException err)
                {
                    Console.WriteLine("Socket error occurred: {0}", err.Message);
                }
                finally
                {
                    // Close the socket
                    Console.WriteLine("Closing the socket...");
                    rawSocket.Close();
                }
            }
        }

        private static UdpHeader BuildUDPHeader(byte[] payLoad,ushort sourcePort,ushort destPort)
        {
            Console.WriteLine("Filling out the UDP header...");
            UdpHeader udpPacket = new UdpHeader();
            udpPacket.SourcePort = sourcePort;
            udpPacket.DestinationPort = destPort;
            udpPacket.Length = (ushort)(UdpHeader.UdpHeaderLength + payLoad.Length);
            udpPacket.Checksum = 0;
            return udpPacket;
        }

        private static Ipv4Header BuildIPV4Header(IPAddress sourceAddress, IPAddress destAddress, int
            messageSize)
        {
            Ipv4Header ipv4Packet = new Ipv4Header();
            // Build the IPv4 header

            Console.WriteLine("Building the IPv4 header...");
            ipv4Packet.Version = 4;
            ipv4Packet.Protocol = (byte)ProtocolType.Udp;
            ipv4Packet.Ttl = 2;
            ipv4Packet.Offset = 0;
            ipv4Packet.Length = (byte)Ipv4Header.Ipv4HeaderLength;
            ipv4Packet.TotalLength = (ushort)System.Convert.ToUInt16(Ipv4Header.Ipv4HeaderLength + UdpHeader.UdpHeaderLength + messageSize);
            ipv4Packet.SourceAddress = sourceAddress;
            ipv4Packet.DestinationAddress = destAddress;
            
            return ipv4Packet;
        }
     }

    public abstract class ProtocolHeader
    {
        abstract public byte[] GetProtocolPacketBytes(byte[] payLoad);
        public byte[] BuildPacket(ArrayList headerList, byte[] payLoad)
        {
            ProtocolHeader protocolHeader;
            byte[] newPayload = null;
            // Traverse the array in reverse order since the outer headers may need
            //    the inner headers and payload to compute checksums on.
            for (int i = headerList.Count - 1; i >= 0; i--)
            {
                protocolHeader = (ProtocolHeader) headerList[i];
                newPayload = protocolHeader.GetProtocolPacketBytes(payLoad);
                // The payLoad for the next iteration of the loop is now any
                //    encapsulated headers plus the original payload data.
                payLoad = newPayload;
            }
            return payLoad;
        }
        public static ushort ComputeChecksum(byte[] payLoad)
        {
            uint xsum = 0;
            ushort shortval = 0, hiword = 0, loword = 0;
            // Sum up the 16-bits
            for (int i = 0; i < payLoad.Length / 2; i++)
            {
                hiword = (ushort) (((ushort) payLoad[i * 2]) << 8);
                loword = (ushort) payLoad[(i * 2) + 1];
                shortval = (ushort) (hiword | loword);
                xsum = xsum + (uint) shortval;
            }
            // Pad if necessary
            if ((payLoad.Length % 2) != 0)
            {
                xsum += (uint) payLoad[payLoad.Length - 1];
            }

            xsum = ((xsum >> 16) + (xsum & 0xFFFF));
            xsum = (xsum + (xsum >> 16));
            shortval = (ushort) (~xsum);
            return shortval;
        }

        /// <summary>
        /// Utility function for printing a byte array into a series of 4 byte hex digits with
        /// four such hex digits displayed per line.
        /// </summary>
        /// <param name="printBytes">Byte array to display</param>
        static public void PrintByteArray(byte[] printBytes)
        {
            int index = 0;
            while (index < printBytes.Length)
            {
                for (int i = 0; i < 4; i++)
                {
                    if (index >= printBytes.Length)
                        break;

                    for (int j = 0; j < 4; j++)
                    {
                        if (index >= printBytes.Length)
                            break;
                        Console.Write("{0}", printBytes[index++].ToString("x2"));
                    }

                    Console.Write(" ");
                }

                Console.WriteLine("");
            }
        }
    }

    public class Ipv4Header : ProtocolHeader
    {
        private byte ipVersion; // actually only 4 bits
        private byte ipLength; // actually only 4 bits
        private byte ipTypeOfService;
        private ushort ipTotalLength;
        private ushort ipId;
        private ushort ipOffset;
        private byte ipTtl;
        private byte ipProtocol;
        private ushort ipChecksum;
        private IPAddress ipSourceAddress;
        private IPAddress ipDestinationAddress;
        static public int Ipv4HeaderLength = 20;

        public Ipv4Header() : base()
        {
            ipVersion = 4;
            ipLength = (byte) Ipv4HeaderLength; // Set the property so it will convert properly
            ipTypeOfService = 0;
            ipId = 0;
            ipOffset = 0;
            ipTtl = 1;
            ipProtocol = 0;
            ipChecksum = 0;
            ipSourceAddress = IPAddress.Any;
            ipDestinationAddress = IPAddress.Any;
        }
        public byte Version
        {
            get { return ipVersion; }
            set { ipVersion = value; }
        }
        public byte Length
        {
            get { return (byte) (ipLength * 4); }
            set { ipLength = (byte) (value / 4); }
        }
        public byte TypeOfService
        {
            get { return ipTypeOfService; }
            set { ipTypeOfService = value; }
        }
        public ushort TotalLength
        {
            get { return (ushort) IPAddress.NetworkToHostOrder((short) ipTotalLength); }
            set { ipTotalLength = (ushort) IPAddress.HostToNetworkOrder((short) value); }
        }

        public ushort Id
        {
            get { return (ushort) IPAddress.NetworkToHostOrder((short) ipId); }
            set { ipId = (ushort) IPAddress.HostToNetworkOrder((short) value); }
        }
        public ushort Offset
        {
            get { return (ushort) IPAddress.NetworkToHostOrder((short) ipOffset); }
            set { ipOffset = (ushort) IPAddress.HostToNetworkOrder((short) value); }
        }
        public byte Ttl
        {
            get { return ipTtl; }
            set { ipTtl = value; }
        }
        public byte Protocol
        {
            get { return ipProtocol; }
            set { ipProtocol = value; }
        }
        public ushort Checksum
        {
            get
            {
                return (ushort)IPAddress.NetworkToHostOrder((short)ipChecksum);
            }
            set
            {
                ipChecksum = (ushort)IPAddress.HostToNetworkOrder((short)value);
            }
        }

        public IPAddress SourceAddress
        {
            get
            {
                return ipSourceAddress;
            }
            set
            {
                ipSourceAddress = value;
            }
        }

        public IPAddress DestinationAddress
        {
            get
            {
                return ipDestinationAddress;
            }
            set
            {
                ipDestinationAddress = value;
            }
        }

        static public Ipv4Header Create(byte[] ipv4Packet, ref int bytesCopied)
        {
            Ipv4Header ipv4Header = new Ipv4Header();
            // Make sure byte array is large enough to contain an IPv4 header
            if (ipv4Packet.Length < Ipv4Header.Ipv4HeaderLength)
                return null;

            // Decode the data in the array back into the class properties
            ipv4Header.ipVersion = (byte)((ipv4Packet[0] >> 4) & 0xF);
            ipv4Header.ipLength = (byte)(ipv4Packet[0] & 0xF);
            ipv4Header.ipTypeOfService = ipv4Packet[1];
            ipv4Header.ipTotalLength = BitConverter.ToUInt16(ipv4Packet, 2);
            ipv4Header.ipId = BitConverter.ToUInt16(ipv4Packet, 4);
            ipv4Header.ipOffset = BitConverter.ToUInt16(ipv4Packet, 6);
            ipv4Header.ipTtl = ipv4Packet[8];
            ipv4Header.ipProtocol = ipv4Packet[9];
            ipv4Header.ipChecksum = BitConverter.ToUInt16(ipv4Packet, 10);
            ipv4Header.ipSourceAddress = new IPAddress(BitConverter.ToUInt32(ipv4Packet, 12));
            ipv4Header.ipDestinationAddress = new IPAddress(BitConverter.ToUInt32(ipv4Packet, 16));
            bytesCopied = ipv4Header.Length;
            return ipv4Header;
        }

        public override byte[] GetProtocolPacketBytes(byte[] payLoad)
        {
            byte[] ipv4Packet, byteValue;
            int index = 0;
            // Allocate space for the IPv4 header plus payload
            ipv4Packet = new byte[Ipv4HeaderLength + payLoad.Length];

            ipv4Packet[index++] = (byte)((ipVersion << 4) | ipLength);
            ipv4Packet[index++] = ipTypeOfService;
            byteValue = BitConverter.GetBytes(ipTotalLength);
            Array.Copy(byteValue, 0, ipv4Packet, index, byteValue.Length);
            index += byteValue.Length;
            byteValue = BitConverter.GetBytes(ipId);
            Array.Copy(byteValue, 0, ipv4Packet, index, byteValue.Length);
            index += byteValue.Length;
            byteValue = BitConverter.GetBytes(ipOffset);
            Array.Copy(byteValue, 0, ipv4Packet, index, byteValue.Length);
            index += byteValue.Length;
            ipv4Packet[index++] = ipTtl;
            ipv4Packet[index++] = ipProtocol;
            ipv4Packet[index++] = 0; // Zero the checksum for now since we will
            ipv4Packet[index++] = 0; // calculate it later
            // Copy the source address
            byteValue = ipSourceAddress.GetAddressBytes();
            Array.Copy(byteValue, 0, ipv4Packet, index, byteValue.Length);
            index += byteValue.Length;
            // Copy the destination address
            byteValue = ipDestinationAddress.GetAddressBytes();
            Array.Copy(byteValue, 0, ipv4Packet, index, byteValue.Length);
            index += byteValue.Length;
            // Copy the payload
            Array.Copy(payLoad, 0, ipv4Packet, index, payLoad.Length);
            index += payLoad.Length;
            // Compute the checksum over the entire packet (IPv4 header + payload)
            Checksum = ComputeChecksum(ipv4Packet);
            // Set the checksum into the built packet
            byteValue = BitConverter.GetBytes(ipChecksum);
            Array.Copy(byteValue, 0, ipv4Packet, 10, byteValue.Length);
            return ipv4Packet;
        }
    }

    public class UdpHeader : ProtocolHeader
    {
        private ushort srcPort;
        private ushort destPort;
        private ushort udpLength;
        private ushort udpChecksum;
        public Ipv4Header ipv4PacketHeader;

        static public int UdpHeaderLength = 8;
        public UdpHeader() : base()
        {
            srcPort = 0;
            destPort = 0;
            udpLength = 0;
            udpChecksum = 0;
            ipv4PacketHeader = null;
        }
        public ushort SourcePort
        {
            get { return (ushort)IPAddress.NetworkToHostOrder((short)srcPort); }
            set { srcPort = (ushort)IPAddress.HostToNetworkOrder((short)value); }
        }
        public ushort DestinationPort
        {
            get { return (ushort)IPAddress.NetworkToHostOrder((short)destPort); }
            set { destPort = (ushort)IPAddress.HostToNetworkOrder((short)value); }
        }
        public ushort Length
        {
            get { return (ushort)IPAddress.NetworkToHostOrder((short)udpLength); }
            set { udpLength = (ushort)IPAddress.HostToNetworkOrder((short)value); }
        }
        public ushort Checksum
        {
            get { return (ushort)IPAddress.NetworkToHostOrder((short)udpChecksum); }
            set { udpChecksum = (ushort)IPAddress.HostToNetworkOrder((short)value); }
        }

        public static UdpHeader Create(byte[] udpData, ref int bytesCopied)
        {
            UdpHeader udpPacketHeader = new UdpHeader();
            udpPacketHeader.srcPort = BitConverter.ToUInt16(udpData, 0);
            udpPacketHeader.destPort = BitConverter.ToUInt16(udpData, 2);
            udpPacketHeader.udpLength = BitConverter.ToUInt16(udpData, 4);
            udpPacketHeader.udpChecksum = BitConverter.ToUInt16(udpData, 6);
            return udpPacketHeader;
        }
        
        public override byte[] GetProtocolPacketBytes(byte[] payLoad)
        {
            byte[] udpPacket = new byte[UdpHeaderLength + payLoad.Length], pseudoHeader = null, byteValue = null;
            int offset = 0;

            // Build the UDP packet first
            byteValue = BitConverter.GetBytes(srcPort);
            Array.Copy(byteValue, 0, udpPacket, offset, byteValue.Length);
            offset += byteValue.Length;
            byteValue = BitConverter.GetBytes(destPort);
            Array.Copy(byteValue, 0, udpPacket, offset, byteValue.Length);
            offset += byteValue.Length;
            byteValue = BitConverter.GetBytes(udpLength);
            Array.Copy(byteValue, 0, udpPacket, offset, byteValue.Length);
            offset += byteValue.Length;

            udpPacket[offset++] = 0; // Checksum is initially zero
            udpPacket[offset++] = 0;

            // Copy payload to end of packet
            Array.Copy(payLoad, 0, udpPacket, offset, payLoad.Length);

            if (ipv4PacketHeader != null)
            {
                pseudoHeader = new byte[UdpHeaderLength + 12 + payLoad.Length];
                // Build the IPv4 pseudo header
                offset = 0;
                
                byteValue = ipv4PacketHeader.SourceAddress.GetAddressBytes();
                Array.Copy(byteValue, 0, pseudoHeader, offset, byteValue.Length);
                offset += byteValue.Length;

                // Destination address
                byteValue = ipv4PacketHeader.DestinationAddress.GetAddressBytes();
                Array.Copy(byteValue, 0, pseudoHeader, offset, byteValue.Length);
                offset += byteValue.Length;

                // 1 byte zero pad plus next header protocol value
                pseudoHeader[offset++] = 0;
                pseudoHeader[offset++] = ipv4PacketHeader.Protocol;

                // Packet length
                byteValue = BitConverter.GetBytes(udpLength);
                Array.Copy(byteValue, 0, pseudoHeader, offset, byteValue.Length);
                offset += byteValue.Length;

                // Copy the UDP packet to the end of this
                Array.Copy(udpPacket, 0, pseudoHeader, offset, udpPacket.Length);
            }

            if (pseudoHeader != null)
            {
                Checksum = ComputeChecksum(pseudoHeader);
            }

            // Put checksum back into packet
            byteValue = BitConverter.GetBytes(udpChecksum);
            ushort test = BitConverter.ToUInt16(byteValue, 0);
            //ushort result = ((ushort)byteValue[0]) << 8 + byteValue[1];

            Array.Copy(byteValue, 0, udpPacket, 6, byteValue.Length);
            return udpPacket;
        }

    }
}

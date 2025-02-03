using qsslWPF.Model;
using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using static qsslSdk.Constants;
namespace qsslSdk
{
    class UdpComm
    {
        private Socket _socket;
        private IPEndPoint _localEndPoint;
        private EndPoint _remoteEndPoint;

        public UdpComm()
        {
            _socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            _localEndPoint = new IPEndPoint(IPAddress.Parse(LOCAL_ADDRESS), LOCAL_PORT);
            _socket.Bind(_localEndPoint);

            // Set a remote endpoint placeholder for recvfrom
            _remoteEndPoint = new IPEndPoint(IPAddress.Any, 0);

            SendMessage(REMOTE_ADDRESS, REMOTE_PORT, "Hello");
        }

        private void SendMessage(string remoteAddress, int remotePort, string message)
        {
            _remoteEndPoint = new IPEndPoint(IPAddress.Parse(remoteAddress), remotePort);
            byte[] data = Encoding.UTF8.GetBytes(message);
            _socket.SendTo(data, _remoteEndPoint);
            System.Diagnostics.Debug.WriteLine($"Sent: {message} to {remoteAddress}:{remotePort}\n");
        }

        private string ReceiveMessage()
        {
            byte[] buffer = new byte[1024];
            int receivedBytes = _socket.ReceiveFrom(buffer, ref _remoteEndPoint);
            string message = Encoding.UTF8.GetString(buffer, 0, receivedBytes);
            System.Diagnostics.Debug.WriteLine($"Received: {message} from {_remoteEndPoint}\n");
            return message;
        }

        public void Stop()
        {
            _socket.Close();
        }

        public string SendAndRecv(string message) 
        {
            SendMessage(REMOTE_ADDRESS, REMOTE_PORT, message);
            return ReceiveMessage();
        }

        public byte[] serializeUserModel(UserModel user)
        {
            byte[] usernameBytes = Encoding.UTF8.GetBytes(user.Username);
            byte[] passwordBytes = Encoding.UTF8.GetBytes(user.Password);
            byte[] message;
            var stream = new System.IO.MemoryStream();

            // Create a message buffer
            try
            {
                // Write username length (2 bytes)
                stream.Write(BitConverter.GetBytes((short)usernameBytes.Length), 0, 2);

                // Write username bytes
                stream.Write(usernameBytes, 0, usernameBytes.Length);

                // Write password length (2 bytes)
                stream.Write(BitConverter.GetBytes((short)passwordBytes.Length), 0, 2);

                // Write password bytes
                stream.Write(passwordBytes, 0, passwordBytes.Length);

                message = stream.ToArray();
            }
            finally {
                stream.Dispose();
            }

            return message;
        }
        public bool recvAndCheckValidation()
        {
           var message =  ReceiveMessage();
            if (message.Equals("Good"))
                return true;
            else
                return false;
        }
    }

}

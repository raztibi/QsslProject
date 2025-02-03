using qsslWPF.Model;
using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace qsslSdk
{
    public class SDK
    {
        private readonly UdpComm udpComm;

        // Event to notify WPF about login results
        public event Action<bool> LoginResultEvent;

        public SDK()
        {
            udpComm = new UdpComm();
        }

        // Send file path to the backend
        public void SendFilePath(string filePath)
        {
            // Simulate processing file path
            System.Diagnostics.Debug.WriteLine($"File path received: {filePath}");
            udpComm.SendAndRecv("Path");
            udpComm.SendAndRecv(filePath);
            System.Diagnostics.Debug.WriteLine($"File path sent to client.");
        }

        // Send user model (username and password) to the backend
        public void SendUserModel(UserModel userModel)
        {
            Task.Run(() =>
            {
                // Simulate backend login logic
                bool loginSuccess;
                udpComm.SendAndRecv("User");
                var message = udpComm.serializeUserModel(userModel);
                udpComm.SendAndRecv(Encoding.UTF8.GetString(message));
                loginSuccess = udpComm.recvAndCheckValidation();
                Thread.Sleep(5000);
                // Trigger the login result event
                LoginResultEvent?.Invoke(loginSuccess);
            });
        }
    }

}

using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace proxy
{
    internal class Program
    {

        TcpClient client;
        TcpClient server;
        TcpListener listener;

        NetworkStream networkStream;


        AsymmetricCipherKeyPair clientKeyPair;
        ECPublicKeyParameters clientPublicKey;
        ECPrivateKeyParameters clientPrivateKey;

        AsymmetricCipherKeyPair serverKeyPair;
        ECPublicKeyParameters serverPublicKey;
        ECPrivateKeyParameters serverPrivateKey;

        AsymmetricCipherKeyPair fakeKeyPair;
        ECPublicKeyParameters fakePublicKey;
        ECPrivateKeyParameters fakePrivateKey;

        ECDomainParameters curve;

        byte[] buffer;
        byte[] finalClientShareKey;
        byte[] finalServerShareKey;

        static void Main(string[] args)
        {
            Program program = new Program();
            program.Connect();
            Console.ReadKey();

        }

        void changeCurvebyName(string name)
        {
            X9ECParameters parameter = SecNamedCurves.GetByName(name);
            curve = new ECDomainParameters(parameter);
        }

        void generatingFakeKeypair()
        {
            SecureRandom random = new SecureRandom();

            ECKeyGenerationParameters param_for_key = new ECKeyGenerationParameters(curve, random);
            ECKeyPairGenerator generator = new ECKeyPairGenerator();
            generator.Init(param_for_key);
            fakeKeyPair = generator.GenerateKeyPair();
            fakePublicKey = (ECPublicKeyParameters)fakeKeyPair.Public;
            fakePrivateKey = (ECPrivateKeyParameters)fakeKeyPair.Private;
            Console.WriteLine("Fake key generation completed!!!");
            Console.WriteLine("Fake Public Key");
            Console.WriteLine("X : " + fakePublicKey.Q.XCoord.ToString());
            Console.WriteLine("Y : " + fakePublicKey.Q.YCoord.ToString());
        }

        void getOtherPublicKey(int who) //who = 0: client, who = 1: server
        {
            int bytesRead;
            if (who == 1)
            {
                networkStream = server.GetStream();
                bytesRead = server.ReceiveBufferSize;
            }
            else
            {
                networkStream = client.GetStream();
                bytesRead = client.ReceiveBufferSize;
            }
            buffer = new byte[bytesRead];

            int len = networkStream.Read(buffer, 0, bytesRead);
            byte[] pub = new byte[len];
            Buffer.BlockCopy(buffer, 0, pub, 0, len);
            ECPoint point = fakePublicKey.Parameters.Curve.DecodePoint(pub);
            ECPublicKeyParameters otherPublicKey = new ECPublicKeyParameters(point, curve);

            IBasicAgreement ok = AgreementUtilities.GetBasicAgreement("ECDH");
            ok.Init(fakePrivateKey);
            byte[] sharekey = ok.CalculateAgreement(otherPublicKey).ToByteArray();
            if (who == 1)
                finalServerShareKey = sharekey;
            else
                finalClientShareKey = sharekey;
            Console.WriteLine("Calculating share key completed!!!");
            if (who == 0)
                Console.Write("Client share key: ");
            else
                Console.Write("Server share key: ");

            Console.Write(BitConverter.ToString(sharekey).Replace("-", String.Empty));
            Console.WriteLine("");
        }

        void sendPublicKey(int who) //who = 0: client, who = 1: server
        {
            buffer = fakePublicKey.Q.GetEncoded();
            if (who == 0)
                networkStream = client.GetStream();
            else
                networkStream = server.GetStream();
            networkStream.Write(buffer, 0, buffer.Length);
            networkStream.Flush();
        }


        void ListenToA()
        {
            Console.WriteLine("Waiting for A to connect...");
            listener = new TcpListener(IPAddress.Any , 10000);
            listener.Start();
            client = listener.AcceptTcpClient();
            Console.WriteLine("A connect successfully!");
        }

        void ConnectToB()
        {
            Console.WriteLine("Attemp connecting to B...");
            //this feature will be add when ngrok
            /*
            string servername = "";
            var address = Dns.GetHostAddresses(servername);
            Debug.Assert(address.Length != 0);
            var endPoint = new IPEndPoint(address[0], 8080);

            server = new TcpClient(endPoint);
            */

            Console.WriteLine("Connectint to B...");
            server = new TcpClient("localhost", 8080);
            Console.WriteLine("Connecting to B successfully!");
        }
        
        void Connect()
        {

            Console.WriteLine("########################################");
            Console.WriteLine("#                                      #");
            Console.WriteLine("#    PROXY ( Controled by attacker)    #");
            Console.WriteLine("#                                      #");
            Console.WriteLine("########################################");

            ConnectToB();
            ListenToA();
            changeCurvebyName("secp256k1");
            generatingFakeKeypair();
            Console.WriteLine("Begin transferring key!!!");

            //-------------------------------------------------
            getOtherPublicKey(0);
            sendPublicKey(0);
            sendPublicKey(1);
            getOtherPublicKey(1);
            //-------------------------------------------------

        }

    }
}

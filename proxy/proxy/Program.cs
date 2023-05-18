using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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

        NetworkStream clientStream;
        NetworkStream serverStream;

        AsymmetricCipherKeyPair fakeKeyPair;
        ECPublicKeyParameters fakePublicKey;
        ECPrivateKeyParameters fakePrivateKey;

        static void Main(string[] args)
        {
            Program program = new Program();
            program.Connect();

        }

        void Connect()
        {
            

            client = new TcpClient("127.0.0.1", 8001);
            
            server = new TcpClient("127.0.0.1", 8000);


            MITM();

        }

        void GetClientPublicKey()
        {
            byte[] fakePublicKeyInByte = fakePublicKey.Q.GetEncoded();
            clientStream.Write(fakePublicKeyInByte, 0, fakePublicKeyInByte.Length);

            byte[] realPublicKeyClientInByte = new byte[fakePublicKeyInByte.Length];
            clientStream.Read(realPublicKeyClientInByte, 0, realPublicKeyClientInByte.Length);


            //save secret
            ECPublicKeyParameters RealClientPublicKey = new ECPublicKeyParameters(
                "ECDSA",
                fakePublicKey.Parameters.Curve.DecodePoint(realPublicKeyClientInByte),
                fakePublicKey.Parameters
                 );
            IBasicAgreement agree = AgreementUtilities.GetBasicAgreement("ECDH");
            agree.Init(fakePrivateKey);
            byte[] ClientSecret = agree.CalculateAgreement(RealClientPublicKey).ToByteArray();
            Console.WriteLine("Client Secret: ", Convert.ToBase64String(ClientSecret));
            File.WriteAllText("client_secret.txt", Convert.ToBase64String(ClientSecret));

        }

        void GetServerPublicKey()
        {
            byte[] fakePublicKeyInByte = fakePublicKey.Q.GetEncoded();
            serverStream.Write(fakePublicKeyInByte, 0, fakePublicKeyInByte.Length);

            byte[] realPublicKeyServerInByte = new byte[fakePublicKeyInByte.Length];
            clientStream.Read(realPublicKeyServerInByte, 0, realPublicKeyServerInByte.Length);


            //save secret
            ECPublicKeyParameters RealSeverPublicKey = new ECPublicKeyParameters(
                "ECDSA",
                fakePublicKey.Parameters.Curve.DecodePoint(realPublicKeyServerInByte),
                fakePublicKey.Parameters
            );
            IBasicAgreement agree = AgreementUtilities.GetBasicAgreement("ECDH");
            agree.Init(fakePrivateKey);

            byte[] ServerSecret = agree.CalculateAgreement(RealSeverPublicKey).ToByteArray();
            Console.WriteLine("Server secret: ", Convert.ToBase64String(ServerSecret));
            File.WriteAllText("sever_secret.txt", Convert.ToBase64String(ServerSecret));
        }

        void MITM()
        {
            //Receive cureve name from server and send to client
            string curvename;// "secp256k1"
            byte[] curNameBytes = new byte[9];
            serverStream = server.GetStream();
            clientStream = client.GetStream();
            serverStream.Read(curNameBytes, 0, curNameBytes.Length);
            curvename = Encoding.ASCII.GetString(curNameBytes);
            Console.WriteLine("Proxy: start ECDHE in " + curvename);
            serverStream.Flush();
            clientStream.Write(curNameBytes, 0, curNameBytes.Length);


            //Calculate fake public key and send to client and server
            X9ECParameters curveParam = SecNamedCurves.GetByName(curvename);
            ECDomainParameters curve = new ECDomainParameters(curveParam);
            ECKeyGenerationParameters keyGenParam = new ECKeyGenerationParameters(curve, new SecureRandom());
            ECKeyPairGenerator gen = new ECKeyPairGenerator();
            gen.Init(keyGenParam);

            fakeKeyPair = gen.GenerateKeyPair();
            fakePublicKey = (ECPublicKeyParameters)fakeKeyPair.Public;
            fakePrivateKey = (ECPrivateKeyParameters)fakeKeyPair.Private;

        }
    }
}

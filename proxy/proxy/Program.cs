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
        static void Main(string[] args)
        {
            Program program = new Program();

        }

        void Connect()
        {
            

            client = new TcpClient("127.0.0.1", 8001);
            server = new TcpClient("127.0.0.1", 8000);


            MITM();

        }

        void MITM()
        {
            //Receive cureve name from server and send to client
            string curvename;// "secp256k1"
            byte[] curNameBytes = new byte[9];
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
            AsymmetricCipherKeyPair fakeClientKeyPair = gen.GenerateKeyPair();

/*            ECPublicKeyParameters fakePublicKeyClient = (ECPublicKeyParameters)fakeClientKeyPair.Public;
            ECPrivateKeyParameters fakePrivateKeyClient = (ECPrivateKeyParameters)fakeClientKeyPair.Private;*/

            AsymmetricCipherKeyPair fakeKeyPair = gen.GenerateKeyPair();
            ECPublicKeyParameters fakePublicKey = (ECPublicKeyParameters)fakeKeyPair.Public;
            ECPrivateKeyParameters fakePrivateKey = (ECPrivateKeyParameters)fakeKeyPair.Private;

            byte[] fakePublicKeyInByte = fakePublicKey.Q.GetEncoded();
            serverStream.Write(fakePublicKeyInByte, 0, fakePublicKeyInByte.Length);
            clientStream.Write(fakePublicKeyInByte, 0, fakePublicKeyInByte.Length);

            //Receive real public key from client and server
            byte[] realPublicKeyClientInByte = new byte[fakePublicKeyInByte.Length];
            serverStream.Read(realPublicKeyClientInByte, 0, realPublicKeyClientInByte.Length);

            byte[] realPublicKeyServerInByte = new byte[fakePublicKeyInByte.Length];
            clientStream.Read(realPublicKeyServerInByte, 0, realPublicKeyServerInByte.Length);



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


            ECPublicKeyParameters RealClientPublicKey = new ECPublicKeyParameters(
                "ECDSA",
                fakePublicKey.Parameters.Curve.DecodePoint(realPublicKeyClientInByte),
                fakePublicKey.Parameters
                );
            agree = AgreementUtilities.GetBasicAgreement("ECDH");
            agree.Init(fakePrivateKey);
            byte[] ClientSecret = agree.CalculateAgreement(RealClientPublicKey).ToByteArray();
            Console.WriteLine("Client Secret: ", Convert.ToBase64String(ClientSecret));
            File.WriteAllText("client_secret.txt", Convert.ToBase64String(ClientSecret));




/*
            ECPublicKeyParameters RealClientPublicKey = new ECPublicKeyParameters(
                "ECDSA",
                fakePublicKeyClient.Parameters.Curve.DecodePoint(realPublicKeyClientInByte),
                fakePublicKeyClient.Parameters
                );

            agree = AgreementUtilities.GetBasicAgreement("ECDH");
            agree.Init(fakePrivateKey);
            byte[] RealClientPublicKeyInByte = agree.CalculateAgreement(RealSeverPublicKey).ToByteArray();
            Console.WriteLine("Proxy send to server message: ", Convert.ToBase64String(RealSeverPublicKeyInByte));
            File.WriteAllText("public-key_sever.txt", Convert.ToBase64String(RealSeverPublicKeyInByte));





            byte[] fake2Server = fakePublicKeyClient.Q.GetEncoded();
            serverStream.Write(fake2Server, 0, fake2Server.Length);

            byte[] getFromServer = new byte[fakePublicKeyClient.Q.GetEncoded().Length];
            serverStream.Read(getFromServer, 0, getFromServer.Length);

            Console.WriteLine("Received Public Key from server");


            ECPublicKeyParameters severPublicKey = new ECPublicKeyParameters (
                "ECDSA", 
                fakePublicKeyClient.Parameters.Curve.DecodePoint(getFromServer), 
                fakePublicKeyClient.Parameters
                );

            IBasicAgreement agree = AgreementUtilities.GetBasicAgreement("ECDH");
            agree.Init(fakePrivateKeyClient);

            byte[] sharedSecret = agree.CalculateAgreement(severPublicKey).ToByteArray();

            Console.WriteLine("Proxy send to server message: ", Convert.ToBase64String(sharedSecret));
            File.WriteAllText("public-key_sever.txt", Convert.ToBase64String(sharedSecret));


            //////////////////////////////
            /// client
            //////////////////////////////
            ///

            clientStream.Write(Encoding.ASCII.GetBytes(curvename), 0, curvename.Length);

            curve = new ECDomainParameters(curveParam);

            keyGenParam = new ECKeyGenerationParameters(curve, new SecureRandom());
            gen = new ECKeyPairGenerator();

            gen.Init(keyGenParam);
            AsymmetricCipherKeyPair fakeServerKeyPair = gen.GenerateKeyPair();

            ECPublicKeyParameters fakePublicKeyServer = (ECPublicKeyParameters)fakeServerKeyPair.Public;
            ECPrivateKeyParameters fakePrivateKeyServer = (ECPrivateKeyParameters)fakeServerKeyPair.Private;    

            byte[] fakeKey2Client = fakePublicKeyServer.Q.GetEncoded();
            clientStream.Write(fakeKey2Client, 0, fakeKey2Client.Length);

            byte[] RealClientdata = new byte[fakeKey2Client.Length];
            clientStream.Read(RealClientdata, 0, RealClientdata.Length);

            Console.WriteLine("Received client public key");

            ECPublicKeyParameters RealClientPublicKey = new ECPublicKeyParameters(
                "ECDSA",
                fakePublicKeyServer.Parameters.Curve.DecodePoint(RealClientdata),
                fakePublicKeyServer.Parameters
                );

            agree = AgreementUtilities.GetBasicAgreement("ECDH");
            agree.Init(fakePrivateKeyServer);


            Array.Clear(sharedSecret, 0, sharedSecret.Length);


            sharedSecret = agree.CalculateAgreement(severPublicKey).ToByteArray();
            Console.WriteLine("Proxy send to server message: ", Convert.ToBase64String(sharedSecret));
            File.WriteAllText("public-key_sever.txt", Convert.ToBase64String(sharedSecret));
*/



        }


    }
}

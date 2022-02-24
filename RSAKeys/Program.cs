using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace Chris.Testing.RSAKeys
{
    class Program
    {

        RSAParameters PrivateKey { get; set; }

        RSAParameters PublicKey { get; set; }

        static void Main(string[] args)
        {
            new Program();
            
        }

        Program()
        {

            CreateKeys(); 
            string signed = SignData("Check This Data", this.PrivateKey);
            bool verify = VerifySignature("Check This Data 2", signed, this.PublicKey);
        }

        public string SignData(string data, RSAParameters privateKey)
        {
            var encoder = new UTF8Encoding();
            byte[] originalData = encoder.GetBytes(data);

            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(privateKey);
                byte[] signedBytes = rsa.SignData(originalData, CryptoConfig.MapNameToOID("SHA512"));
                return Convert.ToBase64String(signedBytes);
            }
        }

        public bool VerifySignature(string data, string signedData, RSAParameters publicKey)
        {
            var encoder = new UTF8Encoding();
            byte[] bytesToVerify = encoder.GetBytes(data);
            byte[] signedBytes = Convert.FromBase64String(signedData);

            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(publicKey);
                SHA512Managed Hash = new SHA512Managed();
                byte[] hashedData = Hash.ComputeHash(signedBytes);
                return rsa.VerifyData(bytesToVerify, CryptoConfig.MapNameToOID("SHA512"), signedBytes);
            }
        }


        void CreateKeys()
        {

            

            RSA rsa = new RSACryptoServiceProvider(2048); // Generate a new 2048 bit RSA key

            //string publicPrivateKeyXML = rsa.ToXmlString(true);
            //string publicOnlyKeyXML = rsa.ToXmlString(false);

            this.PrivateKey = rsa.ExportParameters(true);
            this.PublicKey = rsa.ExportParameters(false);
            


        }

    }
}


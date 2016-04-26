// **************************************************************
// *
// * Written By: Nishant Sukhwal
// * Copyright © 2016 kiwitech. All rights reserved.
// **************************************************************

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TSGSecurity
{
    public static class AESSecurity
    {
        static PaddedBufferedBlockCipher encryptCipher;
        static PaddedBufferedBlockCipher decryptCipher;
        static byte[] buf = new byte[16];
        static byte[] obuf = new byte[512];
        public static byte[] secureKey = new byte[16];// Encoding.UTF8.GetBytes("xcrtNMQdd0FloLyw");
        public static byte[] iVector = new byte[16]; //Encoding.UTF8.GetBytes("gqLOHUioQ0QjhuvI");
        
        /// <summary>
        /// This method calls initially. This will generate the chiper for both encryption and decryption.
        /// </summary>
        private static void InitCiphers()
        {
            ParametersWithIV aesIVKeyParam = new ParametersWithIV(new KeyParameter(secureKey), iVector);

            encryptCipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()));
            encryptCipher.Init(true, aesIVKeyParam);
            decryptCipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()));
            decryptCipher.Init(false, aesIVKeyParam);
        }

        /// <summary>
        /// AES Encryption is done by this method.
        /// </summary>
        /// <param name="inputBytes"></param>
        /// <returns></returns>
        public static byte[] Encrypt(byte[] inputBytes)
        {
            InitCiphers();
            MemoryStream inpustStream = new MemoryStream(inputBytes);
            MemoryStream outputStream = new MemoryStream();
            byte[] outputBytes = null;
            try
            {
                int noBytesRead = 0;        //number of bytes read from input
                int noBytesProcessed = 0;   //number of bytes processed
                while ((noBytesRead = inpustStream.Read(buf, 0, buf.Length)) > 0)
                {
                    noBytesProcessed = encryptCipher.ProcessBytes(buf, 0, noBytesRead, obuf, 0);
                    outputStream.Write(obuf, 0, noBytesProcessed);
                }
                noBytesProcessed = encryptCipher.DoFinal(obuf, 0);
                outputStream.Write(obuf, 0, noBytesProcessed);
                outputBytes = outputStream.ToArray();
                outputStream.Flush();
                return outputBytes;
            }
            catch (Exception oEx)
            {
                System.Diagnostics.Debug.WriteLine("AESSecurity::encrypt" + oEx.ToString());
                return outputBytes;
            }
        }

        /// <summary>
        /// AES Decryption is done by this method.
        /// </summary>
        /// <param name="inputBytes"></param>
        /// <returns></returns>
        public static byte[] Decrypt(byte[] inputBytes)
        {
            InitCiphers();
            MemoryStream inpustStream = new MemoryStream(inputBytes);
            MemoryStream outputStream = new MemoryStream();
            byte[] outputBytes = null;
            try
            {
                int noBytesRead = 0;        //number of bytes read from input
                int noBytesProcessed = 0;   //number of bytes processed

                while ((noBytesRead = inpustStream.Read(buf, 0, buf.Length)) > 0)
                {
                    noBytesProcessed = decryptCipher.ProcessBytes(buf, 0, noBytesRead, obuf, 0);

                    outputStream.Write(obuf, 0, noBytesProcessed);
                }
                noBytesProcessed = decryptCipher.DoFinal(obuf, 0);
                outputStream.Write(obuf, 0, noBytesProcessed);
                outputBytes = outputStream.ToArray();
                outputStream.Flush();
                return outputBytes;
            }
            catch (Exception oEx)
            {
                System.Diagnostics.Debug.WriteLine("AESSecurity::decrypt" + oEx.ToString());
                return outputBytes;
            }
        }
    }
}

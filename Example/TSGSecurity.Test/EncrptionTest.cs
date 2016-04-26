// **************************************************************
// *
// * Written By: Nishant Sukhwal
// * Copyright © 2016 kiwitech. All rights reserved.
// **************************************************************

using System;
using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;
using System.Text;
using TSGSecurity;

namespace Encryption.Test
{
    [TestClass]
    public class EncrptionTest
    {
        static string strAES256Key = "bbC2H19lkVbQDfakxcrtNMQdd0FloLyw";
        static string strAES128Key = "xcrtNMQdd0FloLyw";
        static string strIVector = "gqLOHUioQ0QjhuvI";
        static string strExample = "Nishant Sukhwal";
        /// <summary>
        /// Test case for AES128Encryption
        /// </summary>
        [TestMethod]
        public void AES128Encryption()
        {
            byte[] secureKey = Encoding.UTF8.GetBytes(strAES128Key);
            byte[] bMessage = Encoding.UTF8.GetBytes(strExample);
            string strEncryptResult = string.Empty;
            string strDecryptResult = string.Empty;
            //strEncryptResult = Security.Encrypt(strExample, SecurityType.AES128, strAES128Key, strIVector);
            //strDecryptResult = Security.Decrypt(strEncryptResult, SecurityType.AES128, strAES128Key, strIVector);
            object oEncryptResult = TSGSecurityManager.Encrypt(strExample, SecurityType.AES128, strAES128Key, strIVector);
            strEncryptResult = EncryptResult(strEncryptResult, oEncryptResult);
            object oDecryptResult = TSGSecurityManager.Decrypt(strEncryptResult, SecurityType.AES128, strAES128Key, strIVector);
            strDecryptResult = DecryptResult(strDecryptResult, oDecryptResult);
            Assert.AreEqual(strDecryptResult, strExample); //"PgvK6FNMxbfzm2HOw6SK+A=="
        }

        /// <summary>
        /// Common method to show decrypt result.
        /// </summary>
        /// <param name="strDecryptResult"></param>
        /// <param name="oDecryptResult"></param>
        /// <returns></returns>
        private static string DecryptResult(string strDecryptResult, object oDecryptResult)
        {
            if (oDecryptResult.GetType() == typeof(Tuple<bool, string>))
            {
                Tuple<bool, string> res = oDecryptResult as Tuple<bool, string>;
                bool isValid = res.Item1;
                string strResult = res.Item2;
                if (isValid)
                {
                    if (!string.IsNullOrEmpty(strResult))
                    {
                        strDecryptResult = strResult;
                    }
                }
                else
                {
                    //await new MessageDialog("Unable to encrypt.").ShowAsync();
                }
            }
            return strDecryptResult;
        }

        /// <summary>
        /// Common method to show encrypt result.
        /// </summary>
        /// <param name="strEncryptResult"></param>
        /// <param name="oEncryptResult"></param>
        /// <returns></returns>
        private static string EncryptResult(string strEncryptResult, object oEncryptResult)
        {
            if (oEncryptResult.GetType() == typeof(Tuple<bool, string>))
            {
                Tuple<bool, string> res = oEncryptResult as Tuple<bool, string>;
                bool isValid = res.Item1;
                string strResult = res.Item2;
                if (isValid)
                {
                    if (!string.IsNullOrEmpty(strResult))
                    {
                        strEncryptResult = strResult;
                    }
                }
                else
                {
                    //await new MessageDialog("Unable to encrypt.").ShowAsync();
                }
            }
            return strEncryptResult;
        }

        /// <summary>
        /// Test case for AES256Encryption
        /// </summary>
        [TestMethod]
        public void AES256Encryption()
        {
            byte[] secureKey = Encoding.UTF8.GetBytes(strAES256Key);
            byte[] bMessage = Encoding.UTF8.GetBytes(strExample);
            string strEncryptResult = string.Empty;
            string strDecryptResult = string.Empty;
            object oEncryptResult = TSGSecurityManager.Encrypt(strExample, SecurityType.AES256, strAES256Key, strIVector);
            strEncryptResult = EncryptResult(strEncryptResult, oEncryptResult);
            object oDecryptResult = TSGSecurityManager.Decrypt(strEncryptResult, SecurityType.AES256, strAES256Key, strIVector);
            strDecryptResult = DecryptResult(strDecryptResult, oDecryptResult);
            //strEncryptResult = Security.Encrypt(strExample, SecurityType.AES256, strAES256Key, strIVector);
            //strDecryptResult = Security.Decrypt(strEncryptResult, SecurityType.AES256, strAES256Key, strIVector);
            Assert.AreEqual(strDecryptResult, strExample); //"uyKnSd9iW4Y+N61CTtIsCQ=="
        }

        /// <summary>
        /// Test case for MD5Encryption
        /// </summary>
        [TestMethod]
        public void MD5Encryption()
        {
            object oEncryptResult = TSGSecurityManager.Encrypt(strExample, SecurityType.MD5, string.Empty, string.Empty);
            string strResult = EncryptResult(string.Empty, oEncryptResult);
            //string strResult = Security.Encrypt(strExample, SecurityType.MD5, string.Empty, string.Empty);
            Assert.AreEqual("c22ceacbd8a41966a48f43cb7d25ae21", strResult); //"cc8ec790d23c53435ca291e7b969d298"
        }
    }
}

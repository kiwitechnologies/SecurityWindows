// **************************************************************
// *
// * Written By: Nishant Sukhwal
// * Copyright © 2016 kiwitech. All rights reserved.
// **************************************************************

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;

namespace TSGSecurity
{
    public static class MD5
    {
        /// <summary>
        /// MD5 Encryption is done by this method.
        /// </summary>
        /// <param name="inputBytes"></param>
        /// <returns></returns>
        public static string Encrypt(string strHash)
        {
            string strReturnData = string.Empty;
            try
            {
                var alg = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Md5);
                IBuffer buff = CryptographicBuffer.ConvertStringToBinary(strHash, BinaryStringEncoding.Utf8);
                var hashed = alg.HashData(buff);
                strReturnData = CryptographicBuffer.EncodeToHexString(hashed);
            }
            catch (Exception ex)
            {
                return strReturnData;
            }
            return strReturnData;
        }
    }
}

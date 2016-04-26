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

namespace TSGSecurity
{
    public static class TSGSecurityManager
    {
        /// <summary>
        /// This method is to Encrypt data. Object can be string or byte[]. If data is not getting encrypted then method will return "Unable to Encrypt".
        /// </summary>
        /// <param name="obj"></param>
        /// <param name="eSecurityType"></param>
        /// <param name="strKey"></param>
        /// <param name="strIVector"></param>
        /// <returns></returns>
        public static object Encrypt(object obj, SecurityType eSecurityType, string strKey, string strIVector)
        {
            string strResult = "Unable to encrypt.";
            byte[] outputBytes = null;
            byte[] bData = null;
            try
            {
                if (obj.GetType() == typeof(string))
                {
                    string strMessage = obj as string;
                    bData = Encoding.UTF8.GetBytes(strMessage);
                }
                else if (obj.GetType() == typeof(byte[]))
                {
                    bData = obj as byte[];
                }
                else
                {
                    return new Tuple<bool, string>(false, "Unable to encrypt.");
                }
                switch (eSecurityType)
                {
                    case SecurityType.AES128:
                    case SecurityType.AES256:
                        AESSecurity.secureKey = Encoding.UTF8.GetBytes(strKey);
                        AESSecurity.iVector = Encoding.UTF8.GetBytes(strIVector);
                        outputBytes = AESSecurity.Encrypt(bData);
                        strResult = Convert.ToBase64String(outputBytes);
                        break;
                    case SecurityType.MD5:
                        strResult = MD5.Encrypt(Convert.ToBase64String(bData));
                        outputBytes = Convert.FromBase64String(strResult);
                        break;
                    default:
                        break;
                }
                if (obj.GetType() == typeof(string))
                {
                    return new Tuple<bool, string>(true, strResult);
                }
                else if (obj.GetType() == typeof(byte[]))
                {
                    return new Tuple<bool, byte[]>(true, outputBytes);
                }
                else
                {
                    return new Tuple<bool, string>(false, "Unable to encrypt.");
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine("Security::Encrypt" + ex.ToString());
                return strResult;
            }
        }

        /// <summary>
        /// This method is to Decrypt data. Object can be string or byte[]. If data is not getting decrypted then method will return "Unable to Decrypt".
        /// </summary>
        /// <param name="obj"></param>
        /// <param name="eSecurityType"></param>
        /// <param name="strKey"></param>
        /// <param name="strIVector"></param>
        /// <returns></returns>
        public static object Decrypt(object obj, SecurityType eSecurityType, string strKey, string strIVector)
        {
            string strResult = "Unable to decrypt.";
            byte[] outputBytes = null;
            byte[] bData = null;
            string strMessage = string.Empty;
            try
            {
                if (obj.GetType() == typeof(string))
                {
                    strMessage = obj as string;
                    bData = Convert.FromBase64String(strMessage);
                }
                else if (obj.GetType() == typeof(byte[]))
                {
                    bData = obj as byte[];
                }
                else
                {
                    return new Tuple<bool, string>(false, "Unable to decrypt.");
                }
                switch (eSecurityType)
                {
                    case SecurityType.AES128:
                    case SecurityType.AES256:
                        AESSecurity.secureKey = Encoding.UTF8.GetBytes(strKey);
                        AESSecurity.iVector = Encoding.UTF8.GetBytes(strIVector);
                        outputBytes = AESSecurity.Decrypt(bData);
                        strResult = Encoding.UTF8.GetString(outputBytes, 0, outputBytes.Length);
                        break;
                    case SecurityType.MD5:
                        strResult = MD5.Encrypt(strMessage);
                        outputBytes = Convert.FromBase64String(strResult);
                        break;
                    default:
                        break;
                }
                if (obj.GetType() == typeof(string))
                {
                    return new Tuple<bool, string>(true, strResult);
                }
                else if (obj.GetType() == typeof(byte[]))
                {
                    return new Tuple<bool, byte[]>(true, outputBytes);
                }
                else
                {
                    return new Tuple<bool, string>(false, "Unable to decrypt.");
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine("Security::Decrypt" + ex.ToString());
                return strResult;
            }
        }
    }
}

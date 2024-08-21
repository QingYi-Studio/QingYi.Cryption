using System.Text;
using System;

namespace XOR
{
    /// <summary>
    /// XOR crypto.<br></br>
    /// XOR加密。
    /// </summary>
    public class XorCrypto
    {
        public static string EncodeString(string plainText, string key)
        {
            byte[] keyArray = Encoding.ASCII.GetBytes(key);
            byte[] plainTextArray = Encoding.ASCII.GetBytes(plainText);
            byte[] cypherTextArray = new byte[plainTextArray.Length];

            for (int i = 0; i < plainTextArray.Length; i++)
            {
                cypherTextArray[i] = (byte)(plainTextArray[i] ^ keyArray[i % keyArray.Length]);
            }

            return Convert.ToBase64String(cypherTextArray);
        }

        public static string DecodeString(string cypherText, string key)
        {
            byte[] keyArray = Encoding.ASCII.GetBytes(key);
            byte[] cypherTextArray = Convert.FromBase64String(cypherText);
            byte[] plainTextArray = new byte[cypherTextArray.Length];

            for (int i = 0; i < cypherTextArray.Length; i++)
            {
                plainTextArray[i] = (byte)(cypherTextArray[i] ^ keyArray[i % keyArray.Length]);
            }

            return Encoding.UTF8.GetString(plainTextArray);
        }

        public static byte[] EncodeStringToBytes(string plainText, string key)
        {
            byte[] keyArray = Encoding.ASCII.GetBytes(key);
            byte[] plainTextArray = Encoding.ASCII.GetBytes(plainText);
            byte[] cypherTextArray = new byte[plainTextArray.Length];

            for (int i = 0; i < plainTextArray.Length; i++)
            {
                cypherTextArray[i] = (byte)(plainTextArray[i] ^ keyArray[i % keyArray.Length]);
            }

            return cypherTextArray;
        }

        public static byte[] DecodeStringToBytes(string cypherText, string key)
        {
            byte[] keyArray = Encoding.ASCII.GetBytes(key);
            byte[] cypherTextArray = Convert.FromBase64String(cypherText);
            byte[] plainTextArray = new byte[cypherTextArray.Length];

            for (int i = 0; i < cypherTextArray.Length; i++)
            {
                plainTextArray[i] = (byte)(cypherTextArray[i] ^ keyArray[i % keyArray.Length]);
            }

            return plainTextArray;
        }

        public static string EncodeBytesToString(byte[] plainTextArray, string key)
        {
            byte[] keyArray = Encoding.ASCII.GetBytes(key);
            byte[] cypherTextArray = new byte[plainTextArray.Length];

            for (int i = 0; i < plainTextArray.Length; i++)
            {
                cypherTextArray[i] = (byte)(plainTextArray[i] ^ keyArray[i % keyArray.Length]);
            }

            return Convert.ToBase64String(cypherTextArray);
        }

        public static string DecodeBytesToString(byte[] cypherTextArray, string key)
        {
            byte[] keyArray = Encoding.ASCII.GetBytes(key);
            byte[] plainTextArray = new byte[cypherTextArray.Length];

            for (int i = 0; i < cypherTextArray.Length; i++)
            {
                plainTextArray[i] = (byte)(cypherTextArray[i] ^ keyArray[i % keyArray.Length]);
            }

            return Encoding.UTF8.GetString(plainTextArray);
        }

        public static byte[] EncodeBytes(byte[] plainTextArray, string key)
        {
            byte[] keyArray = Encoding.ASCII.GetBytes(key);
            byte[] cypherTextArray = new byte[plainTextArray.Length];

            for (int i = 0; i < plainTextArray.Length; i++)
            {
                cypherTextArray[i] = (byte)(plainTextArray[i] ^ keyArray[i % keyArray.Length]);
            }

            return cypherTextArray;
        }

        public static byte[] DecodeBytes(byte[] cypherTextArray, string key)
        {
            byte[] keyArray = Encoding.ASCII.GetBytes(key);
            byte[] plainTextArray = new byte[cypherTextArray.Length];

            for (int i = 0; i < cypherTextArray.Length; i++)
            {
                plainTextArray[i] = (byte)(cypherTextArray[i] ^ keyArray[i % keyArray.Length]);
            }

            return plainTextArray;
        }
    }
}

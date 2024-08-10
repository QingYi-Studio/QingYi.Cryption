using System.Text;
using System;

namespace QingYi.Cryption.XOR
{
    public class XORTextCryption
    {
        private readonly string key;

        public XORTextCryption(string key)
        {
            this.key = key;
        }

        public string Encode(string plainText)
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

        public string Decode(string cypherText)
        {
            byte[] keyArray = Encoding.ASCII.GetBytes(key);
            byte[] cypherTextArray = Convert.FromBase64String(cypherText);
            byte[] plainTextArray = new byte[cypherTextArray.Length];

            for (int i = 0; i < cypherTextArray.Length; i++)
            {
                plainTextArray[i] = (byte)(cypherTextArray[i] ^ keyArray[i % keyArray.Length]);
            }

            return Encoding.ASCII.GetString(plainTextArray);
        }
    }
}

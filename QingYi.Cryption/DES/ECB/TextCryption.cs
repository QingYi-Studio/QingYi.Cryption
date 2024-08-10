using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace QingYi.Cryption.DES.ECB
{
    internal class DesEcbTextCryption
    {
        private readonly byte[] _key;

        public DesEcbTextCryption(byte[] key)
        {
            if (key.Length != 8)
            {
                throw new ArgumentException("DES key must be 8 bytes long");
            }
            _key = key;
        }

        public byte[] Encrypt(string plainText)
        {
            using (System.Security.Cryptography.DES des = System.Security.Cryptography.DES.Create())
            {
                des.Mode = CipherMode.ECB;
                des.Padding = PaddingMode.PKCS7;

                using (ICryptoTransform encryptor = des.CreateEncryptor(_key, null))
                {
                    byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                    return PerformCryptography(plainBytes, encryptor);
                }
            }
        }

        public string Decrypt(byte[] cipherText)
        {
            using (System.Security.Cryptography.DES des = System.Security.Cryptography.DES.Create())
            {
                des.Mode = CipherMode.ECB;
                des.Padding = PaddingMode.PKCS7;

                using (ICryptoTransform decryptor = des.CreateDecryptor(_key, null))
                {
                    byte[] plainBytes = PerformCryptography(cipherText, decryptor);
                    return Encoding.UTF8.GetString(plainBytes);
                }
            }
        }

        private byte[] PerformCryptography(byte[] data, ICryptoTransform cryptoTransform)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, cryptoTransform, CryptoStreamMode.Write))
                {
                    cs.Write(data, 0, data.Length);
                    cs.FlushFinalBlock();
                    return ms.ToArray();
                }
            }
        }
    }
}

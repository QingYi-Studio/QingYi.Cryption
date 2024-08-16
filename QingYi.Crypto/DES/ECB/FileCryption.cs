using System;
using System.IO;
using System.Security.Cryptography;

namespace DES.ECB
{
    public class DesEcbFileCryption
    {
        private readonly byte[] _key;

        public DesEcbFileCryption(byte[] key)
        {
            if (key.Length != 8)
            {
                throw new ArgumentException("DES key must be 8 bytes long");
            }
            _key = key;
        }

        public void Encrypt(string inputFilePath, string outputFilePath)
        {
            byte[] fileBytes = File.ReadAllBytes(inputFilePath);

            using (System.Security.Cryptography.DES des = System.Security.Cryptography.DES.Create())
            {
                des.Mode = CipherMode.ECB;
                des.Padding = PaddingMode.PKCS7;

                using (ICryptoTransform encryptor = des.CreateEncryptor(_key, null))
                {
                    byte[] encryptedBytes = PerformCryptography(fileBytes, encryptor);
                    File.WriteAllBytes(outputFilePath, encryptedBytes);
                }
            }
        }

        public void Decrypt(string inputFilePath, string outputFilePath)
        {
            byte[] fileBytes = File.ReadAllBytes(inputFilePath);

            using (System.Security.Cryptography.DES des = System.Security.Cryptography.DES.Create())
            {
                des.Mode = CipherMode.ECB;
                des.Padding = PaddingMode.PKCS7;

                using (ICryptoTransform decryptor = des.CreateDecryptor(_key, null))
                {
                    byte[] decryptedBytes = PerformCryptography(fileBytes, decryptor);
                    File.WriteAllBytes(outputFilePath, decryptedBytes);
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

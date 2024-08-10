using System;
using System.IO;
using System.Security.Cryptography;

namespace QingYi.Cryption.DES.CFB
{
    /// <summary>
    /// It is used to encrypt DES in CFB mode.(Only for file.)
    /// </summary>
    public class DesCfbFileCryption
    {
        /// <summary>
        /// The key used for encryption.
        /// </summary>
        private readonly byte[] key;

        /// <summary>
        /// The iv used for encryption
        /// </summary>
        private readonly byte[] iv;

        public DesCfbFileCryption(byte[] key, byte[] iv)
        {
            if (key.Length != 8) throw new ArgumentException("Key must be 8 bytes long.");
            if (iv.Length != 8) throw new ArgumentException("IV must be 8 bytes long.");
            this.key = key;
            this.iv = iv;
        }

        public void EncryptFile(string inputFilePath, string outputFilePath)
        {
            using (var des = System.Security.Cryptography.DES.Create())
            {
                des.Key = key;
                des.IV = iv;
                des.Mode = CipherMode.CFB;
                des.Padding = PaddingMode.PKCS7;

                using (var encryptor = des.CreateEncryptor())
                using (var inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                using (var outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                using (var cryptoStream = new CryptoStream(outputFileStream, encryptor, CryptoStreamMode.Write))
                {
                    inputFileStream.CopyTo(cryptoStream);
                }
            }
        }

        public void DecryptFile(string inputFilePath, string outputFilePath)
        {
            using (var des = System.Security.Cryptography.DES.Create())
            {
                des.Key = key;
                des.IV = iv;
                des.Mode = CipherMode.CFB;
                des.Padding = PaddingMode.PKCS7;

                using (var decryptor = des.CreateDecryptor())
                using (var inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                using (var outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                using (var cryptoStream = new CryptoStream(inputFileStream, decryptor, CryptoStreamMode.Read))
                {
                    cryptoStream.CopyTo(outputFileStream);
                }
            }
        }
    }
}

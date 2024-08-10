using System.IO;
using System.Security.Cryptography;
using System;

namespace QingYi.Cryption.DES.CFB
{
    /// <summary>
    /// It is used to encrypt DES in CFB mode.(Only for text.)
    /// </summary>
    internal class DesCfbTextCryption
    {
        /// <summary>
        /// The key used for encryption.
        /// </summary>
        private readonly byte[] key;

        /// <summary>
        /// The iv used for encryption
        /// </summary>
        private readonly byte[] iv;

        public DesCfbTextCryption(byte[] key, byte[] iv)
        {
            if (key.Length != 8) throw new ArgumentException("Key must be 8 bytes long.");
            if (iv.Length != 8) throw new ArgumentException("IV must be 8 bytes long.");
            this.key = key;
            this.iv = iv;
        }

        /// <summary>
        /// Encrypt the text.
        /// </summary>
        /// <param name="plainText">The text you want to encrypt.</param>
        /// <returns></returns>
        public byte[] Encrypt(byte[] plainText)
        {
            using (var des = System.Security.Cryptography.DES.Create())
            {
                des.Key = key;
                des.IV = iv;
                des.Mode = CipherMode.CFB;
                des.Padding = PaddingMode.PKCS7;

                using (var encryptor = des.CreateEncryptor())
                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        cs.Write(plainText, 0, plainText.Length);
                    }
                    return ms.ToArray();
                }
            }
        }

        /// <summary>
        /// Decrypt the text.
        /// </summary>
        /// <param name="plainText">The text you want to decrypt.</param>
        /// <returns></returns>
        public byte[] Decrypt(byte[] cipherText)
        {
            using (var des = System.Security.Cryptography.DES.Create())
            {
                des.Key = key;
                des.IV = iv;
                des.Mode = CipherMode.CFB;
                des.Padding = PaddingMode.PKCS7;

                using (var decryptor = des.CreateDecryptor())
                using (var ms = new MemoryStream(cipherText))
                using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                using (var result = new MemoryStream())
                {
                    cs.CopyTo(result);
                    return result.ToArray();
                }
            }
        }
    }
}

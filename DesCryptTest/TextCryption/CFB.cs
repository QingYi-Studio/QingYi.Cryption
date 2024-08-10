using System.Security.Cryptography;

namespace DES.FileCryption
{
    internal class CFB
    {
        private readonly byte[] key;
        private readonly byte[] iv;

        public CFB(byte[] key, byte[] iv)
        {
            if (key.Length != 8) throw new ArgumentException("Key must be 8 bytes long.");
            if (iv.Length != 8) throw new ArgumentException("IV must be 8 bytes long.");
            this.key = key;
            this.iv = iv;
        }

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

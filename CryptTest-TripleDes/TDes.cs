using System.Security.Cryptography;
using System.Text;

namespace CryptTest_TripleDes
{
    public class TDesString
    {
        private readonly string Key;
        private readonly string IV;

        // 构造函数
        public TDesString(string key, string iv)
        {
            if (key.Length != 24)
                throw new ArgumentException("Key must be 24 bytes long.");
            if (iv.Length != 8)
                throw new ArgumentException("IV must be 8 bytes long.");

            Key = key;
            IV = iv;
        }

        /// <summary>
        /// Cut a 24-byte string into three 8-byte pieces.<br></br>
        /// 将 24 字节的字符串切割成三份，每份 8 字节。
        /// </summary>
        /// <param name="part1">Part1<br></br>第一部分</param>
        /// <param name="part2">Part2<br></br>第二部分</param>
        /// <param name="part3">Part3<br></br>第三部分</param>
        private void GetKey(out string part1, out string part2, out string part3)
        {
            if (Key.Length != 24)
                throw new ArgumentException("Input string must be 24 bytes long.");

            // 将输入字符串转换为字节数组
            byte[] bytes = Encoding.UTF8.GetBytes(Key);

            // 确保字节数组长度为 24
            if (bytes.Length != 24)
                throw new ArgumentException("Input string must be 24 bytes long.");

            // 切割字节数组为三份，每份 8 字节
            part1 = Encoding.UTF8.GetString(bytes, 0, 8);
            part2 = Encoding.UTF8.GetString(bytes, 8, 8);
            part3 = Encoding.UTF8.GetString(bytes, 16, 8);
        }

        public string CBCEncrypt(string text)
        {
            string originText = text;
            GetKey(out string part1, out string part2, out string part3);
            string encryptText1 = CBCMode.DESEncrypt(originText, part1, IV);
            string encryptText2 = CBCMode.DESEncrypt(encryptText1, part2, IV);
            string encryptText3 = CBCMode.DESEncrypt(encryptText2, part3, IV);
            return encryptText3;
        }

        public string CBCDecrypt(string text)
        {
            string encryptText = text;
            GetKey(out string part1, out string part2, out string part3);
            string decryptText1 = CBCMode.DESDecrypt(encryptText, part3, IV);
            string decryptText2 = CBCMode.DESDecrypt(decryptText1, part2, IV);
            string decryptText3 = CBCMode.DESDecrypt(decryptText2, part1, IV);
            return decryptText3;
        }

        class CBCMode
        {
            public static string DESEncrypt(string plainText, string key, string iv)
            {
                byte[] plaintextBytes = Encoding.UTF8.GetBytes(plainText);
                byte[] keyBytes = Encoding.UTF8.GetBytes(key);
                byte[] ivBytes = Encoding.UTF8.GetBytes(iv);

                using (DES desAlg = DES.Create())
                {
                    desAlg.Mode = CipherMode.CBC;
                    desAlg.Key = keyBytes;
                    desAlg.IV = ivBytes;

                    using (MemoryStream msEncrypt = new MemoryStream())
                    {
                        using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, desAlg.CreateEncryptor(), CryptoStreamMode.Write))
                        {
                            csEncrypt.Write(plaintextBytes, 0, plaintextBytes.Length);
                            csEncrypt.FlushFinalBlock();
                            return Convert.ToBase64String(msEncrypt.ToArray());
                        }
                    }
                }
            }

            public static string DESDecrypt(string encryptedText, string key, string iv)
            {
                byte[] cipherTextBytes = Convert.FromBase64String(encryptedText);
                byte[] keyBytes = Encoding.UTF8.GetBytes(key);
                byte[] ivBytes = Encoding.UTF8.GetBytes(iv);

                using (DES desAlg = DES.Create())
                {
                    desAlg.Mode = CipherMode.CBC;
                    desAlg.Key = keyBytes;
                    desAlg.IV = ivBytes;

                    using (MemoryStream msDecrypt = new MemoryStream(cipherTextBytes))
                    {
                        using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, desAlg.CreateDecryptor(), CryptoStreamMode.Read))
                        {
                            using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                            {
                                return srDecrypt.ReadToEnd();
                            }
                        }
                    }
                }
            }
        }

        class ECBMode
        {
            private readonly byte[] _key;

            public ECBMode(string key)
            {
                if (key.Length != 8)
                {
                    throw new ArgumentException("DES key must be 8 bytes long");
                }
                _key = Encoding.UTF8.GetBytes(key);
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
}

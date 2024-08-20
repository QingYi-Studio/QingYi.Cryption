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

        /// <summary>
        /// Execute CBC encryption mode.<br></br>
        /// 执行CBC加密模式。
        /// </summary>
        /// <param name="text">Text that needs to be encrypted.<br></br>需要加密的文本。</param>
        /// <returns>Encrypted text<br></br>加密的文本</returns>
        public string CBCEncrypt(string text)
        {
            string originText = text;
            GetKey(out string part1, out string part2, out string part3);
            string encryptText1 = CBCMode.DESEncrypt(originText, part1, IV);
            string encryptText2 = CBCMode.DESEncrypt(encryptText1, part2, IV);
            string encryptText3 = CBCMode.DESEncrypt(encryptText2, part3, IV);
            return encryptText3;
        }

        /// <summary>
        /// Execute CBC decryption mode.<br></br>
        /// 执行CBC解密模式。
        /// </summary>
        /// <param name="text">Text that needs to be decrypted.<br></br>需要解密的文本。</param>
        /// <returns>Decrypted text<br></br>解密的文本</returns>
        public string CBCDecrypt(string text)
        {
            string encryptText = text;
            GetKey(out string part1, out string part2, out string part3);
            string decryptText1 = CBCMode.DESDecrypt(encryptText, part3, IV);
            string decryptText2 = CBCMode.DESDecrypt(decryptText1, part2, IV);
            string decryptText3 = CBCMode.DESDecrypt(decryptText2, part1, IV);
            return decryptText3;
        }

        /// <summary>
        /// Execute ECB encryption mode.<br></br>
        /// 执行ECB加密模式。
        /// </summary>
        /// <param name="text">Text that needs to be encrypted.<br></br>需要加密的文本。</param>
        /// <returns>Encrypted text<br></br>加密的文本</returns>
        public string ECBEncrypt(string text)
        {
            GetKey(out string part1, out string part2, out string part3);
            ECBMode ecb1 = new ECBMode(part1);
            ECBMode ecb2 = new ECBMode(part2);
            ECBMode ecb3 = new ECBMode(part3);
            string originText = text;
            string encryptText1 = ecb1.EncryptString(text);
            string encryptText2 = ecb2.EncryptString(encryptText1);
            string encryptText3 = ecb3.EncryptString(encryptText2);
            return encryptText3;
        }

        /// <summary>
        /// Execute ECB decryption mode.<br></br>
        /// 执行ECB解密模式。
        /// </summary>
        /// <param name="text">Text that needs to be decrypted.<br></br>需要解密的文本。</param>
        /// <returns>Decrypted text<br></br>解密的文本</returns>
        public string ECBDecrypt(string text)
        {
            GetKey(out string part1, out string part2, out string part3);
            ECBMode ecb1 = new ECBMode(part1);
            ECBMode ecb2 = new ECBMode(part2);
            ECBMode ecb3 = new ECBMode(part3);
            string encryptText = text;
            string decryptText1 = ecb3.DecryptString(encryptText);
            string decryptText2 = ecb2.DecryptString(decryptText1);
            string decryptText3 = ecb1.DecryptString(decryptText2);
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

            /// <summary>
            /// Initializes a new instance of the <see cref="DesEcbTextCryption"/> class with the specified key.<br></br>
            /// 用指定的密钥初始化 <see cref="DesEcbTextCryption"/> 类的新实例。
            /// </summary>
            /// <param name="key">The key used for encryption and decryption. It must be 8 bytes long.<br></br>用于加密和解密的密钥。长度必须为8字节。</param>
            /// <exception cref="ArgumentException">Thrown when the key length is not 8 bytes.|当密钥长度不是8字节时抛出。</exception>
            public ECBMode(string key)
            {
                if (key.Length != 8)
                {
                    throw new ArgumentException("DES key must be 8 bytes long");
                }
                _key = Encoding.UTF8.GetBytes(key);
            }

            /// <summary>
            /// Encrypts the specified plain text using DES in ECB mode.<br></br>
            /// 使用DES以ECB方式加密指定的明文。
            /// </summary>
            /// <param name="plainText">The plain text to encrypt.<br></br>要加密的纯文本。</param>
            /// <returns>The encrypted text.|加密文本。</returns>
            public string EncryptString(string plainText)
            {
                using (System.Security.Cryptography.DES des = System.Security.Cryptography.DES.Create())
                {
                    des.Mode = CipherMode.ECB;
                    des.Padding = PaddingMode.PKCS7;

                    using (ICryptoTransform encryptor = des.CreateEncryptor(_key, null))
                    {
                        byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                        byte[] encryptedBytes = PerformCryptography(plainBytes, encryptor);
                        return Convert.ToBase64String(encryptedBytes);
                    }
                }
            }

            /// <summary>
            /// Encrypts the specified plain text using DES in ECB mode.<br></br>
            /// 使用DES以ECB方式加密指定的明文。
            /// </summary>
            /// <param name="plainText">The plain text to encrypt.<br></br>要加密的纯文本。</param>
            /// <returns>The encrypted text as a byte array.|加密文本作为字节数组。</returns>
            public byte[] EncryptStringToBytes(string plainText)
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

            /// <summary>
            /// Decrypts the specified cipher text using DES in ECB mode.<br></br>
            /// 在ECB模式下使用DES解密指定的密文。
            /// </summary>
            /// <param name="cipherText">The encrypted text as a byte array.<br></br>加密文本作为字节数组。</param>
            /// <returns>The decrypted plain text.|解密后的纯文本。</returns>
            public string DecryptBytesToString(byte[] cipherText)
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

            /// <summary>
            /// Decrypts the specified cipher text using DES in ECB mode.<br></br>
            /// 在ECB模式下使用DES解密指定的密文。
            /// </summary>
            /// <param name="cipherTextBase64">The encrypted text.<br></br>被加密的文本。</param>
            /// <returns>The decrypted plain text.|解密后的纯文本。</returns>
            public string DecryptString(string cipherTextBase64)
            {
                using (System.Security.Cryptography.DES des = System.Security.Cryptography.DES.Create())
                {
                    des.Mode = CipherMode.ECB;
                    des.Padding = PaddingMode.PKCS7;

                    using (ICryptoTransform decryptor = des.CreateDecryptor(_key, null))
                    {
                        // Convert Base64 string to byte array
                        byte[] cipherBytes = Convert.FromBase64String(cipherTextBase64);
                        // Perform decryption
                        byte[] plainBytes = PerformCryptography(cipherBytes, decryptor);
                        // Convert byte array to string
                        return Encoding.UTF8.GetString(plainBytes);
                    }
                }
            }

            /// <summary>
            /// Performs encryption or decryption on the provided data using the specified cryptographic transformation.<br></br>
            /// 使用指定的加密转换对提供的数据执行加密或解密。
            /// </summary>
            /// <param name="data">The data to process.<br></br>要处理的数据。</param>
            /// <param name="cryptoTransform">The cryptographic transformation to use.<br></br>要使用的加密转换。</param>
            /// <returns>The processed data as a byte array.|以字节数组的形式处理数据。</returns>
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

    public class TDesFile
    {

    }
}

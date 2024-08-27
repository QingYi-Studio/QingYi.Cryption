using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace AES.CBC
{
    public class PKCS7
    {
        private static byte[] FormattingKeyIV(string hex)
        {
            int numberChars = hex.Length;
            byte[] bytes = new byte[numberChars / 2];
            for (int i = 0; i < numberChars; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }
            return bytes;
        }

        public static string EncryptString(string plainText, string keyHex, string ivHex)
        {
            if (plainText == null) throw new ArgumentNullException(nameof(plainText));
            if (string.IsNullOrEmpty(keyHex) || keyHex.Length != 64) // 32字节密钥的十六进制表示
                throw new ArgumentException("Key must be 64 hex characters.", nameof(keyHex));
            if (string.IsNullOrEmpty(ivHex) || ivHex.Length != 32) // 16字节IV的十六进制表示
                throw new ArgumentException("IV must be 32 hex characters.", nameof(ivHex));

            byte[] key = FormattingKeyIV(keyHex);
            byte[] iv = FormattingKeyIV(ivHex);

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter sw = new StreamWriter(cs))
                        {
                            sw.Write(plainText);
                        }
                    }
                    return Convert.ToBase64String(ms.ToArray());
                }
            }
        }

        public static string DecryptString(string cipherText, string keyHex, string ivHex)
        {
            if (cipherText == null) throw new ArgumentNullException(nameof(cipherText));
            if (string.IsNullOrEmpty(keyHex) || keyHex.Length != 64) // 32字节密钥的十六进制表示
                throw new ArgumentException("Key must be 64 hex characters.", nameof(keyHex));
            if (string.IsNullOrEmpty(ivHex) || ivHex.Length != 32) // 16字节IV的十六进制表示
                throw new ArgumentException("IV must be 32 hex characters.", nameof(ivHex));

            byte[] key = FormattingKeyIV(keyHex);
            byte[] iv = FormattingKeyIV(ivHex);

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using (MemoryStream ms = new MemoryStream(Convert.FromBase64String(cipherText)))
                {
                    using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader sr = new StreamReader(cs))
                        {
                            return sr.ReadToEnd();
                        }
                    }
                }
            }
        }

        public static string EncryptBytesToString(byte[] data, string keyHex, string ivHex)
        {
            byte[] key = FormattingKeyIV(keyHex);
            byte[] iv = FormattingKeyIV(ivHex);

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                {
                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            cs.Write(data, 0, data.Length);
                            cs.FlushFinalBlock();
                            return Convert.ToBase64String(ms.ToArray());
                        }
                    }
                }
            }
        }

        public static byte[] DecryptStringToBytes(string encryptedData, string keyHex, string ivHex)
        {
            byte[] key = FormattingKeyIV(keyHex);
            byte[] iv = FormattingKeyIV(ivHex);
            byte[] encryptedBytes = Convert.FromBase64String(encryptedData);

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                {
                    using (MemoryStream ms = new MemoryStream(encryptedBytes))
                    {
                        using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                        {
                            using (MemoryStream result = new MemoryStream())
                            {
                                cs.CopyTo(result);
                                return result.ToArray();
                            }
                        }
                    }
                }
            }
        }

        public static byte[] EncryptStringToBytes(string plainText, string keyHex, string ivHex)
        {
            byte[] key = FormattingKeyIV(keyHex);
            byte[] iv = FormattingKeyIV(ivHex);

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                {
                    byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            cs.Write(plainBytes, 0, plainBytes.Length);
                            cs.FlushFinalBlock();
                            return ms.ToArray();
                        }
                    }
                }
            }
        }

        public static string DecryptBytesToString(byte[] cipherBytes, string keyHex, string ivHex)
        {
            byte[] key = FormattingKeyIV(keyHex);
            byte[] iv = FormattingKeyIV(ivHex);

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                {
                    using (MemoryStream ms = new MemoryStream(cipherBytes))
                    {
                        using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                        {
                            using (StreamReader reader = new StreamReader(cs))
                            {
                                return reader.ReadToEnd();
                            }
                        }
                    }
                }
            }
        }

        public static void EncryptFile(string inputFilePath, string outputFilePath, string keyHex, string ivHex)
        {
            byte[] key = FormattingKeyIV(keyHex);
            byte[] iv = FormattingKeyIV(ivHex);

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                using (FileStream fsInput = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                using (FileStream fsOutput = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                using (CryptoStream cs = new CryptoStream(fsOutput, encryptor, CryptoStreamMode.Write))
                {
                    fsInput.CopyTo(cs);
                }
            }
        }

        public static void DecryptFile(string inputFilePath, string outputFilePath, string keyHex, string ivHex)
        {
            byte[] key = FormattingKeyIV(keyHex);
            byte[] iv = FormattingKeyIV(ivHex);

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                using (FileStream fsInput = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                using (FileStream fsOutput = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                using (CryptoStream cs = new CryptoStream(fsOutput, decryptor, CryptoStreamMode.Write))
                {
                    fsInput.CopyTo(cs);
                }
            }
        }

        public static byte[] EncryptBytes(byte[] data, string keyHex, string ivHex)
        {
            byte[] key = FormattingKeyIV(keyHex);
            byte[] iv = FormattingKeyIV(ivHex);

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                {
                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            cs.Write(data, 0, data.Length);
                            cs.FlushFinalBlock();
                        }
                        return ms.ToArray();
                    }
                }
            }
        }

        public static byte[] DecryptBytes(byte[] data, string keyHex, string ivHex)
        {
            byte[] key = FormattingKeyIV(keyHex);
            byte[] iv = FormattingKeyIV(ivHex);

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                {
                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Write))
                        {
                            cs.Write(data, 0, data.Length);
                            cs.FlushFinalBlock();
                        }
                        return ms.ToArray();
                    }
                }
            }
        }

        public static byte[] EncryptFileToBytes(string filePath, string keyHex, string ivHex)
        {
            byte[] key = FormattingKeyIV(keyHex);
            byte[] iv = FormattingKeyIV(ivHex);

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                {
                    using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                    {
                        using (MemoryStream ms = new MemoryStream())
                        {
                            using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                            {
                                fs.CopyTo(cs);
                            }
                            return ms.ToArray();
                        }
                    }
                }
            }
        }

        public static void DecryptBytesToFile(byte[] encryptedData, string outputFilePath, string keyHex, string ivHex)
        {
            byte[] key = FormattingKeyIV(keyHex);
            byte[] iv = FormattingKeyIV(ivHex);

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                {
                    using (MemoryStream ms = new MemoryStream(encryptedData))
                    {
                        using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                        {
                            using (FileStream fs = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                            {
                                cs.CopyTo(fs);
                            }
                        }
                    }
                }
            }
        }

        public static void EncryptBytesToFile(byte[] data, string filePath, string keyHex, string ivHex)
        {
            byte[] key = FormattingKeyIV(keyHex);
            byte[] iv = FormattingKeyIV(ivHex);

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                {
                    using (FileStream fs = new FileStream(filePath, FileMode.Create, FileAccess.Write))
                    {
                        using (CryptoStream cs = new CryptoStream(fs, encryptor, CryptoStreamMode.Write))
                        {
                            cs.Write(data, 0, data.Length);
                            cs.FlushFinalBlock();
                        }
                    }
                }
            }
        }

        public static byte[] DecryptFileToBytes(string filePath, string keyHex, string ivHex)
        {
            byte[] key = FormattingKeyIV(keyHex);
            byte[] iv = FormattingKeyIV(ivHex);

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                {
                    using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                    {
                        using (MemoryStream ms = new MemoryStream())
                        {
                            using (CryptoStream cs = new CryptoStream(fs, decryptor, CryptoStreamMode.Read))
                            {
                                cs.CopyTo(ms);
                            }
                            return ms.ToArray();
                        }
                    }
                }
            }
        }
    }
}

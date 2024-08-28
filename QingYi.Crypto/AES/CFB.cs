using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace AES
{
    /// <summary>
    /// CBC encryption mode.<br></br>
    /// CBC加密模式。
    /// </summary>
    public class CFB
    {
        /// <summary>
        /// PKCS7 padding mode.
        /// PKCS7 填充模式。
        /// </summary>
        public class PKCS7
        {
            /// <summary>
            /// Encrypts a plain text string using AES encryption with the specified key and IV.<br/>
            /// 使用指定的密钥和IV对明文字符串进行AES加密。
            /// </summary>
            /// <param name="plainText">The plain text string to be encrypted.<br/>要加密的明文字符串。</param>
            /// <param name="keyBase64">The base64 encoded key for encryption.<br/>用于加密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <returns>The base64 encoded encrypted string.<br/>Base64编码的加密字符串。</returns>
            public static string EncryptString(string plainText, string keyBase64, string ivBase64)
            {
                if (plainText == null || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null"); // 参数不能为null

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.PKCS7;

                    using (ICryptoTransform encryptor = aes.CreateEncryptor())
                    using (MemoryStream memoryStream = new MemoryStream())
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                        cryptoStream.Write(plainBytes, 0, plainBytes.Length);
                        cryptoStream.FlushFinalBlock();
                        byte[] cipherBytes = memoryStream.ToArray();
                        return Convert.ToBase64String(cipherBytes);
                    }
                }
            }

            /// <summary>
            /// Decrypts an encrypted base64 string using AES decryption with the specified key and IV.<br/>
            /// 使用指定的密钥和IV对Base64编码的加密字符串进行AES解密。
            /// </summary>
            /// <param name="cipherTextBase64">The base64 encoded encrypted string to be decrypted.<br/>要解密的Base64编码的加密字符串。</param>
            /// <param name="keyBase64">The base64 encoded key for decryption.<br/>用于解密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <returns>The decrypted plain text string.<br/>解密后的明文字符串。</returns>
            public static string DecryptString(string cipherTextBase64, string keyBase64, string ivBase64)
            {
                if (cipherTextBase64 == null || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null"); // 参数不能为null

                byte[] cipherBytes = Convert.FromBase64String(cipherTextBase64);
                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.PKCS7;

                    using (ICryptoTransform decryptor = aes.CreateDecryptor())
                    using (MemoryStream memoryStream = new MemoryStream(cipherBytes))
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                    using (StreamReader reader = new StreamReader(cryptoStream))
                    {
                        return reader.ReadToEnd();
                    }
                }
            }

            /// <summary>
            /// Encrypts a plain text string and returns the encrypted data as a byte array.<br/>
            /// 对明文字符串进行加密，并将加密后的数据作为字节数组返回。
            /// </summary>
            /// <param name="plainText">The plain text string to be encrypted.<br/>要加密的明文字符串。</param>
            /// <param name="keyBase64">The base64 encoded key for encryption.<br/>用于加密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <returns>A byte array containing the encrypted data.<br/>包含加密数据的字节数组。</returns>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null.<br/>当任何一个参数为null时抛出。</exception>
            public static byte[] EncryptStringToBytes(string plainText, string keyBase64, string ivBase64)
            {
                if (plainText == null || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null"); // 参数不能为null

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.PKCS7;

                    using (ICryptoTransform encryptor = aes.CreateEncryptor())
                    using (MemoryStream memoryStream = new MemoryStream())
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                        cryptoStream.Write(plainBytes, 0, plainBytes.Length);
                        cryptoStream.FlushFinalBlock();
                        return memoryStream.ToArray();
                    }
                }
            }

            /// <summary>
            /// Decrypts a byte array containing encrypted data and returns the plain text string.<br/>
            /// 解密包含加密数据的字节数组，并返回明文字符串。
            /// </summary>
            /// <param name="cipherBytes">The byte array containing the encrypted data.<br/>包含加密数据的字节数组。</param>
            /// <param name="keyBase64">The base64 encoded key for decryption.<br/>用于解密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <returns>The decrypted plain text string.<br/>解密后的明文字符串。</returns>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null.<br/>当任何一个参数为null时抛出。</exception>
            public static string DecryptBytesToString(byte[] cipherBytes, string keyBase64, string ivBase64)
            {
                if (cipherBytes == null || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null"); // 参数不能为null

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.PKCS7;

                    using (ICryptoTransform decryptor = aes.CreateDecryptor())
                    using (MemoryStream memoryStream = new MemoryStream(cipherBytes))
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                    using (StreamReader reader = new StreamReader(cryptoStream))
                    {
                        return reader.ReadToEnd();
                    }
                }
            }

            /// <summary>
            /// Encrypts a byte array and returns the encrypted data as a base64 encoded string.<br/>
            /// 对字节数组进行加密，并将加密后的数据以Base64编码的字符串形式返回。
            /// </summary>
            /// <param name="plainBytes">The byte array to be encrypted.<br/>要加密的字节数组。</param>
            /// <param name="keyBase64">The base64 encoded key for encryption.<br/>用于加密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <returns>A base64 encoded string containing the encrypted data.<br/>包含加密数据的Base64编码字符串。</returns>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null.<br/>当任何一个参数为null时抛出。</exception>
            public static string EncryptBytesToString(byte[] plainBytes, string keyBase64, string ivBase64)
            {
                if (plainBytes == null || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null"); // 参数不能为null

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.PKCS7;

                    using (ICryptoTransform encryptor = aes.CreateEncryptor())
                    using (MemoryStream memoryStream = new MemoryStream())
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(plainBytes, 0, plainBytes.Length);
                        cryptoStream.FlushFinalBlock();
                        byte[] cipherBytes = memoryStream.ToArray();
                        return Convert.ToBase64String(cipherBytes); // 返回Base64编码的加密数据
                    }
                }
            }

            /// <summary>
            /// Decrypts a base64 encoded string containing encrypted data and returns the decrypted byte array.<br/>
            /// 解密包含加密数据的Base64编码字符串，并将解密后的字节数组返回。
            /// </summary>
            /// <param name="cipherTextBase64">The base64 encoded string containing the encrypted data.<br/>包含加密数据的Base64编码字符串。</param>
            /// <param name="keyBase64">The base64 encoded key for decryption.<br/>用于解密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <returns>A byte array containing the decrypted data.<br/>包含解密数据的字节数组。</returns>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null.<br/>当任何一个参数为null时抛出。</exception>
            public static byte[] DecryptStringToBytes(string cipherTextBase64, string keyBase64, string ivBase64)
            {
                if (cipherTextBase64 == null || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null"); // 参数不能为null

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);
                byte[] cipherBytes = Convert.FromBase64String(cipherTextBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.PKCS7;

                    using (ICryptoTransform decryptor = aes.CreateDecryptor())
                    using (MemoryStream memoryStream = new MemoryStream(cipherBytes))
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                    using (MemoryStream resultStream = new MemoryStream())
                    {
                        cryptoStream.CopyTo(resultStream); // 将解密后的数据写入结果流
                        return resultStream.ToArray(); // 返回解密后的字节数组
                    }
                }
            }

            /// <summary>
            /// Encrypts a byte array using AES encryption and returns the encrypted byte array.<br/>
            /// 使用AES加密对字节数组进行加密，并返回加密后的字节数组。
            /// </summary>
            /// <param name="plainBytes">The byte array to be encrypted.<br/>要加密的字节数组。</param>
            /// <param name="keyBase64">The base64 encoded key for encryption.<br/>用于加密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <returns>A byte array containing the encrypted data.<br/>包含加密数据的字节数组。</returns>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null.<br/>当任何一个参数为null时抛出。</exception>
            public static byte[] EncryptBytes(byte[] plainBytes, string keyBase64, string ivBase64)
            {
                if (plainBytes == null || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null"); // 参数不能为null

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.PKCS7;

                    using (ICryptoTransform encryptor = aes.CreateEncryptor())
                    using (MemoryStream memoryStream = new MemoryStream())
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(plainBytes, 0, plainBytes.Length);
                        cryptoStream.FlushFinalBlock();
                        return memoryStream.ToArray(); // 返回加密后的字节数组
                    }
                }
            }

            /// <summary>
            /// Decrypts an encrypted byte array using AES decryption and returns the decrypted byte array.<br/>
            /// 使用AES解密对加密的字节数组进行解密，并返回解密后的字节数组。
            /// </summary>
            /// <param name="cipherBytes">The byte array containing the encrypted data.<br/>包含加密数据的字节数组。</param>
            /// <param name="keyBase64">The base64 encoded key for decryption.<br/>用于解密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <returns>A byte array containing the decrypted data.<br/>包含解密数据的字节数组。</returns>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null.<br/>当任何一个参数为null时抛出。</exception>
            public static byte[] DecryptBytes(byte[] cipherBytes, string keyBase64, string ivBase64)
            {
                if (cipherBytes == null || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null"); // 参数不能为null

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.PKCS7;

                    using (ICryptoTransform decryptor = aes.CreateDecryptor())
                    using (MemoryStream memoryStream = new MemoryStream(cipherBytes))
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                    using (MemoryStream resultStream = new MemoryStream())
                    {
                        cryptoStream.CopyTo(resultStream); // 将解密后的数据写入结果流
                        return resultStream.ToArray(); // 返回解密后的字节数组
                    }
                }
            }

            /// <summary>
            /// Encrypts the contents of a file using AES encryption and writes the encrypted data to another file.<br/>
            /// 使用AES加密对文件内容进行加密，并将加密后的数据写入另一个文件。
            /// </summary>
            /// <param name="inputFilePath">The path to the input file to be encrypted.<br/>要加密的输入文件路径。</param>
            /// <param name="outputFilePath">The path to the output file where encrypted data will be saved.<br/>加密数据将保存到的输出文件路径。</param>
            /// <param name="keyBase64">The base64 encoded key for encryption.<br/>用于加密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null or empty.<br/>当任何一个参数为null或空时抛出。</exception>
            public static void EncryptFile(string inputFilePath, string outputFilePath, string keyBase64, string ivBase64)
            {
                if (string.IsNullOrEmpty(inputFilePath) || string.IsNullOrEmpty(outputFilePath) || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null or empty"); // 参数不能为null或空

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.PKCS7;

                    using (ICryptoTransform encryptor = aes.CreateEncryptor())
                    using (FileStream inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                    using (FileStream outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    using (CryptoStream cryptoStream = new CryptoStream(outputFileStream, encryptor, CryptoStreamMode.Write))
                    {
                        inputFileStream.CopyTo(cryptoStream); // 将输入文件内容复制到加密流
                        cryptoStream.FlushFinalBlock(); // 完成加密并写入输出文件
                    }
                }
            }

            /// <summary>
            /// Decrypts the contents of a file using AES decryption and writes the decrypted data to another file.<br/>
            /// 使用AES解密对文件内容进行解密，并将解密后的数据写入另一个文件。
            /// </summary>
            /// <param name="inputFilePath">The path to the input file to be decrypted.<br/>要解密的输入文件路径。</param>
            /// <param name="outputFilePath">The path to the output file where decrypted data will be saved.<br/>解密数据将保存到的输出文件路径。</param>
            /// <param name="keyBase64">The base64 encoded key for decryption.<br/>用于解密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null or empty.<br/>当任何一个参数为null或空时抛出。</exception>
            public static void DecryptFile(string inputFilePath, string outputFilePath, string keyBase64, string ivBase64)
            {
                if (string.IsNullOrEmpty(inputFilePath) || string.IsNullOrEmpty(outputFilePath) || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null or empty"); // 参数不能为null或空

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.PKCS7;

                    using (ICryptoTransform decryptor = aes.CreateDecryptor())
                    using (FileStream inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                    using (FileStream outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    using (CryptoStream cryptoStream = new CryptoStream(outputFileStream, decryptor, CryptoStreamMode.Write))
                    {
                        inputFileStream.CopyTo(cryptoStream); // 将输入文件内容复制到解密流
                        cryptoStream.FlushFinalBlock(); // 完成解密并写入输出文件
                    }
                }
            }

            /// <summary>
            /// Encrypts a byte array and writes the encrypted data to a file.<br/>
            /// 对字节数组进行加密，并将加密后的数据写入文件。
            /// </summary>
            /// <param name="plainBytes">The byte array containing data to be encrypted.<br/>要加密的数据字节数组。</param>
            /// <param name="outputFilePath">The path to the output file where encrypted data will be saved.<br/>加密数据将保存到的输出文件路径。</param>
            /// <param name="keyBase64">The base64 encoded key for encryption.<br/>用于加密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null or empty.<br/>当任何一个参数为null或空时抛出。</exception>
            public static void EncryptBytesToFile(byte[] plainBytes, string outputFilePath, string keyBase64, string ivBase64)
            {
                if (plainBytes == null || string.IsNullOrEmpty(outputFilePath) || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null or empty");

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.PKCS7;

                    using (ICryptoTransform encryptor = aes.CreateEncryptor())
                    using (FileStream outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    using (CryptoStream cryptoStream = new CryptoStream(outputFileStream, encryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(plainBytes, 0, plainBytes.Length);
                        cryptoStream.FlushFinalBlock();
                    }
                }
            }

            /// <summary>
            /// Decrypts the contents of a file and returns the decrypted data as a byte array.<br/>
            /// 解密文件内容，并将解密后的数据作为字节数组返回。
            /// </summary>
            /// <param name="inputFilePath">The path to the input file to be decrypted.<br/>要解密的输入文件路径。</param>
            /// <param name="keyBase64">The base64 encoded key for decryption.<br/>用于解密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <returns>A byte array containing the decrypted data.<br/>包含解密数据的字节数组。</returns>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null or empty.<br/>当任何一个参数为null或空时抛出。</exception>
            public static byte[] DecryptFileToBytes(string inputFilePath, string keyBase64, string ivBase64)
            {
                if (string.IsNullOrEmpty(inputFilePath) || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null or empty");

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.PKCS7;

                    using (ICryptoTransform decryptor = aes.CreateDecryptor())
                    using (FileStream inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                    using (CryptoStream cryptoStream = new CryptoStream(inputFileStream, decryptor, CryptoStreamMode.Read))
                    using (MemoryStream resultStream = new MemoryStream())
                    {
                        cryptoStream.CopyTo(resultStream);
                        return resultStream.ToArray();
                    }
                }
            }

            /// <summary>
            /// Encrypts the contents of a file and returns the encrypted data as a byte array.<br/>
            /// 对文件内容进行加密，并将加密后的数据作为字节数组返回。
            /// </summary>
            /// <param name="inputFilePath">The path to the input file to be encrypted.<br/>要加密的输入文件路径。</param>
            /// <param name="keyBase64">The base64 encoded key for encryption.<br/>用于加密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <returns>A byte array containing the encrypted data.<br/>包含加密数据的字节数组。</returns>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null or empty.<br/>当任何一个参数为null或空时抛出。</exception>
            public static byte[] EncryptFileToBytes(string inputFilePath, string keyBase64, string ivBase64)
            {
                if (string.IsNullOrEmpty(inputFilePath) || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null or empty");

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.PKCS7;

                    using (ICryptoTransform encryptor = aes.CreateEncryptor())
                    using (FileStream inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                    using (MemoryStream outputStream = new MemoryStream())
                    using (CryptoStream cryptoStream = new CryptoStream(outputStream, encryptor, CryptoStreamMode.Write))
                    {
                        inputFileStream.CopyTo(cryptoStream);
                        cryptoStream.FlushFinalBlock();
                        return outputStream.ToArray();
                    }
                }
            }

            /// <summary>
            /// Decrypts a byte array and writes the decrypted data to a file.<br/>
            /// 对字节数组进行解密，并将解密后的数据写入文件。
            /// </summary>
            /// <param name="encryptedBytes">The byte array containing data to be decrypted.<br/>要解密的字节数组。</param>
            /// <param name="outputFilePath">The path to the output file where decrypted data will be saved.<br/>解密数据将保存到的输出文件路径。</param>
            /// <param name="keyBase64">The base64 encoded key for decryption.<br/>用于解密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null or empty.<br/>当任何一个参数为null或空时抛出。</exception>
            public static void DecryptBytesToFile(byte[] encryptedBytes, string outputFilePath, string keyBase64, string ivBase64)
            {
                if (encryptedBytes == null || string.IsNullOrEmpty(outputFilePath) || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null or empty");

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.PKCS7;

                    using (ICryptoTransform decryptor = aes.CreateDecryptor())
                    using (MemoryStream inputStream = new MemoryStream(encryptedBytes))
                    using (FileStream outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    using (CryptoStream cryptoStream = new CryptoStream(outputFileStream, decryptor, CryptoStreamMode.Write))
                    {
                        inputStream.CopyTo(cryptoStream);
                        cryptoStream.FlushFinalBlock();
                    }
                }
            }
        }

        /// <summary>
        /// None padding mode.
        /// None 填充模式。
        /// </summary>
        public class None
        {
            /// <summary>
            /// Encrypts a plain text string using AES encryption with the specified key and IV.<br/>
            /// 使用指定的密钥和IV对明文字符串进行AES加密。
            /// </summary>
            /// <param name="plainText">The plain text string to be encrypted.<br/>要加密的明文字符串。</param>
            /// <param name="keyBase64">The base64 encoded key for encryption.<br/>用于加密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <returns>The base64 encoded encrypted string.<br/>Base64编码的加密字符串。</returns>
            public static string EncryptString(string plainText, string keyBase64, string ivBase64)
            {
                if (plainText == null || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null"); // 参数不能为null

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.None;

                    using (ICryptoTransform encryptor = aes.CreateEncryptor())
                    using (MemoryStream memoryStream = new MemoryStream())
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                        cryptoStream.Write(plainBytes, 0, plainBytes.Length);
                        cryptoStream.FlushFinalBlock();
                        byte[] cipherBytes = memoryStream.ToArray();
                        return Convert.ToBase64String(cipherBytes);
                    }
                }
            }

            /// <summary>
            /// Decrypts an encrypted base64 string using AES decryption with the specified key and IV.<br/>
            /// 使用指定的密钥和IV对Base64编码的加密字符串进行AES解密。
            /// </summary>
            /// <param name="cipherTextBase64">The base64 encoded encrypted string to be decrypted.<br/>要解密的Base64编码的加密字符串。</param>
            /// <param name="keyBase64">The base64 encoded key for decryption.<br/>用于解密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <returns>The decrypted plain text string.<br/>解密后的明文字符串。</returns>
            public static string DecryptString(string cipherTextBase64, string keyBase64, string ivBase64)
            {
                if (cipherTextBase64 == null || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null"); // 参数不能为null

                byte[] cipherBytes = Convert.FromBase64String(cipherTextBase64);
                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.None;

                    using (ICryptoTransform decryptor = aes.CreateDecryptor())
                    using (MemoryStream memoryStream = new MemoryStream(cipherBytes))
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                    using (StreamReader reader = new StreamReader(cryptoStream))
                    {
                        return reader.ReadToEnd();
                    }
                }
            }

            /// <summary>
            /// Encrypts a plain text string and returns the encrypted data as a byte array.<br/>
            /// 对明文字符串进行加密，并将加密后的数据作为字节数组返回。
            /// </summary>
            /// <param name="plainText">The plain text string to be encrypted.<br/>要加密的明文字符串。</param>
            /// <param name="keyBase64">The base64 encoded key for encryption.<br/>用于加密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <returns>A byte array containing the encrypted data.<br/>包含加密数据的字节数组。</returns>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null.<br/>当任何一个参数为null时抛出。</exception>
            public static byte[] EncryptStringToBytes(string plainText, string keyBase64, string ivBase64)
            {
                if (plainText == null || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null"); // 参数不能为null

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.None;

                    using (ICryptoTransform encryptor = aes.CreateEncryptor())
                    using (MemoryStream memoryStream = new MemoryStream())
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                        cryptoStream.Write(plainBytes, 0, plainBytes.Length);
                        cryptoStream.FlushFinalBlock();
                        return memoryStream.ToArray();
                    }
                }
            }

            /// <summary>
            /// Decrypts a byte array containing encrypted data and returns the plain text string.<br/>
            /// 解密包含加密数据的字节数组，并返回明文字符串。
            /// </summary>
            /// <param name="cipherBytes">The byte array containing the encrypted data.<br/>包含加密数据的字节数组。</param>
            /// <param name="keyBase64">The base64 encoded key for decryption.<br/>用于解密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <returns>The decrypted plain text string.<br/>解密后的明文字符串。</returns>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null.<br/>当任何一个参数为null时抛出。</exception>
            public static string DecryptBytesToString(byte[] cipherBytes, string keyBase64, string ivBase64)
            {
                if (cipherBytes == null || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null"); // 参数不能为null

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.None;

                    using (ICryptoTransform decryptor = aes.CreateDecryptor())
                    using (MemoryStream memoryStream = new MemoryStream(cipherBytes))
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                    using (StreamReader reader = new StreamReader(cryptoStream))
                    {
                        return reader.ReadToEnd();
                    }
                }
            }

            /// <summary>
            /// Encrypts a byte array and returns the encrypted data as a base64 encoded string.<br/>
            /// 对字节数组进行加密，并将加密后的数据以Base64编码的字符串形式返回。
            /// </summary>
            /// <param name="plainBytes">The byte array to be encrypted.<br/>要加密的字节数组。</param>
            /// <param name="keyBase64">The base64 encoded key for encryption.<br/>用于加密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <returns>A base64 encoded string containing the encrypted data.<br/>包含加密数据的Base64编码字符串。</returns>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null.<br/>当任何一个参数为null时抛出。</exception>
            public static string EncryptBytesToString(byte[] plainBytes, string keyBase64, string ivBase64)
            {
                if (plainBytes == null || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null"); // 参数不能为null

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.None;

                    using (ICryptoTransform encryptor = aes.CreateEncryptor())
                    using (MemoryStream memoryStream = new MemoryStream())
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(plainBytes, 0, plainBytes.Length);
                        cryptoStream.FlushFinalBlock();
                        byte[] cipherBytes = memoryStream.ToArray();
                        return Convert.ToBase64String(cipherBytes); // 返回Base64编码的加密数据
                    }
                }
            }

            /// <summary>
            /// Decrypts a base64 encoded string containing encrypted data and returns the decrypted byte array.<br/>
            /// 解密包含加密数据的Base64编码字符串，并将解密后的字节数组返回。
            /// </summary>
            /// <param name="cipherTextBase64">The base64 encoded string containing the encrypted data.<br/>包含加密数据的Base64编码字符串。</param>
            /// <param name="keyBase64">The base64 encoded key for decryption.<br/>用于解密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <returns>A byte array containing the decrypted data.<br/>包含解密数据的字节数组。</returns>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null.<br/>当任何一个参数为null时抛出。</exception>
            public static byte[] DecryptStringToBytes(string cipherTextBase64, string keyBase64, string ivBase64)
            {
                if (cipherTextBase64 == null || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null"); // 参数不能为null

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);
                byte[] cipherBytes = Convert.FromBase64String(cipherTextBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.None;

                    using (ICryptoTransform decryptor = aes.CreateDecryptor())
                    using (MemoryStream memoryStream = new MemoryStream(cipherBytes))
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                    using (MemoryStream resultStream = new MemoryStream())
                    {
                        cryptoStream.CopyTo(resultStream); // 将解密后的数据写入结果流
                        return resultStream.ToArray(); // 返回解密后的字节数组
                    }
                }
            }

            /// <summary>
            /// Encrypts a byte array using AES encryption and returns the encrypted byte array.<br/>
            /// 使用AES加密对字节数组进行加密，并返回加密后的字节数组。
            /// </summary>
            /// <param name="plainBytes">The byte array to be encrypted.<br/>要加密的字节数组。</param>
            /// <param name="keyBase64">The base64 encoded key for encryption.<br/>用于加密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <returns>A byte array containing the encrypted data.<br/>包含加密数据的字节数组。</returns>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null.<br/>当任何一个参数为null时抛出。</exception>
            public static byte[] EncryptBytes(byte[] plainBytes, string keyBase64, string ivBase64)
            {
                if (plainBytes == null || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null"); // 参数不能为null

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.None;

                    using (ICryptoTransform encryptor = aes.CreateEncryptor())
                    using (MemoryStream memoryStream = new MemoryStream())
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(plainBytes, 0, plainBytes.Length);
                        cryptoStream.FlushFinalBlock();
                        return memoryStream.ToArray(); // 返回加密后的字节数组
                    }
                }
            }

            /// <summary>
            /// Decrypts an encrypted byte array using AES decryption and returns the decrypted byte array.<br/>
            /// 使用AES解密对加密的字节数组进行解密，并返回解密后的字节数组。
            /// </summary>
            /// <param name="cipherBytes">The byte array containing the encrypted data.<br/>包含加密数据的字节数组。</param>
            /// <param name="keyBase64">The base64 encoded key for decryption.<br/>用于解密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <returns>A byte array containing the decrypted data.<br/>包含解密数据的字节数组。</returns>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null.<br/>当任何一个参数为null时抛出。</exception>
            public static byte[] DecryptBytes(byte[] cipherBytes, string keyBase64, string ivBase64)
            {
                if (cipherBytes == null || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null"); // 参数不能为null

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.None;

                    using (ICryptoTransform decryptor = aes.CreateDecryptor())
                    using (MemoryStream memoryStream = new MemoryStream(cipherBytes))
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                    using (MemoryStream resultStream = new MemoryStream())
                    {
                        cryptoStream.CopyTo(resultStream); // 将解密后的数据写入结果流
                        return resultStream.ToArray(); // 返回解密后的字节数组
                    }
                }
            }

            /// <summary>
            /// Encrypts the contents of a file using AES encryption and writes the encrypted data to another file.<br/>
            /// 使用AES加密对文件内容进行加密，并将加密后的数据写入另一个文件。
            /// </summary>
            /// <param name="inputFilePath">The path to the input file to be encrypted.<br/>要加密的输入文件路径。</param>
            /// <param name="outputFilePath">The path to the output file where encrypted data will be saved.<br/>加密数据将保存到的输出文件路径。</param>
            /// <param name="keyBase64">The base64 encoded key for encryption.<br/>用于加密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null or empty.<br/>当任何一个参数为null或空时抛出。</exception>
            public static void EncryptFile(string inputFilePath, string outputFilePath, string keyBase64, string ivBase64)
            {
                if (string.IsNullOrEmpty(inputFilePath) || string.IsNullOrEmpty(outputFilePath) || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null or empty"); // 参数不能为null或空

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.None;

                    using (ICryptoTransform encryptor = aes.CreateEncryptor())
                    using (FileStream inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                    using (FileStream outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    using (CryptoStream cryptoStream = new CryptoStream(outputFileStream, encryptor, CryptoStreamMode.Write))
                    {
                        inputFileStream.CopyTo(cryptoStream); // 将输入文件内容复制到加密流
                        cryptoStream.FlushFinalBlock(); // 完成加密并写入输出文件
                    }
                }
            }

            /// <summary>
            /// Decrypts the contents of a file using AES decryption and writes the decrypted data to another file.<br/>
            /// 使用AES解密对文件内容进行解密，并将解密后的数据写入另一个文件。
            /// </summary>
            /// <param name="inputFilePath">The path to the input file to be decrypted.<br/>要解密的输入文件路径。</param>
            /// <param name="outputFilePath">The path to the output file where decrypted data will be saved.<br/>解密数据将保存到的输出文件路径。</param>
            /// <param name="keyBase64">The base64 encoded key for decryption.<br/>用于解密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null or empty.<br/>当任何一个参数为null或空时抛出。</exception>
            public static void DecryptFile(string inputFilePath, string outputFilePath, string keyBase64, string ivBase64)
            {
                if (string.IsNullOrEmpty(inputFilePath) || string.IsNullOrEmpty(outputFilePath) || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null or empty"); // 参数不能为null或空

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.None;

                    using (ICryptoTransform decryptor = aes.CreateDecryptor())
                    using (FileStream inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                    using (FileStream outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    using (CryptoStream cryptoStream = new CryptoStream(outputFileStream, decryptor, CryptoStreamMode.Write))
                    {
                        inputFileStream.CopyTo(cryptoStream); // 将输入文件内容复制到解密流
                        cryptoStream.FlushFinalBlock(); // 完成解密并写入输出文件
                    }
                }
            }

            /// <summary>
            /// Encrypts a byte array and writes the encrypted data to a file.<br/>
            /// 对字节数组进行加密，并将加密后的数据写入文件。
            /// </summary>
            /// <param name="plainBytes">The byte array containing data to be encrypted.<br/>要加密的数据字节数组。</param>
            /// <param name="outputFilePath">The path to the output file where encrypted data will be saved.<br/>加密数据将保存到的输出文件路径。</param>
            /// <param name="keyBase64">The base64 encoded key for encryption.<br/>用于加密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null or empty.<br/>当任何一个参数为null或空时抛出。</exception>
            public static void EncryptBytesToFile(byte[] plainBytes, string outputFilePath, string keyBase64, string ivBase64)
            {
                if (plainBytes == null || string.IsNullOrEmpty(outputFilePath) || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null or empty");

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.None;

                    using (ICryptoTransform encryptor = aes.CreateEncryptor())
                    using (FileStream outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    using (CryptoStream cryptoStream = new CryptoStream(outputFileStream, encryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(plainBytes, 0, plainBytes.Length);
                        cryptoStream.FlushFinalBlock();
                    }
                }
            }

            /// <summary>
            /// Decrypts the contents of a file and returns the decrypted data as a byte array.<br/>
            /// 解密文件内容，并将解密后的数据作为字节数组返回。
            /// </summary>
            /// <param name="inputFilePath">The path to the input file to be decrypted.<br/>要解密的输入文件路径。</param>
            /// <param name="keyBase64">The base64 encoded key for decryption.<br/>用于解密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <returns>A byte array containing the decrypted data.<br/>包含解密数据的字节数组。</returns>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null or empty.<br/>当任何一个参数为null或空时抛出。</exception>
            public static byte[] DecryptFileToBytes(string inputFilePath, string keyBase64, string ivBase64)
            {
                if (string.IsNullOrEmpty(inputFilePath) || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null or empty");

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.None;

                    using (ICryptoTransform decryptor = aes.CreateDecryptor())
                    using (FileStream inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                    using (CryptoStream cryptoStream = new CryptoStream(inputFileStream, decryptor, CryptoStreamMode.Read))
                    using (MemoryStream resultStream = new MemoryStream())
                    {
                        cryptoStream.CopyTo(resultStream);
                        return resultStream.ToArray();
                    }
                }
            }

            /// <summary>
            /// Encrypts the contents of a file and returns the encrypted data as a byte array.<br/>
            /// 对文件内容进行加密，并将加密后的数据作为字节数组返回。
            /// </summary>
            /// <param name="inputFilePath">The path to the input file to be encrypted.<br/>要加密的输入文件路径。</param>
            /// <param name="keyBase64">The base64 encoded key for encryption.<br/>用于加密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <returns>A byte array containing the encrypted data.<br/>包含加密数据的字节数组。</returns>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null or empty.<br/>当任何一个参数为null或空时抛出。</exception>
            public static byte[] EncryptFileToBytes(string inputFilePath, string keyBase64, string ivBase64)
            {
                if (string.IsNullOrEmpty(inputFilePath) || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null or empty");

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.None;

                    using (ICryptoTransform encryptor = aes.CreateEncryptor())
                    using (FileStream inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                    using (MemoryStream outputStream = new MemoryStream())
                    using (CryptoStream cryptoStream = new CryptoStream(outputStream, encryptor, CryptoStreamMode.Write))
                    {
                        inputFileStream.CopyTo(cryptoStream);
                        cryptoStream.FlushFinalBlock();
                        return outputStream.ToArray();
                    }
                }
            }

            /// <summary>
            /// Decrypts a byte array and writes the decrypted data to a file.<br/>
            /// 对字节数组进行解密，并将解密后的数据写入文件。
            /// </summary>
            /// <param name="encryptedBytes">The byte array containing data to be decrypted.<br/>要解密的字节数组。</param>
            /// <param name="outputFilePath">The path to the output file where decrypted data will be saved.<br/>解密数据将保存到的输出文件路径。</param>
            /// <param name="keyBase64">The base64 encoded key for decryption.<br/>用于解密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null or empty.<br/>当任何一个参数为null或空时抛出。</exception>
            public static void DecryptBytesToFile(byte[] encryptedBytes, string outputFilePath, string keyBase64, string ivBase64)
            {
                if (encryptedBytes == null || string.IsNullOrEmpty(outputFilePath) || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null or empty");

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.None;

                    using (ICryptoTransform decryptor = aes.CreateDecryptor())
                    using (MemoryStream inputStream = new MemoryStream(encryptedBytes))
                    using (FileStream outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    using (CryptoStream cryptoStream = new CryptoStream(outputFileStream, decryptor, CryptoStreamMode.Write))
                    {
                        inputStream.CopyTo(cryptoStream);
                        cryptoStream.FlushFinalBlock();
                    }
                }
            }
        }

        /// <summary>
        /// Zeros padding mode.
        /// Zeros 填充模式。
        /// </summary>
        public class Zeros
        {
            /// <summary>
            /// Encrypts a plain text string using AES encryption with the specified key and IV.<br/>
            /// 使用指定的密钥和IV对明文字符串进行AES加密。
            /// </summary>
            /// <param name="plainText">The plain text string to be encrypted.<br/>要加密的明文字符串。</param>
            /// <param name="keyBase64">The base64 encoded key for encryption.<br/>用于加密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <returns>The base64 encoded encrypted string.<br/>Base64编码的加密字符串。</returns>
            public static string EncryptString(string plainText, string keyBase64, string ivBase64)
            {
                if (plainText == null || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null"); // 参数不能为null

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.Zeros;

                    using (ICryptoTransform encryptor = aes.CreateEncryptor())
                    using (MemoryStream memoryStream = new MemoryStream())
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                        cryptoStream.Write(plainBytes, 0, plainBytes.Length);
                        cryptoStream.FlushFinalBlock();
                        byte[] cipherBytes = memoryStream.ToArray();
                        return Convert.ToBase64String(cipherBytes);
                    }
                }
            }

            /// <summary>
            /// Decrypts an encrypted base64 string using AES decryption with the specified key and IV.<br/>
            /// 使用指定的密钥和IV对Base64编码的加密字符串进行AES解密。
            /// </summary>
            /// <param name="cipherTextBase64">The base64 encoded encrypted string to be decrypted.<br/>要解密的Base64编码的加密字符串。</param>
            /// <param name="keyBase64">The base64 encoded key for decryption.<br/>用于解密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <returns>The decrypted plain text string.<br/>解密后的明文字符串。</returns>
            public static string DecryptString(string cipherTextBase64, string keyBase64, string ivBase64)
            {
                if (cipherTextBase64 == null || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null"); // 参数不能为null

                byte[] cipherBytes = Convert.FromBase64String(cipherTextBase64);
                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.Zeros;

                    using (ICryptoTransform decryptor = aes.CreateDecryptor())
                    using (MemoryStream memoryStream = new MemoryStream(cipherBytes))
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                    using (StreamReader reader = new StreamReader(cryptoStream))
                    {
                        return reader.ReadToEnd();
                    }
                }
            }

            /// <summary>
            /// Encrypts a plain text string and returns the encrypted data as a byte array.<br/>
            /// 对明文字符串进行加密，并将加密后的数据作为字节数组返回。
            /// </summary>
            /// <param name="plainText">The plain text string to be encrypted.<br/>要加密的明文字符串。</param>
            /// <param name="keyBase64">The base64 encoded key for encryption.<br/>用于加密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <returns>A byte array containing the encrypted data.<br/>包含加密数据的字节数组。</returns>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null.<br/>当任何一个参数为null时抛出。</exception>
            public static byte[] EncryptStringToBytes(string plainText, string keyBase64, string ivBase64)
            {
                if (plainText == null || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null"); // 参数不能为null

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.Zeros;

                    using (ICryptoTransform encryptor = aes.CreateEncryptor())
                    using (MemoryStream memoryStream = new MemoryStream())
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                        cryptoStream.Write(plainBytes, 0, plainBytes.Length);
                        cryptoStream.FlushFinalBlock();
                        return memoryStream.ToArray();
                    }
                }
            }

            /// <summary>
            /// Decrypts a byte array containing encrypted data and returns the plain text string.<br/>
            /// 解密包含加密数据的字节数组，并返回明文字符串。
            /// </summary>
            /// <param name="cipherBytes">The byte array containing the encrypted data.<br/>包含加密数据的字节数组。</param>
            /// <param name="keyBase64">The base64 encoded key for decryption.<br/>用于解密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <returns>The decrypted plain text string.<br/>解密后的明文字符串。</returns>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null.<br/>当任何一个参数为null时抛出。</exception>
            public static string DecryptBytesToString(byte[] cipherBytes, string keyBase64, string ivBase64)
            {
                if (cipherBytes == null || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null"); // 参数不能为null

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.Zeros;

                    using (ICryptoTransform decryptor = aes.CreateDecryptor())
                    using (MemoryStream memoryStream = new MemoryStream(cipherBytes))
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                    using (StreamReader reader = new StreamReader(cryptoStream))
                    {
                        return reader.ReadToEnd();
                    }
                }
            }

            /// <summary>
            /// Encrypts a byte array and returns the encrypted data as a base64 encoded string.<br/>
            /// 对字节数组进行加密，并将加密后的数据以Base64编码的字符串形式返回。
            /// </summary>
            /// <param name="plainBytes">The byte array to be encrypted.<br/>要加密的字节数组。</param>
            /// <param name="keyBase64">The base64 encoded key for encryption.<br/>用于加密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <returns>A base64 encoded string containing the encrypted data.<br/>包含加密数据的Base64编码字符串。</returns>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null.<br/>当任何一个参数为null时抛出。</exception>
            public static string EncryptBytesToString(byte[] plainBytes, string keyBase64, string ivBase64)
            {
                if (plainBytes == null || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null"); // 参数不能为null

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.Zeros;

                    using (ICryptoTransform encryptor = aes.CreateEncryptor())
                    using (MemoryStream memoryStream = new MemoryStream())
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(plainBytes, 0, plainBytes.Length);
                        cryptoStream.FlushFinalBlock();
                        byte[] cipherBytes = memoryStream.ToArray();
                        return Convert.ToBase64String(cipherBytes); // 返回Base64编码的加密数据
                    }
                }
            }

            /// <summary>
            /// Decrypts a base64 encoded string containing encrypted data and returns the decrypted byte array.<br/>
            /// 解密包含加密数据的Base64编码字符串，并将解密后的字节数组返回。
            /// </summary>
            /// <param name="cipherTextBase64">The base64 encoded string containing the encrypted data.<br/>包含加密数据的Base64编码字符串。</param>
            /// <param name="keyBase64">The base64 encoded key for decryption.<br/>用于解密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <returns>A byte array containing the decrypted data.<br/>包含解密数据的字节数组。</returns>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null.<br/>当任何一个参数为null时抛出。</exception>
            public static byte[] DecryptStringToBytes(string cipherTextBase64, string keyBase64, string ivBase64)
            {
                if (cipherTextBase64 == null || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null"); // 参数不能为null

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);
                byte[] cipherBytes = Convert.FromBase64String(cipherTextBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.Zeros;

                    using (ICryptoTransform decryptor = aes.CreateDecryptor())
                    using (MemoryStream memoryStream = new MemoryStream(cipherBytes))
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                    using (MemoryStream resultStream = new MemoryStream())
                    {
                        cryptoStream.CopyTo(resultStream); // 将解密后的数据写入结果流
                        return resultStream.ToArray(); // 返回解密后的字节数组
                    }
                }
            }

            /// <summary>
            /// Encrypts a byte array using AES encryption and returns the encrypted byte array.<br/>
            /// 使用AES加密对字节数组进行加密，并返回加密后的字节数组。
            /// </summary>
            /// <param name="plainBytes">The byte array to be encrypted.<br/>要加密的字节数组。</param>
            /// <param name="keyBase64">The base64 encoded key for encryption.<br/>用于加密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <returns>A byte array containing the encrypted data.<br/>包含加密数据的字节数组。</returns>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null.<br/>当任何一个参数为null时抛出。</exception>
            public static byte[] EncryptBytes(byte[] plainBytes, string keyBase64, string ivBase64)
            {
                if (plainBytes == null || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null"); // 参数不能为null

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.Zeros;

                    using (ICryptoTransform encryptor = aes.CreateEncryptor())
                    using (MemoryStream memoryStream = new MemoryStream())
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(plainBytes, 0, plainBytes.Length);
                        cryptoStream.FlushFinalBlock();
                        return memoryStream.ToArray(); // 返回加密后的字节数组
                    }
                }
            }

            /// <summary>
            /// Decrypts an encrypted byte array using AES decryption and returns the decrypted byte array.<br/>
            /// 使用AES解密对加密的字节数组进行解密，并返回解密后的字节数组。
            /// </summary>
            /// <param name="cipherBytes">The byte array containing the encrypted data.<br/>包含加密数据的字节数组。</param>
            /// <param name="keyBase64">The base64 encoded key for decryption.<br/>用于解密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <returns>A byte array containing the decrypted data.<br/>包含解密数据的字节数组。</returns>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null.<br/>当任何一个参数为null时抛出。</exception>
            public static byte[] DecryptBytes(byte[] cipherBytes, string keyBase64, string ivBase64)
            {
                if (cipherBytes == null || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null"); // 参数不能为null

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.Zeros;

                    using (ICryptoTransform decryptor = aes.CreateDecryptor())
                    using (MemoryStream memoryStream = new MemoryStream(cipherBytes))
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                    using (MemoryStream resultStream = new MemoryStream())
                    {
                        cryptoStream.CopyTo(resultStream); // 将解密后的数据写入结果流
                        return resultStream.ToArray(); // 返回解密后的字节数组
                    }
                }
            }

            /// <summary>
            /// Encrypts the contents of a file using AES encryption and writes the encrypted data to another file.<br/>
            /// 使用AES加密对文件内容进行加密，并将加密后的数据写入另一个文件。
            /// </summary>
            /// <param name="inputFilePath">The path to the input file to be encrypted.<br/>要加密的输入文件路径。</param>
            /// <param name="outputFilePath">The path to the output file where encrypted data will be saved.<br/>加密数据将保存到的输出文件路径。</param>
            /// <param name="keyBase64">The base64 encoded key for encryption.<br/>用于加密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null or empty.<br/>当任何一个参数为null或空时抛出。</exception>
            public static void EncryptFile(string inputFilePath, string outputFilePath, string keyBase64, string ivBase64)
            {
                if (string.IsNullOrEmpty(inputFilePath) || string.IsNullOrEmpty(outputFilePath) || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null or empty"); // 参数不能为null或空

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.Zeros;

                    using (ICryptoTransform encryptor = aes.CreateEncryptor())
                    using (FileStream inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                    using (FileStream outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    using (CryptoStream cryptoStream = new CryptoStream(outputFileStream, encryptor, CryptoStreamMode.Write))
                    {
                        inputFileStream.CopyTo(cryptoStream); // 将输入文件内容复制到加密流
                        cryptoStream.FlushFinalBlock(); // 完成加密并写入输出文件
                    }
                }
            }

            /// <summary>
            /// Decrypts the contents of a file using AES decryption and writes the decrypted data to another file.<br/>
            /// 使用AES解密对文件内容进行解密，并将解密后的数据写入另一个文件。
            /// </summary>
            /// <param name="inputFilePath">The path to the input file to be decrypted.<br/>要解密的输入文件路径。</param>
            /// <param name="outputFilePath">The path to the output file where decrypted data will be saved.<br/>解密数据将保存到的输出文件路径。</param>
            /// <param name="keyBase64">The base64 encoded key for decryption.<br/>用于解密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null or empty.<br/>当任何一个参数为null或空时抛出。</exception>
            public static void DecryptFile(string inputFilePath, string outputFilePath, string keyBase64, string ivBase64)
            {
                if (string.IsNullOrEmpty(inputFilePath) || string.IsNullOrEmpty(outputFilePath) || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null or empty"); // 参数不能为null或空

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.Zeros;

                    using (ICryptoTransform decryptor = aes.CreateDecryptor())
                    using (FileStream inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                    using (FileStream outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    using (CryptoStream cryptoStream = new CryptoStream(outputFileStream, decryptor, CryptoStreamMode.Write))
                    {
                        inputFileStream.CopyTo(cryptoStream); // 将输入文件内容复制到解密流
                        cryptoStream.FlushFinalBlock(); // 完成解密并写入输出文件
                    }
                }
            }

            /// <summary>
            /// Encrypts a byte array and writes the encrypted data to a file.<br/>
            /// 对字节数组进行加密，并将加密后的数据写入文件。
            /// </summary>
            /// <param name="plainBytes">The byte array containing data to be encrypted.<br/>要加密的数据字节数组。</param>
            /// <param name="outputFilePath">The path to the output file where encrypted data will be saved.<br/>加密数据将保存到的输出文件路径。</param>
            /// <param name="keyBase64">The base64 encoded key for encryption.<br/>用于加密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null or empty.<br/>当任何一个参数为null或空时抛出。</exception>
            public static void EncryptBytesToFile(byte[] plainBytes, string outputFilePath, string keyBase64, string ivBase64)
            {
                if (plainBytes == null || string.IsNullOrEmpty(outputFilePath) || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null or empty");

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.Zeros;

                    using (ICryptoTransform encryptor = aes.CreateEncryptor())
                    using (FileStream outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    using (CryptoStream cryptoStream = new CryptoStream(outputFileStream, encryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(plainBytes, 0, plainBytes.Length);
                        cryptoStream.FlushFinalBlock();
                    }
                }
            }

            /// <summary>
            /// Decrypts the contents of a file and returns the decrypted data as a byte array.<br/>
            /// 解密文件内容，并将解密后的数据作为字节数组返回。
            /// </summary>
            /// <param name="inputFilePath">The path to the input file to be decrypted.<br/>要解密的输入文件路径。</param>
            /// <param name="keyBase64">The base64 encoded key for decryption.<br/>用于解密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <returns>A byte array containing the decrypted data.<br/>包含解密数据的字节数组。</returns>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null or empty.<br/>当任何一个参数为null或空时抛出。</exception>
            public static byte[] DecryptFileToBytes(string inputFilePath, string keyBase64, string ivBase64)
            {
                if (string.IsNullOrEmpty(inputFilePath) || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null or empty");

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.Zeros;

                    using (ICryptoTransform decryptor = aes.CreateDecryptor())
                    using (FileStream inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                    using (CryptoStream cryptoStream = new CryptoStream(inputFileStream, decryptor, CryptoStreamMode.Read))
                    using (MemoryStream resultStream = new MemoryStream())
                    {
                        cryptoStream.CopyTo(resultStream);
                        return resultStream.ToArray();
                    }
                }
            }

            /// <summary>
            /// Encrypts the contents of a file and returns the encrypted data as a byte array.<br/>
            /// 对文件内容进行加密，并将加密后的数据作为字节数组返回。
            /// </summary>
            /// <param name="inputFilePath">The path to the input file to be encrypted.<br/>要加密的输入文件路径。</param>
            /// <param name="keyBase64">The base64 encoded key for encryption.<br/>用于加密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <returns>A byte array containing the encrypted data.<br/>包含加密数据的字节数组。</returns>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null or empty.<br/>当任何一个参数为null或空时抛出。</exception>
            public static byte[] EncryptFileToBytes(string inputFilePath, string keyBase64, string ivBase64)
            {
                if (string.IsNullOrEmpty(inputFilePath) || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null or empty");

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.Zeros;

                    using (ICryptoTransform encryptor = aes.CreateEncryptor())
                    using (FileStream inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                    using (MemoryStream outputStream = new MemoryStream())
                    using (CryptoStream cryptoStream = new CryptoStream(outputStream, encryptor, CryptoStreamMode.Write))
                    {
                        inputFileStream.CopyTo(cryptoStream);
                        cryptoStream.FlushFinalBlock();
                        return outputStream.ToArray();
                    }
                }
            }

            /// <summary>
            /// Decrypts a byte array and writes the decrypted data to a file.<br/>
            /// 对字节数组进行解密，并将解密后的数据写入文件。
            /// </summary>
            /// <param name="encryptedBytes">The byte array containing data to be decrypted.<br/>要解密的字节数组。</param>
            /// <param name="outputFilePath">The path to the output file where decrypted data will be saved.<br/>解密数据将保存到的输出文件路径。</param>
            /// <param name="keyBase64">The base64 encoded key for decryption.<br/>用于解密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null or empty.<br/>当任何一个参数为null或空时抛出。</exception>
            public static void DecryptBytesToFile(byte[] encryptedBytes, string outputFilePath, string keyBase64, string ivBase64)
            {
                if (encryptedBytes == null || string.IsNullOrEmpty(outputFilePath) || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null or empty");

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.Zeros;

                    using (ICryptoTransform decryptor = aes.CreateDecryptor())
                    using (MemoryStream inputStream = new MemoryStream(encryptedBytes))
                    using (FileStream outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    using (CryptoStream cryptoStream = new CryptoStream(outputFileStream, decryptor, CryptoStreamMode.Write))
                    {
                        inputStream.CopyTo(cryptoStream);
                        cryptoStream.FlushFinalBlock();
                    }
                }
            }
        }

        /// <summary>
        /// ISO10126 padding mode.
        /// ISO10126 填充模式。
        /// </summary>
        public class ISO10126
        {
            /// <summary>
            /// Encrypts a plain text string using AES encryption with the specified key and IV.<br/>
            /// 使用指定的密钥和IV对明文字符串进行AES加密。
            /// </summary>
            /// <param name="plainText">The plain text string to be encrypted.<br/>要加密的明文字符串。</param>
            /// <param name="keyBase64">The base64 encoded key for encryption.<br/>用于加密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <returns>The base64 encoded encrypted string.<br/>Base64编码的加密字符串。</returns>
            public static string EncryptString(string plainText, string keyBase64, string ivBase64)
            {
                if (plainText == null || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null"); // 参数不能为null

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.ISO10126;

                    using (ICryptoTransform encryptor = aes.CreateEncryptor())
                    using (MemoryStream memoryStream = new MemoryStream())
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                        cryptoStream.Write(plainBytes, 0, plainBytes.Length);
                        cryptoStream.FlushFinalBlock();
                        byte[] cipherBytes = memoryStream.ToArray();
                        return Convert.ToBase64String(cipherBytes);
                    }
                }
            }

            /// <summary>
            /// Decrypts an encrypted base64 string using AES decryption with the specified key and IV.<br/>
            /// 使用指定的密钥和IV对Base64编码的加密字符串进行AES解密。
            /// </summary>
            /// <param name="cipherTextBase64">The base64 encoded encrypted string to be decrypted.<br/>要解密的Base64编码的加密字符串。</param>
            /// <param name="keyBase64">The base64 encoded key for decryption.<br/>用于解密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <returns>The decrypted plain text string.<br/>解密后的明文字符串。</returns>
            public static string DecryptString(string cipherTextBase64, string keyBase64, string ivBase64)
            {
                if (cipherTextBase64 == null || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null"); // 参数不能为null

                byte[] cipherBytes = Convert.FromBase64String(cipherTextBase64);
                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.ISO10126;

                    using (ICryptoTransform decryptor = aes.CreateDecryptor())
                    using (MemoryStream memoryStream = new MemoryStream(cipherBytes))
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                    using (StreamReader reader = new StreamReader(cryptoStream))
                    {
                        return reader.ReadToEnd();
                    }
                }
            }

            /// <summary>
            /// Encrypts a plain text string and returns the encrypted data as a byte array.<br/>
            /// 对明文字符串进行加密，并将加密后的数据作为字节数组返回。
            /// </summary>
            /// <param name="plainText">The plain text string to be encrypted.<br/>要加密的明文字符串。</param>
            /// <param name="keyBase64">The base64 encoded key for encryption.<br/>用于加密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <returns>A byte array containing the encrypted data.<br/>包含加密数据的字节数组。</returns>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null.<br/>当任何一个参数为null时抛出。</exception>
            public static byte[] EncryptStringToBytes(string plainText, string keyBase64, string ivBase64)
            {
                if (plainText == null || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null"); // 参数不能为null

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.ISO10126;

                    using (ICryptoTransform encryptor = aes.CreateEncryptor())
                    using (MemoryStream memoryStream = new MemoryStream())
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                        cryptoStream.Write(plainBytes, 0, plainBytes.Length);
                        cryptoStream.FlushFinalBlock();
                        return memoryStream.ToArray();
                    }
                }
            }

            /// <summary>
            /// Decrypts a byte array containing encrypted data and returns the plain text string.<br/>
            /// 解密包含加密数据的字节数组，并返回明文字符串。
            /// </summary>
            /// <param name="cipherBytes">The byte array containing the encrypted data.<br/>包含加密数据的字节数组。</param>
            /// <param name="keyBase64">The base64 encoded key for decryption.<br/>用于解密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <returns>The decrypted plain text string.<br/>解密后的明文字符串。</returns>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null.<br/>当任何一个参数为null时抛出。</exception>
            public static string DecryptBytesToString(byte[] cipherBytes, string keyBase64, string ivBase64)
            {
                if (cipherBytes == null || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null"); // 参数不能为null

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.ISO10126;

                    using (ICryptoTransform decryptor = aes.CreateDecryptor())
                    using (MemoryStream memoryStream = new MemoryStream(cipherBytes))
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                    using (StreamReader reader = new StreamReader(cryptoStream))
                    {
                        return reader.ReadToEnd();
                    }
                }
            }

            /// <summary>
            /// Encrypts a byte array and returns the encrypted data as a base64 encoded string.<br/>
            /// 对字节数组进行加密，并将加密后的数据以Base64编码的字符串形式返回。
            /// </summary>
            /// <param name="plainBytes">The byte array to be encrypted.<br/>要加密的字节数组。</param>
            /// <param name="keyBase64">The base64 encoded key for encryption.<br/>用于加密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <returns>A base64 encoded string containing the encrypted data.<br/>包含加密数据的Base64编码字符串。</returns>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null.<br/>当任何一个参数为null时抛出。</exception>
            public static string EncryptBytesToString(byte[] plainBytes, string keyBase64, string ivBase64)
            {
                if (plainBytes == null || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null"); // 参数不能为null

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.ISO10126;

                    using (ICryptoTransform encryptor = aes.CreateEncryptor())
                    using (MemoryStream memoryStream = new MemoryStream())
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(plainBytes, 0, plainBytes.Length);
                        cryptoStream.FlushFinalBlock();
                        byte[] cipherBytes = memoryStream.ToArray();
                        return Convert.ToBase64String(cipherBytes); // 返回Base64编码的加密数据
                    }
                }
            }

            /// <summary>
            /// Decrypts a base64 encoded string containing encrypted data and returns the decrypted byte array.<br/>
            /// 解密包含加密数据的Base64编码字符串，并将解密后的字节数组返回。
            /// </summary>
            /// <param name="cipherTextBase64">The base64 encoded string containing the encrypted data.<br/>包含加密数据的Base64编码字符串。</param>
            /// <param name="keyBase64">The base64 encoded key for decryption.<br/>用于解密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <returns>A byte array containing the decrypted data.<br/>包含解密数据的字节数组。</returns>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null.<br/>当任何一个参数为null时抛出。</exception>
            public static byte[] DecryptStringToBytes(string cipherTextBase64, string keyBase64, string ivBase64)
            {
                if (cipherTextBase64 == null || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null"); // 参数不能为null

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);
                byte[] cipherBytes = Convert.FromBase64String(cipherTextBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.ISO10126;

                    using (ICryptoTransform decryptor = aes.CreateDecryptor())
                    using (MemoryStream memoryStream = new MemoryStream(cipherBytes))
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                    using (MemoryStream resultStream = new MemoryStream())
                    {
                        cryptoStream.CopyTo(resultStream); // 将解密后的数据写入结果流
                        return resultStream.ToArray(); // 返回解密后的字节数组
                    }
                }
            }

            /// <summary>
            /// Encrypts a byte array using AES encryption and returns the encrypted byte array.<br/>
            /// 使用AES加密对字节数组进行加密，并返回加密后的字节数组。
            /// </summary>
            /// <param name="plainBytes">The byte array to be encrypted.<br/>要加密的字节数组。</param>
            /// <param name="keyBase64">The base64 encoded key for encryption.<br/>用于加密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <returns>A byte array containing the encrypted data.<br/>包含加密数据的字节数组。</returns>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null.<br/>当任何一个参数为null时抛出。</exception>
            public static byte[] EncryptBytes(byte[] plainBytes, string keyBase64, string ivBase64)
            {
                if (plainBytes == null || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null"); // 参数不能为null

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.ISO10126;

                    using (ICryptoTransform encryptor = aes.CreateEncryptor())
                    using (MemoryStream memoryStream = new MemoryStream())
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(plainBytes, 0, plainBytes.Length);
                        cryptoStream.FlushFinalBlock();
                        return memoryStream.ToArray(); // 返回加密后的字节数组
                    }
                }
            }

            /// <summary>
            /// Decrypts an encrypted byte array using AES decryption and returns the decrypted byte array.<br/>
            /// 使用AES解密对加密的字节数组进行解密，并返回解密后的字节数组。
            /// </summary>
            /// <param name="cipherBytes">The byte array containing the encrypted data.<br/>包含加密数据的字节数组。</param>
            /// <param name="keyBase64">The base64 encoded key for decryption.<br/>用于解密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <returns>A byte array containing the decrypted data.<br/>包含解密数据的字节数组。</returns>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null.<br/>当任何一个参数为null时抛出。</exception>
            public static byte[] DecryptBytes(byte[] cipherBytes, string keyBase64, string ivBase64)
            {
                if (cipherBytes == null || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null"); // 参数不能为null

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.ISO10126;

                    using (ICryptoTransform decryptor = aes.CreateDecryptor())
                    using (MemoryStream memoryStream = new MemoryStream(cipherBytes))
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                    using (MemoryStream resultStream = new MemoryStream())
                    {
                        cryptoStream.CopyTo(resultStream); // 将解密后的数据写入结果流
                        return resultStream.ToArray(); // 返回解密后的字节数组
                    }
                }
            }

            /// <summary>
            /// Encrypts the contents of a file using AES encryption and writes the encrypted data to another file.<br/>
            /// 使用AES加密对文件内容进行加密，并将加密后的数据写入另一个文件。
            /// </summary>
            /// <param name="inputFilePath">The path to the input file to be encrypted.<br/>要加密的输入文件路径。</param>
            /// <param name="outputFilePath">The path to the output file where encrypted data will be saved.<br/>加密数据将保存到的输出文件路径。</param>
            /// <param name="keyBase64">The base64 encoded key for encryption.<br/>用于加密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null or empty.<br/>当任何一个参数为null或空时抛出。</exception>
            public static void EncryptFile(string inputFilePath, string outputFilePath, string keyBase64, string ivBase64)
            {
                if (string.IsNullOrEmpty(inputFilePath) || string.IsNullOrEmpty(outputFilePath) || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null or empty"); // 参数不能为null或空

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.ISO10126;

                    using (ICryptoTransform encryptor = aes.CreateEncryptor())
                    using (FileStream inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                    using (FileStream outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    using (CryptoStream cryptoStream = new CryptoStream(outputFileStream, encryptor, CryptoStreamMode.Write))
                    {
                        inputFileStream.CopyTo(cryptoStream); // 将输入文件内容复制到加密流
                        cryptoStream.FlushFinalBlock(); // 完成加密并写入输出文件
                    }
                }
            }

            /// <summary>
            /// Decrypts the contents of a file using AES decryption and writes the decrypted data to another file.<br/>
            /// 使用AES解密对文件内容进行解密，并将解密后的数据写入另一个文件。
            /// </summary>
            /// <param name="inputFilePath">The path to the input file to be decrypted.<br/>要解密的输入文件路径。</param>
            /// <param name="outputFilePath">The path to the output file where decrypted data will be saved.<br/>解密数据将保存到的输出文件路径。</param>
            /// <param name="keyBase64">The base64 encoded key for decryption.<br/>用于解密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null or empty.<br/>当任何一个参数为null或空时抛出。</exception>
            public static void DecryptFile(string inputFilePath, string outputFilePath, string keyBase64, string ivBase64)
            {
                if (string.IsNullOrEmpty(inputFilePath) || string.IsNullOrEmpty(outputFilePath) || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null or empty"); // 参数不能为null或空

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.ISO10126;

                    using (ICryptoTransform decryptor = aes.CreateDecryptor())
                    using (FileStream inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                    using (FileStream outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    using (CryptoStream cryptoStream = new CryptoStream(outputFileStream, decryptor, CryptoStreamMode.Write))
                    {
                        inputFileStream.CopyTo(cryptoStream); // 将输入文件内容复制到解密流
                        cryptoStream.FlushFinalBlock(); // 完成解密并写入输出文件
                    }
                }
            }

            /// <summary>
            /// Encrypts a byte array and writes the encrypted data to a file.<br/>
            /// 对字节数组进行加密，并将加密后的数据写入文件。
            /// </summary>
            /// <param name="plainBytes">The byte array containing data to be encrypted.<br/>要加密的数据字节数组。</param>
            /// <param name="outputFilePath">The path to the output file where encrypted data will be saved.<br/>加密数据将保存到的输出文件路径。</param>
            /// <param name="keyBase64">The base64 encoded key for encryption.<br/>用于加密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null or empty.<br/>当任何一个参数为null或空时抛出。</exception>
            public static void EncryptBytesToFile(byte[] plainBytes, string outputFilePath, string keyBase64, string ivBase64)
            {
                if (plainBytes == null || string.IsNullOrEmpty(outputFilePath) || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null or empty");

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.ISO10126;

                    using (ICryptoTransform encryptor = aes.CreateEncryptor())
                    using (FileStream outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    using (CryptoStream cryptoStream = new CryptoStream(outputFileStream, encryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(plainBytes, 0, plainBytes.Length);
                        cryptoStream.FlushFinalBlock();
                    }
                }
            }

            /// <summary>
            /// Decrypts the contents of a file and returns the decrypted data as a byte array.<br/>
            /// 解密文件内容，并将解密后的数据作为字节数组返回。
            /// </summary>
            /// <param name="inputFilePath">The path to the input file to be decrypted.<br/>要解密的输入文件路径。</param>
            /// <param name="keyBase64">The base64 encoded key for decryption.<br/>用于解密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <returns>A byte array containing the decrypted data.<br/>包含解密数据的字节数组。</returns>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null or empty.<br/>当任何一个参数为null或空时抛出。</exception>
            public static byte[] DecryptFileToBytes(string inputFilePath, string keyBase64, string ivBase64)
            {
                if (string.IsNullOrEmpty(inputFilePath) || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null or empty");

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.ISO10126;

                    using (ICryptoTransform decryptor = aes.CreateDecryptor())
                    using (FileStream inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                    using (CryptoStream cryptoStream = new CryptoStream(inputFileStream, decryptor, CryptoStreamMode.Read))
                    using (MemoryStream resultStream = new MemoryStream())
                    {
                        cryptoStream.CopyTo(resultStream);
                        return resultStream.ToArray();
                    }
                }
            }

            /// <summary>
            /// Encrypts the contents of a file and returns the encrypted data as a byte array.<br/>
            /// 对文件内容进行加密，并将加密后的数据作为字节数组返回。
            /// </summary>
            /// <param name="inputFilePath">The path to the input file to be encrypted.<br/>要加密的输入文件路径。</param>
            /// <param name="keyBase64">The base64 encoded key for encryption.<br/>用于加密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <returns>A byte array containing the encrypted data.<br/>包含加密数据的字节数组。</returns>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null or empty.<br/>当任何一个参数为null或空时抛出。</exception>
            public static byte[] EncryptFileToBytes(string inputFilePath, string keyBase64, string ivBase64)
            {
                if (string.IsNullOrEmpty(inputFilePath) || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null or empty");

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.ISO10126;

                    using (ICryptoTransform encryptor = aes.CreateEncryptor())
                    using (FileStream inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                    using (MemoryStream outputStream = new MemoryStream())
                    using (CryptoStream cryptoStream = new CryptoStream(outputStream, encryptor, CryptoStreamMode.Write))
                    {
                        inputFileStream.CopyTo(cryptoStream);
                        cryptoStream.FlushFinalBlock();
                        return outputStream.ToArray();
                    }
                }
            }

            /// <summary>
            /// Decrypts a byte array and writes the decrypted data to a file.<br/>
            /// 对字节数组进行解密，并将解密后的数据写入文件。
            /// </summary>
            /// <param name="encryptedBytes">The byte array containing data to be decrypted.<br/>要解密的字节数组。</param>
            /// <param name="outputFilePath">The path to the output file where decrypted data will be saved.<br/>解密数据将保存到的输出文件路径。</param>
            /// <param name="keyBase64">The base64 encoded key for decryption.<br/>用于解密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null or empty.<br/>当任何一个参数为null或空时抛出。</exception>
            public static void DecryptBytesToFile(byte[] encryptedBytes, string outputFilePath, string keyBase64, string ivBase64)
            {
                if (encryptedBytes == null || string.IsNullOrEmpty(outputFilePath) || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null or empty");

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.ISO10126;

                    using (ICryptoTransform decryptor = aes.CreateDecryptor())
                    using (MemoryStream inputStream = new MemoryStream(encryptedBytes))
                    using (FileStream outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    using (CryptoStream cryptoStream = new CryptoStream(outputFileStream, decryptor, CryptoStreamMode.Write))
                    {
                        inputStream.CopyTo(cryptoStream);
                        cryptoStream.FlushFinalBlock();
                    }
                }
            }
        }

        /// <summary>
        /// ANSIX923 padding mode.
        /// ANSIX923 填充模式。
        /// </summary>
        public class ANSIX923
        {
            /// <summary>
            /// Encrypts a plain text string using AES encryption with the specified key and IV.<br/>
            /// 使用指定的密钥和IV对明文字符串进行AES加密。
            /// </summary>
            /// <param name="plainText">The plain text string to be encrypted.<br/>要加密的明文字符串。</param>
            /// <param name="keyBase64">The base64 encoded key for encryption.<br/>用于加密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <returns>The base64 encoded encrypted string.<br/>Base64编码的加密字符串。</returns>
            public static string EncryptString(string plainText, string keyBase64, string ivBase64)
            {
                if (plainText == null || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null"); // 参数不能为null

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.ANSIX923;

                    using (ICryptoTransform encryptor = aes.CreateEncryptor())
                    using (MemoryStream memoryStream = new MemoryStream())
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                        cryptoStream.Write(plainBytes, 0, plainBytes.Length);
                        cryptoStream.FlushFinalBlock();
                        byte[] cipherBytes = memoryStream.ToArray();
                        return Convert.ToBase64String(cipherBytes);
                    }
                }
            }

            /// <summary>
            /// Decrypts an encrypted base64 string using AES decryption with the specified key and IV.<br/>
            /// 使用指定的密钥和IV对Base64编码的加密字符串进行AES解密。
            /// </summary>
            /// <param name="cipherTextBase64">The base64 encoded encrypted string to be decrypted.<br/>要解密的Base64编码的加密字符串。</param>
            /// <param name="keyBase64">The base64 encoded key for decryption.<br/>用于解密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <returns>The decrypted plain text string.<br/>解密后的明文字符串。</returns>
            public static string DecryptString(string cipherTextBase64, string keyBase64, string ivBase64)
            {
                if (cipherTextBase64 == null || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null"); // 参数不能为null

                byte[] cipherBytes = Convert.FromBase64String(cipherTextBase64);
                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.ANSIX923;

                    using (ICryptoTransform decryptor = aes.CreateDecryptor())
                    using (MemoryStream memoryStream = new MemoryStream(cipherBytes))
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                    using (StreamReader reader = new StreamReader(cryptoStream))
                    {
                        return reader.ReadToEnd();
                    }
                }
            }

            /// <summary>
            /// Encrypts a plain text string and returns the encrypted data as a byte array.<br/>
            /// 对明文字符串进行加密，并将加密后的数据作为字节数组返回。
            /// </summary>
            /// <param name="plainText">The plain text string to be encrypted.<br/>要加密的明文字符串。</param>
            /// <param name="keyBase64">The base64 encoded key for encryption.<br/>用于加密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <returns>A byte array containing the encrypted data.<br/>包含加密数据的字节数组。</returns>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null.<br/>当任何一个参数为null时抛出。</exception>
            public static byte[] EncryptStringToBytes(string plainText, string keyBase64, string ivBase64)
            {
                if (plainText == null || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null"); // 参数不能为null

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.ANSIX923;

                    using (ICryptoTransform encryptor = aes.CreateEncryptor())
                    using (MemoryStream memoryStream = new MemoryStream())
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                        cryptoStream.Write(plainBytes, 0, plainBytes.Length);
                        cryptoStream.FlushFinalBlock();
                        return memoryStream.ToArray();
                    }
                }
            }

            /// <summary>
            /// Decrypts a byte array containing encrypted data and returns the plain text string.<br/>
            /// 解密包含加密数据的字节数组，并返回明文字符串。
            /// </summary>
            /// <param name="cipherBytes">The byte array containing the encrypted data.<br/>包含加密数据的字节数组。</param>
            /// <param name="keyBase64">The base64 encoded key for decryption.<br/>用于解密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <returns>The decrypted plain text string.<br/>解密后的明文字符串。</returns>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null.<br/>当任何一个参数为null时抛出。</exception>
            public static string DecryptBytesToString(byte[] cipherBytes, string keyBase64, string ivBase64)
            {
                if (cipherBytes == null || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null"); // 参数不能为null

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.ANSIX923;

                    using (ICryptoTransform decryptor = aes.CreateDecryptor())
                    using (MemoryStream memoryStream = new MemoryStream(cipherBytes))
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                    using (StreamReader reader = new StreamReader(cryptoStream))
                    {
                        return reader.ReadToEnd();
                    }
                }
            }

            /// <summary>
            /// Encrypts a byte array and returns the encrypted data as a base64 encoded string.<br/>
            /// 对字节数组进行加密，并将加密后的数据以Base64编码的字符串形式返回。
            /// </summary>
            /// <param name="plainBytes">The byte array to be encrypted.<br/>要加密的字节数组。</param>
            /// <param name="keyBase64">The base64 encoded key for encryption.<br/>用于加密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <returns>A base64 encoded string containing the encrypted data.<br/>包含加密数据的Base64编码字符串。</returns>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null.<br/>当任何一个参数为null时抛出。</exception>
            public static string EncryptBytesToString(byte[] plainBytes, string keyBase64, string ivBase64)
            {
                if (plainBytes == null || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null"); // 参数不能为null

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.ANSIX923;

                    using (ICryptoTransform encryptor = aes.CreateEncryptor())
                    using (MemoryStream memoryStream = new MemoryStream())
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(plainBytes, 0, plainBytes.Length);
                        cryptoStream.FlushFinalBlock();
                        byte[] cipherBytes = memoryStream.ToArray();
                        return Convert.ToBase64String(cipherBytes); // 返回Base64编码的加密数据
                    }
                }
            }

            /// <summary>
            /// Decrypts a base64 encoded string containing encrypted data and returns the decrypted byte array.<br/>
            /// 解密包含加密数据的Base64编码字符串，并将解密后的字节数组返回。
            /// </summary>
            /// <param name="cipherTextBase64">The base64 encoded string containing the encrypted data.<br/>包含加密数据的Base64编码字符串。</param>
            /// <param name="keyBase64">The base64 encoded key for decryption.<br/>用于解密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <returns>A byte array containing the decrypted data.<br/>包含解密数据的字节数组。</returns>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null.<br/>当任何一个参数为null时抛出。</exception>
            public static byte[] DecryptStringToBytes(string cipherTextBase64, string keyBase64, string ivBase64)
            {
                if (cipherTextBase64 == null || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null"); // 参数不能为null

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);
                byte[] cipherBytes = Convert.FromBase64String(cipherTextBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.ANSIX923;

                    using (ICryptoTransform decryptor = aes.CreateDecryptor())
                    using (MemoryStream memoryStream = new MemoryStream(cipherBytes))
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                    using (MemoryStream resultStream = new MemoryStream())
                    {
                        cryptoStream.CopyTo(resultStream); // 将解密后的数据写入结果流
                        return resultStream.ToArray(); // 返回解密后的字节数组
                    }
                }
            }

            /// <summary>
            /// Encrypts a byte array using AES encryption and returns the encrypted byte array.<br/>
            /// 使用AES加密对字节数组进行加密，并返回加密后的字节数组。
            /// </summary>
            /// <param name="plainBytes">The byte array to be encrypted.<br/>要加密的字节数组。</param>
            /// <param name="keyBase64">The base64 encoded key for encryption.<br/>用于加密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <returns>A byte array containing the encrypted data.<br/>包含加密数据的字节数组。</returns>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null.<br/>当任何一个参数为null时抛出。</exception>
            public static byte[] EncryptBytes(byte[] plainBytes, string keyBase64, string ivBase64)
            {
                if (plainBytes == null || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null"); // 参数不能为null

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.ANSIX923;

                    using (ICryptoTransform encryptor = aes.CreateEncryptor())
                    using (MemoryStream memoryStream = new MemoryStream())
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(plainBytes, 0, plainBytes.Length);
                        cryptoStream.FlushFinalBlock();
                        return memoryStream.ToArray(); // 返回加密后的字节数组
                    }
                }
            }

            /// <summary>
            /// Decrypts an encrypted byte array using AES decryption and returns the decrypted byte array.<br/>
            /// 使用AES解密对加密的字节数组进行解密，并返回解密后的字节数组。
            /// </summary>
            /// <param name="cipherBytes">The byte array containing the encrypted data.<br/>包含加密数据的字节数组。</param>
            /// <param name="keyBase64">The base64 encoded key for decryption.<br/>用于解密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <returns>A byte array containing the decrypted data.<br/>包含解密数据的字节数组。</returns>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null.<br/>当任何一个参数为null时抛出。</exception>
            public static byte[] DecryptBytes(byte[] cipherBytes, string keyBase64, string ivBase64)
            {
                if (cipherBytes == null || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null"); // 参数不能为null

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.ANSIX923;

                    using (ICryptoTransform decryptor = aes.CreateDecryptor())
                    using (MemoryStream memoryStream = new MemoryStream(cipherBytes))
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                    using (MemoryStream resultStream = new MemoryStream())
                    {
                        cryptoStream.CopyTo(resultStream); // 将解密后的数据写入结果流
                        return resultStream.ToArray(); // 返回解密后的字节数组
                    }
                }
            }

            /// <summary>
            /// Encrypts the contents of a file using AES encryption and writes the encrypted data to another file.<br/>
            /// 使用AES加密对文件内容进行加密，并将加密后的数据写入另一个文件。
            /// </summary>
            /// <param name="inputFilePath">The path to the input file to be encrypted.<br/>要加密的输入文件路径。</param>
            /// <param name="outputFilePath">The path to the output file where encrypted data will be saved.<br/>加密数据将保存到的输出文件路径。</param>
            /// <param name="keyBase64">The base64 encoded key for encryption.<br/>用于加密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null or empty.<br/>当任何一个参数为null或空时抛出。</exception>
            public static void EncryptFile(string inputFilePath, string outputFilePath, string keyBase64, string ivBase64)
            {
                if (string.IsNullOrEmpty(inputFilePath) || string.IsNullOrEmpty(outputFilePath) || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null or empty"); // 参数不能为null或空

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.ANSIX923;

                    using (ICryptoTransform encryptor = aes.CreateEncryptor())
                    using (FileStream inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                    using (FileStream outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    using (CryptoStream cryptoStream = new CryptoStream(outputFileStream, encryptor, CryptoStreamMode.Write))
                    {
                        inputFileStream.CopyTo(cryptoStream); // 将输入文件内容复制到加密流
                        cryptoStream.FlushFinalBlock(); // 完成加密并写入输出文件
                    }
                }
            }

            /// <summary>
            /// Decrypts the contents of a file using AES decryption and writes the decrypted data to another file.<br/>
            /// 使用AES解密对文件内容进行解密，并将解密后的数据写入另一个文件。
            /// </summary>
            /// <param name="inputFilePath">The path to the input file to be decrypted.<br/>要解密的输入文件路径。</param>
            /// <param name="outputFilePath">The path to the output file where decrypted data will be saved.<br/>解密数据将保存到的输出文件路径。</param>
            /// <param name="keyBase64">The base64 encoded key for decryption.<br/>用于解密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null or empty.<br/>当任何一个参数为null或空时抛出。</exception>
            public static void DecryptFile(string inputFilePath, string outputFilePath, string keyBase64, string ivBase64)
            {
                if (string.IsNullOrEmpty(inputFilePath) || string.IsNullOrEmpty(outputFilePath) || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null or empty"); // 参数不能为null或空

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.ANSIX923;

                    using (ICryptoTransform decryptor = aes.CreateDecryptor())
                    using (FileStream inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                    using (FileStream outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    using (CryptoStream cryptoStream = new CryptoStream(outputFileStream, decryptor, CryptoStreamMode.Write))
                    {
                        inputFileStream.CopyTo(cryptoStream); // 将输入文件内容复制到解密流
                        cryptoStream.FlushFinalBlock(); // 完成解密并写入输出文件
                    }
                }
            }

            /// <summary>
            /// Encrypts a byte array and writes the encrypted data to a file.<br/>
            /// 对字节数组进行加密，并将加密后的数据写入文件。
            /// </summary>
            /// <param name="plainBytes">The byte array containing data to be encrypted.<br/>要加密的数据字节数组。</param>
            /// <param name="outputFilePath">The path to the output file where encrypted data will be saved.<br/>加密数据将保存到的输出文件路径。</param>
            /// <param name="keyBase64">The base64 encoded key for encryption.<br/>用于加密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null or empty.<br/>当任何一个参数为null或空时抛出。</exception>
            public static void EncryptBytesToFile(byte[] plainBytes, string outputFilePath, string keyBase64, string ivBase64)
            {
                if (plainBytes == null || string.IsNullOrEmpty(outputFilePath) || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null or empty");

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.ANSIX923;

                    using (ICryptoTransform encryptor = aes.CreateEncryptor())
                    using (FileStream outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    using (CryptoStream cryptoStream = new CryptoStream(outputFileStream, encryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(plainBytes, 0, plainBytes.Length);
                        cryptoStream.FlushFinalBlock();
                    }
                }
            }

            /// <summary>
            /// Decrypts the contents of a file and returns the decrypted data as a byte array.<br/>
            /// 解密文件内容，并将解密后的数据作为字节数组返回。
            /// </summary>
            /// <param name="inputFilePath">The path to the input file to be decrypted.<br/>要解密的输入文件路径。</param>
            /// <param name="keyBase64">The base64 encoded key for decryption.<br/>用于解密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <returns>A byte array containing the decrypted data.<br/>包含解密数据的字节数组。</returns>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null or empty.<br/>当任何一个参数为null或空时抛出。</exception>
            public static byte[] DecryptFileToBytes(string inputFilePath, string keyBase64, string ivBase64)
            {
                if (string.IsNullOrEmpty(inputFilePath) || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null or empty");

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.ANSIX923;

                    using (ICryptoTransform decryptor = aes.CreateDecryptor())
                    using (FileStream inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                    using (CryptoStream cryptoStream = new CryptoStream(inputFileStream, decryptor, CryptoStreamMode.Read))
                    using (MemoryStream resultStream = new MemoryStream())
                    {
                        cryptoStream.CopyTo(resultStream);
                        return resultStream.ToArray();
                    }
                }
            }

            /// <summary>
            /// Encrypts the contents of a file and returns the encrypted data as a byte array.<br/>
            /// 对文件内容进行加密，并将加密后的数据作为字节数组返回。
            /// </summary>
            /// <param name="inputFilePath">The path to the input file to be encrypted.<br/>要加密的输入文件路径。</param>
            /// <param name="keyBase64">The base64 encoded key for encryption.<br/>用于加密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <returns>A byte array containing the encrypted data.<br/>包含加密数据的字节数组。</returns>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null or empty.<br/>当任何一个参数为null或空时抛出。</exception>
            public static byte[] EncryptFileToBytes(string inputFilePath, string keyBase64, string ivBase64)
            {
                if (string.IsNullOrEmpty(inputFilePath) || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null or empty");

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.ANSIX923;

                    using (ICryptoTransform encryptor = aes.CreateEncryptor())
                    using (FileStream inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                    using (MemoryStream outputStream = new MemoryStream())
                    using (CryptoStream cryptoStream = new CryptoStream(outputStream, encryptor, CryptoStreamMode.Write))
                    {
                        inputFileStream.CopyTo(cryptoStream);
                        cryptoStream.FlushFinalBlock();
                        return outputStream.ToArray();
                    }
                }
            }

            /// <summary>
            /// Decrypts a byte array and writes the decrypted data to a file.<br/>
            /// 对字节数组进行解密，并将解密后的数据写入文件。
            /// </summary>
            /// <param name="encryptedBytes">The byte array containing data to be decrypted.<br/>要解密的字节数组。</param>
            /// <param name="outputFilePath">The path to the output file where decrypted data will be saved.<br/>解密数据将保存到的输出文件路径。</param>
            /// <param name="keyBase64">The base64 encoded key for decryption.<br/>用于解密的Base64编码密钥。</param>
            /// <param name="ivBase64">The base64 encoded initialization vector (IV).<br/>Base64编码的初始化向量（IV）。</param>
            /// <exception cref="ArgumentNullException">Thrown when any of the arguments is null or empty.<br/>当任何一个参数为null或空时抛出。</exception>
            public static void DecryptBytesToFile(byte[] encryptedBytes, string outputFilePath, string keyBase64, string ivBase64)
            {
                if (encryptedBytes == null || string.IsNullOrEmpty(outputFilePath) || keyBase64 == null || ivBase64 == null)
                    throw new ArgumentNullException("Arguments cannot be null or empty");

                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.ANSIX923;

                    using (ICryptoTransform decryptor = aes.CreateDecryptor())
                    using (MemoryStream inputStream = new MemoryStream(encryptedBytes))
                    using (FileStream outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    using (CryptoStream cryptoStream = new CryptoStream(outputFileStream, decryptor, CryptoStreamMode.Write))
                    {
                        inputStream.CopyTo(cryptoStream);
                        cryptoStream.FlushFinalBlock();
                    }
                }
            }
        }
    }
}

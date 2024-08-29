using System.IO;
using System.Security.Cryptography;
using System.Text;
using System;

namespace AES
{
    /// <summary>
    /// ECB encryption mode.<br></br>
    /// ECB加密模式。
    /// </summary>
    public class ECB
    {
        /// <summary>
        /// PKCS7 padding mode.
        /// PKCS7 填充模式。
        /// </summary>
        public class PKCS7
        {
            /// <summary>
            /// Encrypts a plain text string using AES encryption with ECB mode.<br></br>
            /// 使用 ECB 模式的 AES 加密对纯文本字符串进行加密。
            /// </summary>
            /// <param name="plainText">The plain text string to encrypt.<br></br>要加密的纯文本字符串。</param>
            /// <param name="key">The encryption key, must be 32 characters long.<br></br>加密密钥，必须为 32 个字符长。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被使用，但仍需提供。</param>
            /// <returns>The encrypted string in Base64 format.<br></br>以 Base64 格式返回的加密字符串。</returns>
            /// <remarks>
            /// This method uses AES encryption in ECB mode.<br></br>Note: ECB mode is not recommended for secure encryption as it does not use an initialization vector and has certain security vulnerabilities.<br></br>
            /// 该方法使用 ECB 模式的 AES 加密。<br></br>注意：ECB 模式不建议用于安全加密，因为它不使用初始化向量，并且具有某些安全漏洞。
            /// </remarks>
            public static string EncryptString(string plainText, string key, string iv)
            {
                if (key.Length != 32) throw new ArgumentException("Key must be 32 characters long.");
                if (iv.Length != 16) throw new ArgumentException("IV must be 16 characters long.");

                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv);

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置为 ECB 模式
                    aes.Padding = PaddingMode.PKCS7; // 设置填充模式
                    aes.Key = keyBytes;
                    aes.IV = ivBytes; // 在 ECB 模式下，IV 不会被使用，但仍需提供

                    var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                    var plainBytes = Encoding.UTF8.GetBytes(plainText);

                    using (var ms = new MemoryStream())
                    {
                        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            cs.Write(plainBytes, 0, plainBytes.Length);
                            cs.FlushFinalBlock();
                        }

                        return Convert.ToBase64String(ms.ToArray());
                    }
                }
            }

            /// <summary>
            /// Decrypts an encrypted string using AES decryption with ECB mode.<br></br>
            /// 使用 ECB 模式的 AES 解密对加密字符串进行解密。
            /// </summary>
            /// <param name="cipherText">The encrypted string in Base64 format to decrypt.<br></br>要解密的以 Base64 格式加密的字符串。</param>
            /// <param name="key">The decryption key, must be 32 characters long.<br></br>解密密钥，必须为 32 个字符长。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被使用，但仍需提供。</param>
            /// <returns>The decrypted plain text string.<br></br>解密后的纯文本字符串。</returns>
            /// <remarks>
            /// This method uses AES decryption in ECB mode.<br></br>Note: ECB mode is not recommended for secure decryption as it does not use an initialization vector and has certain security vulnerabilities.<br></br>
            /// 该方法使用 ECB 模式的 AES 解密。<br></br>注意：ECB 模式不建议用于安全解密，因为它不使用初始化向量，并且具有某些安全漏洞。
            /// </remarks>
            public static string DecryptString(string cipherText, string key, string iv)
            {
                if (key.Length != 32) throw new ArgumentException("Key must be 32 characters long.");
                if (iv.Length != 16) throw new ArgumentException("IV must be 16 characters long.");

                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv);

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置为 ECB 模式
                    aes.Padding = PaddingMode.PKCS7; // 设置填充模式
                    aes.Key = keyBytes;
                    aes.IV = ivBytes; // 在 ECB 模式下，IV 不会被使用，但仍需提供

                    var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    var cipherBytes = Convert.FromBase64String(cipherText);

                    using (var ms = new MemoryStream(cipherBytes))
                    {
                        using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                        {
                            using (var reader = new StreamReader(cs))
                            {
                                return reader.ReadToEnd();
                            }
                        }
                    }
                }
            }

            /// <summary>
            /// Encrypts a plain text string to a byte array using AES encryption with ECB mode.<br></br>
            /// 使用 ECB 模式的 AES 加密将纯文本字符串加密为字节数组。
            /// </summary>
            /// <param name="plainText">The plain text string to encrypt.<br></br>要加密的纯文本字符串。</param>
            /// <param name="key">The encryption key, must be 32 characters long.<br></br>加密密钥，必须为 32 个字符长。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被使用，但仍需提供。</param>
            /// <returns>The encrypted data as a byte array.<br></br>以字节数组形式返回的加密数据。</returns>
            /// <remarks>
            /// This method uses AES encryption in ECB mode.<br></br>Note: ECB mode is not recommended for secure encryption as it does not use an initialization vector and has certain security vulnerabilities.<br></br>
            /// 该方法使用 ECB 模式的 AES 加密。<br></br>注意：ECB 模式不建议用于安全加密，因为它不使用初始化向量，并且具有某些安全漏洞。
            /// </remarks>
            public static byte[] EncryptStringToBytes(string plainText, string key, string iv)
            {
                if (key.Length != 32) throw new ArgumentException("Key must be 32 characters long.");
                if (iv.Length != 16) throw new ArgumentException("IV must be 16 characters long.");

                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv);

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB;
                    aes.Padding = PaddingMode.PKCS7;
                    aes.Key = keyBytes;
                    aes.IV = ivBytes; // 在 ECB 模式下，IV 不会被使用，但仍需提供

                    var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
                    var plainBytes = Encoding.UTF8.GetBytes(plainText);

                    using (var ms = new MemoryStream())
                    {
                        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            cs.Write(plainBytes, 0, plainBytes.Length);
                            cs.FlushFinalBlock();
                        }
                        return ms.ToArray();
                    }
                }
            }

            /// <summary>
            /// Decrypts a byte array to a plain text string using AES decryption with ECB mode.<br></br>
            /// 使用 ECB 模式的 AES 解密将字节数组解密为纯文本字符串。
            /// </summary>
            /// <param name="cipherBytes">The encrypted data as a byte array to decrypt.<br></br>要解密的以字节数组形式的加密数据。</param>
            /// <param name="key">The decryption key, must be 32 characters long.<br></br>解密密钥，必须为 32 个字符长。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被使用，但仍需提供。</param>
            /// <returns>The decrypted plain text string.<br></br>解密后的纯文本字符串。</returns>
            /// <remarks>
            /// This method uses AES decryption in ECB mode.<br></br>Note: ECB mode is not recommended for secure decryption as it does not use an initialization vector and has certain security vulnerabilities.<br></br>
            /// 该方法使用 ECB 模式的 AES 解密。<br></br>注意：ECB 模式不建议用于安全解密，因为它不使用初始化向量，并且具有某些安全漏洞。
            /// </remarks>
            public static string DecryptBytesToString(byte[] cipherBytes, string key, string iv)
            {
                if (key.Length != 32) throw new ArgumentException("Key must be 32 characters long.");
                if (iv.Length != 16) throw new ArgumentException("IV must be 16 characters long.");

                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv);

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB;
                    aes.Padding = PaddingMode.PKCS7;
                    aes.Key = keyBytes;
                    aes.IV = ivBytes; // 在 ECB 模式下，IV 不会被使用，但仍需提供

                    var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    using (var ms = new MemoryStream(cipherBytes))
                    {
                        using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                        {
                            using (var reader = new StreamReader(cs, Encoding.UTF8))
                            {
                                return reader.ReadToEnd();
                            }
                        }
                    }
                }
            }

            /// <summary>
            /// Encrypts a byte array to a Base64-encoded string using AES encryption with ECB mode.<br></br>
            /// 使用 ECB 模式的 AES 加密将字节数组加密为 Base64 编码的字符串。
            /// </summary>
            /// <param name="data">The byte array to encrypt.<br></br>要加密的字节数组。</param>
            /// <param name="key">The encryption key, must be 32 characters long.<br></br>加密密钥，必须为 32 个字符长。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被实际使用，但仍需提供。</param>
            /// <returns>The encrypted data as a Base64-encoded string.<br></br>以 Base64 编码的字符串形式返回的加密数据。</returns>
            /// <remarks>
            /// This method uses AES encryption in ECB mode.<br></br>Note: ECB mode is not recommended for secure encryption as it does not use an initialization vector and has certain security vulnerabilities.<br></br>
            /// 该方法使用 ECB 模式的 AES 加密。<br></br>注意：ECB 模式不建议用于安全加密，因为它不使用初始化向量，并且具有某些安全漏洞。
            /// </remarks>
            public static string EncryptBytesToString(byte[] data, string key, string iv)
            {
                // 检查密钥长度，AES-256 需要 32 字节的密钥
                if (key.Length != 32) throw new ArgumentException("密钥必须为32个字符长。");
                // 检查初始化向量长度，虽然在 ECB 模式下不使用 IV，但仍需传递
                if (iv.Length != 16) throw new ArgumentException("IV必须为16个字符长。");

                // 将密钥和初始化向量从字符串转换为字节数组
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv); // 在 ECB 模式下，IV 不会被实际使用

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置加密模式为 ECB
                    aes.Padding = PaddingMode.PKCS7; // 设置填充模式为 PKCS7
                    aes.Key = keyBytes; // 设置密钥
                    aes.IV = ivBytes; // 设置 IV（虽然 ECB 模式下 IV 不实际使用）

                    // 创建加密器
                    var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                    using (var ms = new MemoryStream())
                    {
                        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            // 写入待加密的字节数据
                            cs.Write(data, 0, data.Length);
                            cs.FlushFinalBlock(); // 完成加密
                        }
                        // 将加密后的字节数据转换为 Base64 编码的字符串并返回
                        return Convert.ToBase64String(ms.ToArray());
                    }
                }
            }

            /// <summary>
            /// Decrypts a Base64-encoded string to a byte array using AES decryption with ECB mode.<br></br>
            /// 使用 ECB 模式的 AES 解密将 Base64 编码的字符串解密为字节数组。
            /// </summary>
            /// <param name="cipherText">The Base64-encoded string to decrypt.<br></br>要解密的 Base64 编码的字符串。</param>
            /// <param name="key">The decryption key, must be 32 characters long.<br></br>解密密钥，必须为 32 个字符长。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被实际使用，但仍需提供。</param>
            /// <returns>The decrypted data as a byte array.<br></br>解密后的字节数组。</returns>
            /// <remarks>
            /// This method uses AES decryption in ECB mode.<br></br>Note: ECB mode is not recommended for secure decryption as it does not use an initialization vector and has certain security vulnerabilities.<br></br>
            /// 该方法使用 ECB 模式的 AES 解密。<br></br>注意：ECB 模式不建议用于安全解密，因为它不使用初始化向量，并且具有某些安全漏洞。
            /// </remarks>
            public static byte[] DecryptStringToBytes(string cipherText, string key, string iv)
            {
                // 检查密钥长度，AES-256 需要 32 字节的密钥
                if (key.Length != 32) throw new ArgumentException("密钥必须为32个字符长。");
                // 检查初始化向量长度，虽然在 ECB 模式下不使用 IV，但仍需传递
                if (iv.Length != 16) throw new ArgumentException("IV必须为16个字符长。");

                // 将密钥和初始化向量从字符串转换为字节数组
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv); // 在 ECB 模式下，IV 不会被实际使用

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置解密模式为 ECB
                    aes.Padding = PaddingMode.PKCS7; // 设置填充模式为 PKCS7
                    aes.Key = keyBytes; // 设置密钥
                    aes.IV = ivBytes; // 设置 IV（虽然 ECB 模式下 IV 不实际使用）

                    // 创建解密器
                    var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    // 将 Base64 编码的字符串转换为字节数组
                    var cipherBytes = Convert.FromBase64String(cipherText);

                    using (var ms = new MemoryStream(cipherBytes))
                    {
                        using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                        {
                            using (var output = new MemoryStream())
                            {
                                // 读取解密后的字节数据
                                cs.CopyTo(output);
                                return output.ToArray();
                            }
                        }
                    }
                }
            }

            /// <summary>
            /// Encrypts a byte array using AES encryption with ECB mode and returns the encrypted data as a byte array.
            /// 使用 ECB 模式的 AES 加密加密字节数组，并以字节数组的形式返回加密后的数据。
            /// </summary>
            /// <param name="data">The byte array to encrypt.<br></br>要加密的字节数组。</param>
            /// <param name="key">The encryption key, must be 32 characters long. It will be converted to a byte array.<br></br>加密密钥，必须为 32 个字符长。将被转换为字节数组。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被实际使用，但仍需提供。</param>
            /// <returns>The encrypted data as a byte array.<br></br>以字节数组形式返回的加密数据。</returns>
            /// <remarks>
            /// This method uses AES encryption in ECB mode.<br></br>Note: ECB mode is not recommended for secure encryption as it does not use an initialization vector and may expose patterns in the plaintext.<br></br>
            /// 该方法使用 ECB 模式的 AES 加密。<br></br>注意：ECB 模式不建议用于安全加密，因为它不使用初始化向量，并可能暴露明文中的模式。
            /// </remarks>
            public static byte[] EncryptBytes(byte[] data, string key, string iv)
            {
                // 确保密钥长度为32字节（256位），AES-256加密需要此长度
                if (key.Length != 32) throw new ArgumentException("密钥必须是32个字符长。");
                // 确保IV长度为16字节（128位），虽然ECB模式下不实际使用IV
                if (iv.Length != 16) throw new ArgumentException("IV必须是16个字符长。");

                // 将密钥和IV从字符串转换为字节数组
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv); // 在ECB模式下IV不会被实际使用

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置为ECB模式
                    aes.Padding = PaddingMode.PKCS7; // 设置为PKCS7填充模式
                    aes.Key = keyBytes; // 设置密钥
                    aes.IV = ivBytes; // 设置IV（在ECB模式下不实际使用）

                    // 创建加密器
                    var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                    using (var ms = new MemoryStream())
                    {
                        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            // 将数据写入CryptoStream以进行加密
                            cs.Write(data, 0, data.Length);
                            cs.FlushFinalBlock(); // 确保所有数据都已写入
                        }
                        // 返回加密后的字节数组
                        return ms.ToArray();
                    }
                }
            }

            /// <summary>
            /// Decrypts a byte array using AES decryption with ECB mode and returns the decrypted data as a byte array.
            /// 使用 ECB 模式的 AES 解密解密字节数组，并以字节数组的形式返回解密后的数据。
            /// </summary>
            /// <param name="cipherData">The byte array containing the encrypted data.<br></br>包含加密数据的字节数组。</param>
            /// <param name="key">The decryption key, must be 32 characters long. It will be converted to a byte array.<br></br>解密密钥，必须为 32 个字符长。将被转换为字节数组。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被实际使用，但仍需提供。</param>
            /// <returns>The decrypted data as a byte array.<br></br>以字节数组形式返回的解密数据。</returns>
            /// <remarks>
            /// This method uses AES decryption in ECB mode.<br></br>Note: ECB mode is not recommended for secure decryption as it does not use an initialization vector and may expose patterns in the ciphertext.<br></br>
            /// 该方法使用 ECB 模式的 AES 解密。<br></br>注意：ECB 模式不建议用于安全解密，因为它不使用初始化向量，并可能暴露密文中的模式。
            /// </remarks>
            public static byte[] DecryptBytes(byte[] cipherData, string key, string iv)
            {
                // 确保密钥长度为32字节（256位），AES-256解密需要此长度
                if (key.Length != 32) throw new ArgumentException("密钥必须是32个字符长。");
                // 确保IV长度为16字节（128位），虽然ECB模式下不实际使用IV
                if (iv.Length != 16) throw new ArgumentException("IV必须是16个字符长。");

                // 将密钥和IV从字符串转换为字节数组
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv); // 在ECB模式下IV不会被实际使用

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置为ECB模式
                    aes.Padding = PaddingMode.PKCS7; // 设置为PKCS7填充模式
                    aes.Key = keyBytes; // 设置密钥
                    aes.IV = ivBytes; // 设置IV（在ECB模式下不实际使用）

                    // 创建解密器
                    var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    using (var ms = new MemoryStream(cipherData))
                    {
                        using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                        {
                            using (var output = new MemoryStream())
                            {
                                // 从CryptoStream读取解密后的数据
                                cs.CopyTo(output);
                                // 返回解密后的字节数组
                                return output.ToArray();
                            }
                        }
                    }
                }
            }

            /// <summary>
            /// Encrypts a file using AES encryption in ECB mode and writes the encrypted data to an output file.
            /// 使用 ECB 模式的 AES 加密加密文件，并将加密后的数据写入输出文件。
            /// </summary>
            /// <param name="inputFilePath">The path to the input file that will be encrypted.<br></br>要加密的输入文件的路径。</param>
            /// <param name="outputFilePath">The path to the output file where the encrypted data will be saved.<br></br>加密数据将保存到的输出文件的路径。</param>
            /// <param name="key">The encryption key, must be 32 characters long. It will be converted to a byte array.<br></br>加密密钥，必须为 32 个字符长。将被转换为字节数组。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被实际使用，但仍需提供。</param>
            /// <exception cref="ArgumentException">Thrown when the key or IV is of incorrect length.<br></br>当密钥或 IV 长度不正确时抛出。</exception>
            /// <remarks>
            /// This method uses AES encryption in ECB mode, which does not use the IV and is not recommended for secure encryption due to potential security vulnerabilities.<br></br>Note: ECB mode can expose patterns in the plaintext.<br></br>该方法使用 ECB 模式的 AES 加密，不使用 IV，并且由于潜在的安全漏洞，不建议用于安全加密。<br></br>注意：ECB 模式可能暴露明文中的模式。
            /// </remarks>
            public static void EncryptFile(string inputFilePath, string outputFilePath, string key, string iv)
            {
                // 检查密钥长度，AES-256需要32字节的密钥
                if (key.Length != 32) throw new ArgumentException("密钥必须是32个字符长。");
                // 检查IV长度，虽然ECB模式下不使用IV，但仍需传递
                if (iv.Length != 16) throw new ArgumentException("IV必须是16个字符长。");

                // 将密钥和IV从字符串转换为字节数组
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv); // 在ECB模式下IV不会被实际使用

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置为ECB模式
                    aes.Padding = PaddingMode.PKCS7; // 设置为PKCS7填充模式
                    aes.Key = keyBytes; // 设置密钥
                    aes.IV = ivBytes; // 设置IV（在ECB模式下不实际使用）

                    // 创建加密器
                    var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                    using (var inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                    using (var outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    using (var cryptoStream = new CryptoStream(outputFileStream, encryptor, CryptoStreamMode.Write))
                    {
                        // 加密文件内容
                        inputFileStream.CopyTo(cryptoStream);
                        cryptoStream.FlushFinalBlock(); // 确保所有数据都已加密
                    }
                }
            }

            /// <summary>
            /// Decrypts a file using AES decryption in ECB mode and writes the decrypted data to an output file.
            /// 使用 ECB 模式的 AES 解密解密文件，并将解密后的数据写入输出文件。
            /// </summary>
            /// <param name="inputFilePath">The path to the input file that contains the encrypted data.<br></br>包含加密数据的输入文件的路径。</param>
            /// <param name="outputFilePath">The path to the output file where the decrypted data will be saved.<br></br>解密数据将保存到的输出文件的路径。</param>
            /// <param name="key">The decryption key, must be 32 characters long. It will be converted to a byte array.<br></br>解密密钥，必须为 32 个字符长。将被转换为字节数组。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被实际使用，但仍需提供。</param>
            /// <exception cref="ArgumentException">Thrown when the key or IV is of incorrect length.<br></br>当密钥或 IV 长度不正确时抛出。</exception>
            /// <remarks>
            /// This method uses AES decryption in ECB mode, which does not use the IV and is not recommended for secure decryption due to potential security vulnerabilities.<br></br>Note: ECB mode can expose patterns in the ciphertext.<br></br>该方法使用 ECB 模式的 AES 解密，不使用 IV，并且由于潜在的安全漏洞，不建议用于安全解密。<br></br>注意：ECB 模式可能暴露密文中的模式。
            /// </remarks>
            public static void DecryptFile(string inputFilePath, string outputFilePath, string key, string iv)
            {
                // 检查密钥长度，AES-256需要32字节的密钥
                if (key.Length != 32) throw new ArgumentException("密钥必须是32个字符长。");
                // 检查IV长度，虽然ECB模式下不使用IV，但仍需传递
                if (iv.Length != 16) throw new ArgumentException("IV必须是16个字符长。");

                // 将密钥和IV从字符串转换为字节数组
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv); // 在ECB模式下IV不会被实际使用

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置为ECB模式
                    aes.Padding = PaddingMode.PKCS7; // 设置为PKCS7填充模式
                    aes.Key = keyBytes; // 设置密钥
                    aes.IV = ivBytes; // 设置IV（在ECB模式下不实际使用）

                    // 创建解密器
                    var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    using (var inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                    using (var outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    using (var cryptoStream = new CryptoStream(outputFileStream, decryptor, CryptoStreamMode.Write))
                    {
                        // 解密文件内容
                        inputFileStream.CopyTo(cryptoStream);
                        cryptoStream.FlushFinalBlock(); // 确保所有数据都已解密
                    }
                }
            }

            /// <summary>
            /// Encrypts a file and returns the encrypted data as a byte array.
            /// 加密文件并返回加密数据的字节数组。
            /// </summary>
            /// <param name="inputFilePath">The path to the input file that will be encrypted.<br></br>要加密的输入文件的路径。</param>
            /// <param name="key">The encryption key, must be 32 characters long. It will be converted to a byte array.<br></br>加密密钥，必须为 32 个字符长。将被转换为字节数组。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被实际使用，但仍需提供。</param>
            /// <returns>A byte array containing the encrypted data.<br></br>包含加密数据的字节数组。</returns>
            /// <exception cref="ArgumentException">Thrown when the key or IV is of incorrect length.<br></br>当密钥或 IV 长度不正确时抛出。</exception>
            /// <remarks>
            /// This method uses AES encryption in ECB mode, which does not use the IV and is not recommended for secure encryption due to potential security vulnerabilities.<br></br>Note: ECB mode can expose patterns in the plaintext.<br></br>该方法使用 ECB 模式的 AES 加密，不使用 IV，并且由于潜在的安全漏洞，不建议用于安全加密。<br></br>注意：ECB 模式可能暴露明文中的模式。
            /// </remarks>
            public static byte[] EncryptFileToBytes(string inputFilePath, string key, string iv)
            {
                // 确保密钥长度为32字节（256位），AES-256需要此长度
                if (key.Length != 32) throw new ArgumentException("密钥必须是32个字符长。");
                // 确保IV长度为16字节（128位），虽然ECB模式下不实际使用IV
                if (iv.Length != 16) throw new ArgumentException("IV必须是16个字符长。");

                // 将密钥和IV从字符串转换为字节数组
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv); // 在ECB模式下IV不会被实际使用

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置为ECB模式
                    aes.Padding = PaddingMode.PKCS7; // 设置为PKCS7填充模式
                    aes.Key = keyBytes; // 设置密钥
                    aes.IV = ivBytes; // 设置IV（在ECB模式下不实际使用）

                    // 创建加密器
                    var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                    using (var inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                    using (var ms = new MemoryStream())
                    using (var cryptoStream = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        // 将文件内容复制到CryptoStream进行加密
                        inputFileStream.CopyTo(cryptoStream);
                        cryptoStream.FlushFinalBlock(); // 确保所有数据都已加密

                        // 返回加密后的字节数组
                        return ms.ToArray();
                    }
                }
            }

            /// <summary>
            /// Decrypts a byte array containing encrypted data and returns the decrypted data as a byte array.
            /// 解密包含加密数据的字节数组，并返回解密后的数据的字节数组。
            /// </summary>
            /// <param name="cipherData">The byte array containing the encrypted data.<br></br>包含加密数据的字节数组。</param>
            /// <param name="key">The decryption key, must be 32 characters long. It will be converted to a byte array.<br></br>解密密钥，必须为 32 个字符长。将被转换为字节数组。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被实际使用，但仍需提供。</param>
            /// <returns>A byte array containing the decrypted data.<br></br>包含解密数据的字节数组。</returns>
            /// <exception cref="ArgumentException">Thrown when the key or IV is of incorrect length.<br></br>当密钥或 IV 长度不正确时抛出。</exception>
            /// <remarks>
            /// This method uses AES decryption in ECB mode, which does not use the IV and is not recommended for secure decryption due to potential security vulnerabilities.<br></br>Note: ECB mode can expose patterns in the ciphertext.<br></br>该方法使用 ECB 模式的 AES 解密，不使用 IV，并且由于潜在的安全漏洞，不建议用于安全解密。<br></br>注意：ECB 模式可能暴露密文中的模式。
            /// </remarks>
            public static byte[] DecryptBytesToFile(byte[] cipherData, string key, string iv)
            {
                // 确保密钥长度为32字节（256位），AES-256需要此长度
                if (key.Length != 32) throw new ArgumentException("密钥必须是32个字符长。");
                // 确保IV长度为16字节（128位），虽然ECB模式下不实际使用IV
                if (iv.Length != 16) throw new ArgumentException("IV必须是16个字符长。");

                // 将密钥和IV从字符串转换为字节数组
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv); // 在ECB模式下IV不会被实际使用

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置为ECB模式
                    aes.Padding = PaddingMode.PKCS7; // 设置为PKCS7填充模式
                    aes.Key = keyBytes; // 设置密钥
                    aes.IV = ivBytes; // 设置IV（在ECB模式下不实际使用）

                    // 创建解密器
                    var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    using (var ms = new MemoryStream(cipherData))
                    using (var cryptoStream = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    using (var output = new MemoryStream())
                    {
                        // 从CryptoStream读取解密后的数据
                        cryptoStream.CopyTo(output);
                        // 返回解密后的字节数组
                        return output.ToArray();
                    }
                }
            }

            /// <summary>
            /// Encrypts the given byte array and writes the encrypted data to a file.
            /// 加密给定的字节数组，并将加密后的数据写入文件。
            /// </summary>
            /// <param name="data">The byte array containing the data to encrypt.<br></br>包含要加密的数据的字节数组。</param>
            /// <param name="outputFilePath">The path to the output file where the encrypted data will be written.<br></br>加密数据将被写入的输出文件路径。</param>
            /// <param name="key">The encryption key, must be 32 characters long. This key will be converted to a byte array.<br></br>加密密钥，必须为 32 个字符长。该密钥将被转换为字节数组。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被实际使用，但仍需提供。</param>
            /// <exception cref="ArgumentException">Thrown when the key or IV is of incorrect length.<br></br>当密钥或 IV 长度不正确时抛出。</exception>
            /// <remarks>
            /// This method uses AES encryption in ECB mode. Note that ECB mode does not use the IV and is generally not recommended for secure encryption due to its vulnerability to certain attacks.<br></br>该方法使用 ECB 模式的 AES 加密。注意，ECB 模式不使用 IV，并且通常不建议用于安全加密，因为它容易受到某些攻击。
            /// </remarks>
            public static void EncryptBytesToFile(byte[] data, string outputFilePath, string key, string iv)
            {
                // 确保密钥长度为32字节（256位），AES-256需要此长度
                if (key.Length != 32) throw new ArgumentException("密钥必须是32个字符长。");
                // 确保IV长度为16字节（128位），虽然ECB模式下IV不会被实际使用
                if (iv.Length != 16) throw new ArgumentException("IV必须是16个字符长。");

                // 将密钥和IV从字符串转换为字节数组
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv); // 在ECB模式下IV不会被实际使用

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置为ECB模式
                    aes.Padding = PaddingMode.PKCS7; // 设置为PKCS7填充模式
                    aes.Key = keyBytes; // 设置密钥
                    aes.IV = ivBytes; // 设置IV（在ECB模式下不实际使用）

                    // 创建加密器
                    var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                    using (var outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    using (var cryptoStream = new CryptoStream(outputFileStream, encryptor, CryptoStreamMode.Write))
                    {
                        // 将数据写入CryptoStream进行加密
                        cryptoStream.Write(data, 0, data.Length);
                        cryptoStream.FlushFinalBlock(); // 确保所有数据都已加密
                    }
                }
            }

            /// <summary>
            /// Decrypts the data from a file and returns the decrypted byte array.
            /// 从文件中解密数据并返回解密后的字节数组。
            /// </summary>
            /// <param name="inputFilePath">The path to the input file containing the encrypted data.<br></br>包含加密数据的输入文件路径。</param>
            /// <param name="key">The decryption key, must be 32 characters long. This key will be converted to a byte array.<br></br>解密密钥，必须为 32 个字符长。该密钥将被转换为字节数组。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被实际使用，但仍需提供。</param>
            /// <returns>A byte array containing the decrypted data.<br></br>包含解密数据的字节数组。</returns>
            /// <exception cref="ArgumentException">Thrown when the key or IV is of incorrect length.<br></br>当密钥或 IV 长度不正确时抛出。</exception>
            /// <remarks>
            /// This method uses AES decryption in ECB mode. Note that ECB mode does not use the IV and is generally not recommended for secure decryption due to its vulnerability to certain attacks.<br></br>该方法使用 ECB 模式的 AES 解密。注意，ECB 模式不使用 IV，并且通常不建议用于安全解密，因为它容易受到某些攻击。
            /// </remarks>
            public static byte[] DecryptFileToBytes(string inputFilePath, string key, string iv)
            {
                // 确保密钥长度为32字节（256位），AES-256需要此长度
                if (key.Length != 32) throw new ArgumentException("密钥必须是32个字符长。");
                // 确保IV长度为16字节（128位），虽然ECB模式下IV不会被实际使用
                if (iv.Length != 16) throw new ArgumentException("IV必须是16个字符长。");

                // 将密钥和IV从字符串转换为字节数组
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv); // 在ECB模式下IV不会被实际使用

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置为ECB模式
                    aes.Padding = PaddingMode.PKCS7; // 设置为PKCS7填充模式
                    aes.Key = keyBytes; // 设置密钥
                    aes.IV = ivBytes; // 设置IV（在ECB模式下不实际使用）

                    // 创建解密器
                    var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    using (var inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                    using (var cryptoStream = new CryptoStream(inputFileStream, decryptor, CryptoStreamMode.Read))
                    using (var ms = new MemoryStream())
                    {
                        // 从CryptoStream读取解密后的数据
                        cryptoStream.CopyTo(ms);
                        // 返回解密后的字节数组
                        return ms.ToArray();
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
            /// Encrypts a plain text string using AES encryption with ECB mode.<br></br>
            /// 使用 ECB 模式的 AES 加密对纯文本字符串进行加密。
            /// </summary>
            /// <param name="plainText">The plain text string to encrypt.<br></br>要加密的纯文本字符串。</param>
            /// <param name="key">The encryption key, must be 32 characters long.<br></br>加密密钥，必须为 32 个字符长。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被使用，但仍需提供。</param>
            /// <returns>The encrypted string in Base64 format.<br></br>以 Base64 格式返回的加密字符串。</returns>
            /// <remarks>
            /// This method uses AES encryption in ECB mode.<br></br>Note: ECB mode is not recommended for secure encryption as it does not use an initialization vector and has certain security vulnerabilities.<br></br>
            /// 该方法使用 ECB 模式的 AES 加密。<br></br>注意：ECB 模式不建议用于安全加密，因为它不使用初始化向量，并且具有某些安全漏洞。
            /// </remarks>
            public static string EncryptString(string plainText, string key, string iv)
            {
                if (key.Length != 32) throw new ArgumentException("Key must be 32 characters long.");
                if (iv.Length != 16) throw new ArgumentException("IV must be 16 characters long.");

                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv);

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置为 ECB 模式
                    aes.Padding = PaddingMode.None; // 设置填充模式
                    aes.Key = keyBytes;
                    aes.IV = ivBytes; // 在 ECB 模式下，IV 不会被使用，但仍需提供

                    var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                    var plainBytes = Encoding.UTF8.GetBytes(plainText);

                    using (var ms = new MemoryStream())
                    {
                        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            cs.Write(plainBytes, 0, plainBytes.Length);
                            cs.FlushFinalBlock();
                        }

                        return Convert.ToBase64String(ms.ToArray());
                    }
                }
            }

            /// <summary>
            /// Decrypts an encrypted string using AES decryption with ECB mode.<br></br>
            /// 使用 ECB 模式的 AES 解密对加密字符串进行解密。
            /// </summary>
            /// <param name="cipherText">The encrypted string in Base64 format to decrypt.<br></br>要解密的以 Base64 格式加密的字符串。</param>
            /// <param name="key">The decryption key, must be 32 characters long.<br></br>解密密钥，必须为 32 个字符长。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被使用，但仍需提供。</param>
            /// <returns>The decrypted plain text string.<br></br>解密后的纯文本字符串。</returns>
            /// <remarks>
            /// This method uses AES decryption in ECB mode.<br></br>Note: ECB mode is not recommended for secure decryption as it does not use an initialization vector and has certain security vulnerabilities.<br></br>
            /// 该方法使用 ECB 模式的 AES 解密。<br></br>注意：ECB 模式不建议用于安全解密，因为它不使用初始化向量，并且具有某些安全漏洞。
            /// </remarks>
            public static string DecryptString(string cipherText, string key, string iv)
            {
                if (key.Length != 32) throw new ArgumentException("Key must be 32 characters long.");
                if (iv.Length != 16) throw new ArgumentException("IV must be 16 characters long.");

                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv);

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置为 ECB 模式
                    aes.Padding = PaddingMode.None; // 设置填充模式
                    aes.Key = keyBytes;
                    aes.IV = ivBytes; // 在 ECB 模式下，IV 不会被使用，但仍需提供

                    var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    var cipherBytes = Convert.FromBase64String(cipherText);

                    using (var ms = new MemoryStream(cipherBytes))
                    {
                        using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                        {
                            using (var reader = new StreamReader(cs))
                            {
                                return reader.ReadToEnd();
                            }
                        }
                    }
                }
            }

            /// <summary>
            /// Encrypts a plain text string to a byte array using AES encryption with ECB mode.<br></br>
            /// 使用 ECB 模式的 AES 加密将纯文本字符串加密为字节数组。
            /// </summary>
            /// <param name="plainText">The plain text string to encrypt.<br></br>要加密的纯文本字符串。</param>
            /// <param name="key">The encryption key, must be 32 characters long.<br></br>加密密钥，必须为 32 个字符长。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被使用，但仍需提供。</param>
            /// <returns>The encrypted data as a byte array.<br></br>以字节数组形式返回的加密数据。</returns>
            /// <remarks>
            /// This method uses AES encryption in ECB mode.<br></br>Note: ECB mode is not recommended for secure encryption as it does not use an initialization vector and has certain security vulnerabilities.<br></br>
            /// 该方法使用 ECB 模式的 AES 加密。<br></br>注意：ECB 模式不建议用于安全加密，因为它不使用初始化向量，并且具有某些安全漏洞。
            /// </remarks>
            public static byte[] EncryptStringToBytes(string plainText, string key, string iv)
            {
                if (key.Length != 32) throw new ArgumentException("Key must be 32 characters long.");
                if (iv.Length != 16) throw new ArgumentException("IV must be 16 characters long.");

                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv);

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB;
                    aes.Padding = PaddingMode.None;
                    aes.Key = keyBytes;
                    aes.IV = ivBytes; // 在 ECB 模式下，IV 不会被使用，但仍需提供

                    var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
                    var plainBytes = Encoding.UTF8.GetBytes(plainText);

                    using (var ms = new MemoryStream())
                    {
                        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            cs.Write(plainBytes, 0, plainBytes.Length);
                            cs.FlushFinalBlock();
                        }
                        return ms.ToArray();
                    }
                }
            }

            /// <summary>
            /// Decrypts a byte array to a plain text string using AES decryption with ECB mode.<br></br>
            /// 使用 ECB 模式的 AES 解密将字节数组解密为纯文本字符串。
            /// </summary>
            /// <param name="cipherBytes">The encrypted data as a byte array to decrypt.<br></br>要解密的以字节数组形式的加密数据。</param>
            /// <param name="key">The decryption key, must be 32 characters long.<br></br>解密密钥，必须为 32 个字符长。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被使用，但仍需提供。</param>
            /// <returns>The decrypted plain text string.<br></br>解密后的纯文本字符串。</returns>
            /// <remarks>
            /// This method uses AES decryption in ECB mode.<br></br>Note: ECB mode is not recommended for secure decryption as it does not use an initialization vector and has certain security vulnerabilities.<br></br>
            /// 该方法使用 ECB 模式的 AES 解密。<br></br>注意：ECB 模式不建议用于安全解密，因为它不使用初始化向量，并且具有某些安全漏洞。
            /// </remarks>
            public static string DecryptBytesToString(byte[] cipherBytes, string key, string iv)
            {
                if (key.Length != 32) throw new ArgumentException("Key must be 32 characters long.");
                if (iv.Length != 16) throw new ArgumentException("IV must be 16 characters long.");

                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv);

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB;
                    aes.Padding = PaddingMode.None;
                    aes.Key = keyBytes;
                    aes.IV = ivBytes; // 在 ECB 模式下，IV 不会被使用，但仍需提供

                    var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    using (var ms = new MemoryStream(cipherBytes))
                    {
                        using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                        {
                            using (var reader = new StreamReader(cs, Encoding.UTF8))
                            {
                                return reader.ReadToEnd();
                            }
                        }
                    }
                }
            }

            /// <summary>
            /// Encrypts a byte array to a Base64-encoded string using AES encryption with ECB mode.<br></br>
            /// 使用 ECB 模式的 AES 加密将字节数组加密为 Base64 编码的字符串。
            /// </summary>
            /// <param name="data">The byte array to encrypt.<br></br>要加密的字节数组。</param>
            /// <param name="key">The encryption key, must be 32 characters long.<br></br>加密密钥，必须为 32 个字符长。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被实际使用，但仍需提供。</param>
            /// <returns>The encrypted data as a Base64-encoded string.<br></br>以 Base64 编码的字符串形式返回的加密数据。</returns>
            /// <remarks>
            /// This method uses AES encryption in ECB mode.<br></br>Note: ECB mode is not recommended for secure encryption as it does not use an initialization vector and has certain security vulnerabilities.<br></br>
            /// 该方法使用 ECB 模式的 AES 加密。<br></br>注意：ECB 模式不建议用于安全加密，因为它不使用初始化向量，并且具有某些安全漏洞。
            /// </remarks>
            public static string EncryptBytesToString(byte[] data, string key, string iv)
            {
                // 检查密钥长度，AES-256 需要 32 字节的密钥
                if (key.Length != 32) throw new ArgumentException("密钥必须为32个字符长。");
                // 检查初始化向量长度，虽然在 ECB 模式下不使用 IV，但仍需传递
                if (iv.Length != 16) throw new ArgumentException("IV必须为16个字符长。");

                // 将密钥和初始化向量从字符串转换为字节数组
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv); // 在 ECB 模式下，IV 不会被实际使用

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置加密模式为 ECB
                    aes.Padding = PaddingMode.None; // 设置填充模式为 None
                    aes.Key = keyBytes; // 设置密钥
                    aes.IV = ivBytes; // 设置 IV（虽然 ECB 模式下 IV 不实际使用）

                    // 创建加密器
                    var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                    using (var ms = new MemoryStream())
                    {
                        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            // 写入待加密的字节数据
                            cs.Write(data, 0, data.Length);
                            cs.FlushFinalBlock(); // 完成加密
                        }
                        // 将加密后的字节数据转换为 Base64 编码的字符串并返回
                        return Convert.ToBase64String(ms.ToArray());
                    }
                }
            }

            /// <summary>
            /// Decrypts a Base64-encoded string to a byte array using AES decryption with ECB mode.<br></br>
            /// 使用 ECB 模式的 AES 解密将 Base64 编码的字符串解密为字节数组。
            /// </summary>
            /// <param name="cipherText">The Base64-encoded string to decrypt.<br></br>要解密的 Base64 编码的字符串。</param>
            /// <param name="key">The decryption key, must be 32 characters long.<br></br>解密密钥，必须为 32 个字符长。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被实际使用，但仍需提供。</param>
            /// <returns>The decrypted data as a byte array.<br></br>解密后的字节数组。</returns>
            /// <remarks>
            /// This method uses AES decryption in ECB mode.<br></br>Note: ECB mode is not recommended for secure decryption as it does not use an initialization vector and has certain security vulnerabilities.<br></br>
            /// 该方法使用 ECB 模式的 AES 解密。<br></br>注意：ECB 模式不建议用于安全解密，因为它不使用初始化向量，并且具有某些安全漏洞。
            /// </remarks>
            public static byte[] DecryptStringToBytes(string cipherText, string key, string iv)
            {
                // 检查密钥长度，AES-256 需要 32 字节的密钥
                if (key.Length != 32) throw new ArgumentException("密钥必须为32个字符长。");
                // 检查初始化向量长度，虽然在 ECB 模式下不使用 IV，但仍需传递
                if (iv.Length != 16) throw new ArgumentException("IV必须为16个字符长。");

                // 将密钥和初始化向量从字符串转换为字节数组
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv); // 在 ECB 模式下，IV 不会被实际使用

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置解密模式为 ECB
                    aes.Padding = PaddingMode.None; // 设置填充模式为 None
                    aes.Key = keyBytes; // 设置密钥
                    aes.IV = ivBytes; // 设置 IV（虽然 ECB 模式下 IV 不实际使用）

                    // 创建解密器
                    var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    // 将 Base64 编码的字符串转换为字节数组
                    var cipherBytes = Convert.FromBase64String(cipherText);

                    using (var ms = new MemoryStream(cipherBytes))
                    {
                        using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                        {
                            using (var output = new MemoryStream())
                            {
                                // 读取解密后的字节数据
                                cs.CopyTo(output);
                                return output.ToArray();
                            }
                        }
                    }
                }
            }

            /// <summary>
            /// Encrypts a byte array using AES encryption with ECB mode and returns the encrypted data as a byte array.
            /// 使用 ECB 模式的 AES 加密加密字节数组，并以字节数组的形式返回加密后的数据。
            /// </summary>
            /// <param name="data">The byte array to encrypt.<br></br>要加密的字节数组。</param>
            /// <param name="key">The encryption key, must be 32 characters long. It will be converted to a byte array.<br></br>加密密钥，必须为 32 个字符长。将被转换为字节数组。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被实际使用，但仍需提供。</param>
            /// <returns>The encrypted data as a byte array.<br></br>以字节数组形式返回的加密数据。</returns>
            /// <remarks>
            /// This method uses AES encryption in ECB mode.<br></br>Note: ECB mode is not recommended for secure encryption as it does not use an initialization vector and may expose patterns in the plaintext.<br></br>
            /// 该方法使用 ECB 模式的 AES 加密。<br></br>注意：ECB 模式不建议用于安全加密，因为它不使用初始化向量，并可能暴露明文中的模式。
            /// </remarks>
            public static byte[] EncryptBytes(byte[] data, string key, string iv)
            {
                // 确保密钥长度为32字节（256位），AES-256加密需要此长度
                if (key.Length != 32) throw new ArgumentException("密钥必须是32个字符长。");
                // 确保IV长度为16字节（128位），虽然ECB模式下不实际使用IV
                if (iv.Length != 16) throw new ArgumentException("IV必须是16个字符长。");

                // 将密钥和IV从字符串转换为字节数组
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv); // 在ECB模式下IV不会被实际使用

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置为ECB模式
                    aes.Padding = PaddingMode.None; // 设置为None填充模式
                    aes.Key = keyBytes; // 设置密钥
                    aes.IV = ivBytes; // 设置IV（在ECB模式下不实际使用）

                    // 创建加密器
                    var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                    using (var ms = new MemoryStream())
                    {
                        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            // 将数据写入CryptoStream以进行加密
                            cs.Write(data, 0, data.Length);
                            cs.FlushFinalBlock(); // 确保所有数据都已写入
                        }
                        // 返回加密后的字节数组
                        return ms.ToArray();
                    }
                }
            }

            /// <summary>
            /// Decrypts a byte array using AES decryption with ECB mode and returns the decrypted data as a byte array.
            /// 使用 ECB 模式的 AES 解密解密字节数组，并以字节数组的形式返回解密后的数据。
            /// </summary>
            /// <param name="cipherData">The byte array containing the encrypted data.<br></br>包含加密数据的字节数组。</param>
            /// <param name="key">The decryption key, must be 32 characters long. It will be converted to a byte array.<br></br>解密密钥，必须为 32 个字符长。将被转换为字节数组。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被实际使用，但仍需提供。</param>
            /// <returns>The decrypted data as a byte array.<br></br>以字节数组形式返回的解密数据。</returns>
            /// <remarks>
            /// This method uses AES decryption in ECB mode.<br></br>Note: ECB mode is not recommended for secure decryption as it does not use an initialization vector and may expose patterns in the ciphertext.<br></br>
            /// 该方法使用 ECB 模式的 AES 解密。<br></br>注意：ECB 模式不建议用于安全解密，因为它不使用初始化向量，并可能暴露密文中的模式。
            /// </remarks>
            public static byte[] DecryptBytes(byte[] cipherData, string key, string iv)
            {
                // 确保密钥长度为32字节（256位），AES-256解密需要此长度
                if (key.Length != 32) throw new ArgumentException("密钥必须是32个字符长。");
                // 确保IV长度为16字节（128位），虽然ECB模式下不实际使用IV
                if (iv.Length != 16) throw new ArgumentException("IV必须是16个字符长。");

                // 将密钥和IV从字符串转换为字节数组
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv); // 在ECB模式下IV不会被实际使用

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置为ECB模式
                    aes.Padding = PaddingMode.None; // 设置为None填充模式
                    aes.Key = keyBytes; // 设置密钥
                    aes.IV = ivBytes; // 设置IV（在ECB模式下不实际使用）

                    // 创建解密器
                    var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    using (var ms = new MemoryStream(cipherData))
                    {
                        using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                        {
                            using (var output = new MemoryStream())
                            {
                                // 从CryptoStream读取解密后的数据
                                cs.CopyTo(output);
                                // 返回解密后的字节数组
                                return output.ToArray();
                            }
                        }
                    }
                }
            }

            /// <summary>
            /// Encrypts a file using AES encryption in ECB mode and writes the encrypted data to an output file.
            /// 使用 ECB 模式的 AES 加密加密文件，并将加密后的数据写入输出文件。
            /// </summary>
            /// <param name="inputFilePath">The path to the input file that will be encrypted.<br></br>要加密的输入文件的路径。</param>
            /// <param name="outputFilePath">The path to the output file where the encrypted data will be saved.<br></br>加密数据将保存到的输出文件的路径。</param>
            /// <param name="key">The encryption key, must be 32 characters long. It will be converted to a byte array.<br></br>加密密钥，必须为 32 个字符长。将被转换为字节数组。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被实际使用，但仍需提供。</param>
            /// <exception cref="ArgumentException">Thrown when the key or IV is of incorrect length.<br></br>当密钥或 IV 长度不正确时抛出。</exception>
            /// <remarks>
            /// This method uses AES encryption in ECB mode, which does not use the IV and is not recommended for secure encryption due to potential security vulnerabilities.<br></br>Note: ECB mode can expose patterns in the plaintext.<br></br>该方法使用 ECB 模式的 AES 加密，不使用 IV，并且由于潜在的安全漏洞，不建议用于安全加密。<br></br>注意：ECB 模式可能暴露明文中的模式。
            /// </remarks>
            public static void EncryptFile(string inputFilePath, string outputFilePath, string key, string iv)
            {
                // 检查密钥长度，AES-256需要32字节的密钥
                if (key.Length != 32) throw new ArgumentException("密钥必须是32个字符长。");
                // 检查IV长度，虽然ECB模式下不使用IV，但仍需传递
                if (iv.Length != 16) throw new ArgumentException("IV必须是16个字符长。");

                // 将密钥和IV从字符串转换为字节数组
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv); // 在ECB模式下IV不会被实际使用

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置为ECB模式
                    aes.Padding = PaddingMode.None; // 设置为None填充模式
                    aes.Key = keyBytes; // 设置密钥
                    aes.IV = ivBytes; // 设置IV（在ECB模式下不实际使用）

                    // 创建加密器
                    var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                    using (var inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                    using (var outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    using (var cryptoStream = new CryptoStream(outputFileStream, encryptor, CryptoStreamMode.Write))
                    {
                        // 加密文件内容
                        inputFileStream.CopyTo(cryptoStream);
                        cryptoStream.FlushFinalBlock(); // 确保所有数据都已加密
                    }
                }
            }

            /// <summary>
            /// Decrypts a file using AES decryption in ECB mode and writes the decrypted data to an output file.
            /// 使用 ECB 模式的 AES 解密解密文件，并将解密后的数据写入输出文件。
            /// </summary>
            /// <param name="inputFilePath">The path to the input file that contains the encrypted data.<br></br>包含加密数据的输入文件的路径。</param>
            /// <param name="outputFilePath">The path to the output file where the decrypted data will be saved.<br></br>解密数据将保存到的输出文件的路径。</param>
            /// <param name="key">The decryption key, must be 32 characters long. It will be converted to a byte array.<br></br>解密密钥，必须为 32 个字符长。将被转换为字节数组。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被实际使用，但仍需提供。</param>
            /// <exception cref="ArgumentException">Thrown when the key or IV is of incorrect length.<br></br>当密钥或 IV 长度不正确时抛出。</exception>
            /// <remarks>
            /// This method uses AES decryption in ECB mode, which does not use the IV and is not recommended for secure decryption due to potential security vulnerabilities.<br></br>Note: ECB mode can expose patterns in the ciphertext.<br></br>该方法使用 ECB 模式的 AES 解密，不使用 IV，并且由于潜在的安全漏洞，不建议用于安全解密。<br></br>注意：ECB 模式可能暴露密文中的模式。
            /// </remarks>
            public static void DecryptFile(string inputFilePath, string outputFilePath, string key, string iv)
            {
                // 检查密钥长度，AES-256需要32字节的密钥
                if (key.Length != 32) throw new ArgumentException("密钥必须是32个字符长。");
                // 检查IV长度，虽然ECB模式下不使用IV，但仍需传递
                if (iv.Length != 16) throw new ArgumentException("IV必须是16个字符长。");

                // 将密钥和IV从字符串转换为字节数组
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv); // 在ECB模式下IV不会被实际使用

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置为ECB模式
                    aes.Padding = PaddingMode.None; // 设置为None填充模式
                    aes.Key = keyBytes; // 设置密钥
                    aes.IV = ivBytes; // 设置IV（在ECB模式下不实际使用）

                    // 创建解密器
                    var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    using (var inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                    using (var outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    using (var cryptoStream = new CryptoStream(outputFileStream, decryptor, CryptoStreamMode.Write))
                    {
                        // 解密文件内容
                        inputFileStream.CopyTo(cryptoStream);
                        cryptoStream.FlushFinalBlock(); // 确保所有数据都已解密
                    }
                }
            }

            /// <summary>
            /// Encrypts a file and returns the encrypted data as a byte array.
            /// 加密文件并返回加密数据的字节数组。
            /// </summary>
            /// <param name="inputFilePath">The path to the input file that will be encrypted.<br></br>要加密的输入文件的路径。</param>
            /// <param name="key">The encryption key, must be 32 characters long. It will be converted to a byte array.<br></br>加密密钥，必须为 32 个字符长。将被转换为字节数组。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被实际使用，但仍需提供。</param>
            /// <returns>A byte array containing the encrypted data.<br></br>包含加密数据的字节数组。</returns>
            /// <exception cref="ArgumentException">Thrown when the key or IV is of incorrect length.<br></br>当密钥或 IV 长度不正确时抛出。</exception>
            /// <remarks>
            /// This method uses AES encryption in ECB mode, which does not use the IV and is not recommended for secure encryption due to potential security vulnerabilities.<br></br>Note: ECB mode can expose patterns in the plaintext.<br></br>该方法使用 ECB 模式的 AES 加密，不使用 IV，并且由于潜在的安全漏洞，不建议用于安全加密。<br></br>注意：ECB 模式可能暴露明文中的模式。
            /// </remarks>
            public static byte[] EncryptFileToBytes(string inputFilePath, string key, string iv)
            {
                // 确保密钥长度为32字节（256位），AES-256需要此长度
                if (key.Length != 32) throw new ArgumentException("密钥必须是32个字符长。");
                // 确保IV长度为16字节（128位），虽然ECB模式下不实际使用IV
                if (iv.Length != 16) throw new ArgumentException("IV必须是16个字符长。");

                // 将密钥和IV从字符串转换为字节数组
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv); // 在ECB模式下IV不会被实际使用

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置为ECB模式
                    aes.Padding = PaddingMode.None; // 设置为None填充模式
                    aes.Key = keyBytes; // 设置密钥
                    aes.IV = ivBytes; // 设置IV（在ECB模式下不实际使用）

                    // 创建加密器
                    var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                    using (var inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                    using (var ms = new MemoryStream())
                    using (var cryptoStream = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        // 将文件内容复制到CryptoStream进行加密
                        inputFileStream.CopyTo(cryptoStream);
                        cryptoStream.FlushFinalBlock(); // 确保所有数据都已加密

                        // 返回加密后的字节数组
                        return ms.ToArray();
                    }
                }
            }

            /// <summary>
            /// Decrypts a byte array containing encrypted data and returns the decrypted data as a byte array.
            /// 解密包含加密数据的字节数组，并返回解密后的数据的字节数组。
            /// </summary>
            /// <param name="cipherData">The byte array containing the encrypted data.<br></br>包含加密数据的字节数组。</param>
            /// <param name="key">The decryption key, must be 32 characters long. It will be converted to a byte array.<br></br>解密密钥，必须为 32 个字符长。将被转换为字节数组。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被实际使用，但仍需提供。</param>
            /// <returns>A byte array containing the decrypted data.<br></br>包含解密数据的字节数组。</returns>
            /// <exception cref="ArgumentException">Thrown when the key or IV is of incorrect length.<br></br>当密钥或 IV 长度不正确时抛出。</exception>
            /// <remarks>
            /// This method uses AES decryption in ECB mode, which does not use the IV and is not recommended for secure decryption due to potential security vulnerabilities.<br></br>Note: ECB mode can expose patterns in the ciphertext.<br></br>该方法使用 ECB 模式的 AES 解密，不使用 IV，并且由于潜在的安全漏洞，不建议用于安全解密。<br></br>注意：ECB 模式可能暴露密文中的模式。
            /// </remarks>
            public static byte[] DecryptBytesToFile(byte[] cipherData, string key, string iv)
            {
                // 确保密钥长度为32字节（256位），AES-256需要此长度
                if (key.Length != 32) throw new ArgumentException("密钥必须是32个字符长。");
                // 确保IV长度为16字节（128位），虽然ECB模式下不实际使用IV
                if (iv.Length != 16) throw new ArgumentException("IV必须是16个字符长。");

                // 将密钥和IV从字符串转换为字节数组
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv); // 在ECB模式下IV不会被实际使用

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置为ECB模式
                    aes.Padding = PaddingMode.None; // 设置为None填充模式
                    aes.Key = keyBytes; // 设置密钥
                    aes.IV = ivBytes; // 设置IV（在ECB模式下不实际使用）

                    // 创建解密器
                    var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    using (var ms = new MemoryStream(cipherData))
                    using (var cryptoStream = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    using (var output = new MemoryStream())
                    {
                        // 从CryptoStream读取解密后的数据
                        cryptoStream.CopyTo(output);
                        // 返回解密后的字节数组
                        return output.ToArray();
                    }
                }
            }

            /// <summary>
            /// Encrypts the given byte array and writes the encrypted data to a file.
            /// 加密给定的字节数组，并将加密后的数据写入文件。
            /// </summary>
            /// <param name="data">The byte array containing the data to encrypt.<br></br>包含要加密的数据的字节数组。</param>
            /// <param name="outputFilePath">The path to the output file where the encrypted data will be written.<br></br>加密数据将被写入的输出文件路径。</param>
            /// <param name="key">The encryption key, must be 32 characters long. This key will be converted to a byte array.<br></br>加密密钥，必须为 32 个字符长。该密钥将被转换为字节数组。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被实际使用，但仍需提供。</param>
            /// <exception cref="ArgumentException">Thrown when the key or IV is of incorrect length.<br></br>当密钥或 IV 长度不正确时抛出。</exception>
            /// <remarks>
            /// This method uses AES encryption in ECB mode. Note that ECB mode does not use the IV and is generally not recommended for secure encryption due to its vulnerability to certain attacks.<br></br>该方法使用 ECB 模式的 AES 加密。注意，ECB 模式不使用 IV，并且通常不建议用于安全加密，因为它容易受到某些攻击。
            /// </remarks>
            public static void EncryptBytesToFile(byte[] data, string outputFilePath, string key, string iv)
            {
                // 确保密钥长度为32字节（256位），AES-256需要此长度
                if (key.Length != 32) throw new ArgumentException("密钥必须是32个字符长。");
                // 确保IV长度为16字节（128位），虽然ECB模式下IV不会被实际使用
                if (iv.Length != 16) throw new ArgumentException("IV必须是16个字符长。");

                // 将密钥和IV从字符串转换为字节数组
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv); // 在ECB模式下IV不会被实际使用

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置为ECB模式
                    aes.Padding = PaddingMode.None; // 设置为None填充模式
                    aes.Key = keyBytes; // 设置密钥
                    aes.IV = ivBytes; // 设置IV（在ECB模式下不实际使用）

                    // 创建加密器
                    var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                    using (var outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    using (var cryptoStream = new CryptoStream(outputFileStream, encryptor, CryptoStreamMode.Write))
                    {
                        // 将数据写入CryptoStream进行加密
                        cryptoStream.Write(data, 0, data.Length);
                        cryptoStream.FlushFinalBlock(); // 确保所有数据都已加密
                    }
                }
            }

            /// <summary>
            /// Decrypts the data from a file and returns the decrypted byte array.
            /// 从文件中解密数据并返回解密后的字节数组。
            /// </summary>
            /// <param name="inputFilePath">The path to the input file containing the encrypted data.<br></br>包含加密数据的输入文件路径。</param>
            /// <param name="key">The decryption key, must be 32 characters long. This key will be converted to a byte array.<br></br>解密密钥，必须为 32 个字符长。该密钥将被转换为字节数组。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被实际使用，但仍需提供。</param>
            /// <returns>A byte array containing the decrypted data.<br></br>包含解密数据的字节数组。</returns>
            /// <exception cref="ArgumentException">Thrown when the key or IV is of incorrect length.<br></br>当密钥或 IV 长度不正确时抛出。</exception>
            /// <remarks>
            /// This method uses AES decryption in ECB mode. Note that ECB mode does not use the IV and is generally not recommended for secure decryption due to its vulnerability to certain attacks.<br></br>该方法使用 ECB 模式的 AES 解密。注意，ECB 模式不使用 IV，并且通常不建议用于安全解密，因为它容易受到某些攻击。
            /// </remarks>
            public static byte[] DecryptFileToBytes(string inputFilePath, string key, string iv)
            {
                // 确保密钥长度为32字节（256位），AES-256需要此长度
                if (key.Length != 32) throw new ArgumentException("密钥必须是32个字符长。");
                // 确保IV长度为16字节（128位），虽然ECB模式下IV不会被实际使用
                if (iv.Length != 16) throw new ArgumentException("IV必须是16个字符长。");

                // 将密钥和IV从字符串转换为字节数组
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv); // 在ECB模式下IV不会被实际使用

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置为ECB模式
                    aes.Padding = PaddingMode.None; // 设置为None填充模式
                    aes.Key = keyBytes; // 设置密钥
                    aes.IV = ivBytes; // 设置IV（在ECB模式下不实际使用）

                    // 创建解密器
                    var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    using (var inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                    using (var cryptoStream = new CryptoStream(inputFileStream, decryptor, CryptoStreamMode.Read))
                    using (var ms = new MemoryStream())
                    {
                        // 从CryptoStream读取解密后的数据
                        cryptoStream.CopyTo(ms);
                        // 返回解密后的字节数组
                        return ms.ToArray();
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
            /// Encrypts a plain text string using AES encryption with ECB mode.<br></br>
            /// 使用 ECB 模式的 AES 加密对纯文本字符串进行加密。
            /// </summary>
            /// <param name="plainText">The plain text string to encrypt.<br></br>要加密的纯文本字符串。</param>
            /// <param name="key">The encryption key, must be 32 characters long.<br></br>加密密钥，必须为 32 个字符长。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被使用，但仍需提供。</param>
            /// <returns>The encrypted string in Base64 format.<br></br>以 Base64 格式返回的加密字符串。</returns>
            /// <remarks>
            /// This method uses AES encryption in ECB mode.<br></br>Note: ECB mode is not recommended for secure encryption as it does not use an initialization vector and has certain security vulnerabilities.<br></br>
            /// 该方法使用 ECB 模式的 AES 加密。<br></br>注意：ECB 模式不建议用于安全加密，因为它不使用初始化向量，并且具有某些安全漏洞。
            /// </remarks>
            public static string EncryptString(string plainText, string key, string iv)
            {
                if (key.Length != 32) throw new ArgumentException("Key must be 32 characters long.");
                if (iv.Length != 16) throw new ArgumentException("IV must be 16 characters long.");

                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv);

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置为 ECB 模式
                    aes.Padding = PaddingMode.Zeros; // 设置填充模式
                    aes.Key = keyBytes;
                    aes.IV = ivBytes; // 在 ECB 模式下，IV 不会被使用，但仍需提供

                    var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                    var plainBytes = Encoding.UTF8.GetBytes(plainText);

                    using (var ms = new MemoryStream())
                    {
                        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            cs.Write(plainBytes, 0, plainBytes.Length);
                            cs.FlushFinalBlock();
                        }

                        return Convert.ToBase64String(ms.ToArray());
                    }
                }
            }

            /// <summary>
            /// Decrypts an encrypted string using AES decryption with ECB mode.<br></br>
            /// 使用 ECB 模式的 AES 解密对加密字符串进行解密。
            /// </summary>
            /// <param name="cipherText">The encrypted string in Base64 format to decrypt.<br></br>要解密的以 Base64 格式加密的字符串。</param>
            /// <param name="key">The decryption key, must be 32 characters long.<br></br>解密密钥，必须为 32 个字符长。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被使用，但仍需提供。</param>
            /// <returns>The decrypted plain text string.<br></br>解密后的纯文本字符串。</returns>
            /// <remarks>
            /// This method uses AES decryption in ECB mode.<br></br>Note: ECB mode is not recommended for secure decryption as it does not use an initialization vector and has certain security vulnerabilities.<br></br>
            /// 该方法使用 ECB 模式的 AES 解密。<br></br>注意：ECB 模式不建议用于安全解密，因为它不使用初始化向量，并且具有某些安全漏洞。
            /// </remarks>
            public static string DecryptString(string cipherText, string key, string iv)
            {
                if (key.Length != 32) throw new ArgumentException("Key must be 32 characters long.");
                if (iv.Length != 16) throw new ArgumentException("IV must be 16 characters long.");

                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv);

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置为 ECB 模式
                    aes.Padding = PaddingMode.Zeros; // 设置填充模式
                    aes.Key = keyBytes;
                    aes.IV = ivBytes; // 在 ECB 模式下，IV 不会被使用，但仍需提供

                    var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    var cipherBytes = Convert.FromBase64String(cipherText);

                    using (var ms = new MemoryStream(cipherBytes))
                    {
                        using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                        {
                            using (var reader = new StreamReader(cs))
                            {
                                return reader.ReadToEnd();
                            }
                        }
                    }
                }
            }

            /// <summary>
            /// Encrypts a plain text string to a byte array using AES encryption with ECB mode.<br></br>
            /// 使用 ECB 模式的 AES 加密将纯文本字符串加密为字节数组。
            /// </summary>
            /// <param name="plainText">The plain text string to encrypt.<br></br>要加密的纯文本字符串。</param>
            /// <param name="key">The encryption key, must be 32 characters long.<br></br>加密密钥，必须为 32 个字符长。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被使用，但仍需提供。</param>
            /// <returns>The encrypted data as a byte array.<br></br>以字节数组形式返回的加密数据。</returns>
            /// <remarks>
            /// This method uses AES encryption in ECB mode.<br></br>Note: ECB mode is not recommended for secure encryption as it does not use an initialization vector and has certain security vulnerabilities.<br></br>
            /// 该方法使用 ECB 模式的 AES 加密。<br></br>注意：ECB 模式不建议用于安全加密，因为它不使用初始化向量，并且具有某些安全漏洞。
            /// </remarks>
            public static byte[] EncryptStringToBytes(string plainText, string key, string iv)
            {
                if (key.Length != 32) throw new ArgumentException("Key must be 32 characters long.");
                if (iv.Length != 16) throw new ArgumentException("IV must be 16 characters long.");

                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv);

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB;
                    aes.Padding = PaddingMode.Zeros;
                    aes.Key = keyBytes;
                    aes.IV = ivBytes; // 在 ECB 模式下，IV 不会被使用，但仍需提供

                    var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
                    var plainBytes = Encoding.UTF8.GetBytes(plainText);

                    using (var ms = new MemoryStream())
                    {
                        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            cs.Write(plainBytes, 0, plainBytes.Length);
                            cs.FlushFinalBlock();
                        }
                        return ms.ToArray();
                    }
                }
            }

            /// <summary>
            /// Decrypts a byte array to a plain text string using AES decryption with ECB mode.<br></br>
            /// 使用 ECB 模式的 AES 解密将字节数组解密为纯文本字符串。
            /// </summary>
            /// <param name="cipherBytes">The encrypted data as a byte array to decrypt.<br></br>要解密的以字节数组形式的加密数据。</param>
            /// <param name="key">The decryption key, must be 32 characters long.<br></br>解密密钥，必须为 32 个字符长。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被使用，但仍需提供。</param>
            /// <returns>The decrypted plain text string.<br></br>解密后的纯文本字符串。</returns>
            /// <remarks>
            /// This method uses AES decryption in ECB mode.<br></br>Note: ECB mode is not recommended for secure decryption as it does not use an initialization vector and has certain security vulnerabilities.<br></br>
            /// 该方法使用 ECB 模式的 AES 解密。<br></br>注意：ECB 模式不建议用于安全解密，因为它不使用初始化向量，并且具有某些安全漏洞。
            /// </remarks>
            public static string DecryptBytesToString(byte[] cipherBytes, string key, string iv)
            {
                if (key.Length != 32) throw new ArgumentException("Key must be 32 characters long.");
                if (iv.Length != 16) throw new ArgumentException("IV must be 16 characters long.");

                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv);

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB;
                    aes.Padding = PaddingMode.Zeros;
                    aes.Key = keyBytes;
                    aes.IV = ivBytes; // 在 ECB 模式下，IV 不会被使用，但仍需提供

                    var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    using (var ms = new MemoryStream(cipherBytes))
                    {
                        using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                        {
                            using (var reader = new StreamReader(cs, Encoding.UTF8))
                            {
                                return reader.ReadToEnd();
                            }
                        }
                    }
                }
            }

            /// <summary>
            /// Encrypts a byte array to a Base64-encoded string using AES encryption with ECB mode.<br></br>
            /// 使用 ECB 模式的 AES 加密将字节数组加密为 Base64 编码的字符串。
            /// </summary>
            /// <param name="data">The byte array to encrypt.<br></br>要加密的字节数组。</param>
            /// <param name="key">The encryption key, must be 32 characters long.<br></br>加密密钥，必须为 32 个字符长。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被实际使用，但仍需提供。</param>
            /// <returns>The encrypted data as a Base64-encoded string.<br></br>以 Base64 编码的字符串形式返回的加密数据。</returns>
            /// <remarks>
            /// This method uses AES encryption in ECB mode.<br></br>Note: ECB mode is not recommended for secure encryption as it does not use an initialization vector and has certain security vulnerabilities.<br></br>
            /// 该方法使用 ECB 模式的 AES 加密。<br></br>注意：ECB 模式不建议用于安全加密，因为它不使用初始化向量，并且具有某些安全漏洞。
            /// </remarks>
            public static string EncryptBytesToString(byte[] data, string key, string iv)
            {
                // 检查密钥长度，AES-256 需要 32 字节的密钥
                if (key.Length != 32) throw new ArgumentException("密钥必须为32个字符长。");
                // 检查初始化向量长度，虽然在 ECB 模式下不使用 IV，但仍需传递
                if (iv.Length != 16) throw new ArgumentException("IV必须为16个字符长。");

                // 将密钥和初始化向量从字符串转换为字节数组
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv); // 在 ECB 模式下，IV 不会被实际使用

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置加密模式为 ECB
                    aes.Padding = PaddingMode.Zeros; // 设置填充模式为 Zeros
                    aes.Key = keyBytes; // 设置密钥
                    aes.IV = ivBytes; // 设置 IV（虽然 ECB 模式下 IV 不实际使用）

                    // 创建加密器
                    var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                    using (var ms = new MemoryStream())
                    {
                        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            // 写入待加密的字节数据
                            cs.Write(data, 0, data.Length);
                            cs.FlushFinalBlock(); // 完成加密
                        }
                        // 将加密后的字节数据转换为 Base64 编码的字符串并返回
                        return Convert.ToBase64String(ms.ToArray());
                    }
                }
            }

            /// <summary>
            /// Decrypts a Base64-encoded string to a byte array using AES decryption with ECB mode.<br></br>
            /// 使用 ECB 模式的 AES 解密将 Base64 编码的字符串解密为字节数组。
            /// </summary>
            /// <param name="cipherText">The Base64-encoded string to decrypt.<br></br>要解密的 Base64 编码的字符串。</param>
            /// <param name="key">The decryption key, must be 32 characters long.<br></br>解密密钥，必须为 32 个字符长。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被实际使用，但仍需提供。</param>
            /// <returns>The decrypted data as a byte array.<br></br>解密后的字节数组。</returns>
            /// <remarks>
            /// This method uses AES decryption in ECB mode.<br></br>Note: ECB mode is not recommended for secure decryption as it does not use an initialization vector and has certain security vulnerabilities.<br></br>
            /// 该方法使用 ECB 模式的 AES 解密。<br></br>注意：ECB 模式不建议用于安全解密，因为它不使用初始化向量，并且具有某些安全漏洞。
            /// </remarks>
            public static byte[] DecryptStringToBytes(string cipherText, string key, string iv)
            {
                // 检查密钥长度，AES-256 需要 32 字节的密钥
                if (key.Length != 32) throw new ArgumentException("密钥必须为32个字符长。");
                // 检查初始化向量长度，虽然在 ECB 模式下不使用 IV，但仍需传递
                if (iv.Length != 16) throw new ArgumentException("IV必须为16个字符长。");

                // 将密钥和初始化向量从字符串转换为字节数组
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv); // 在 ECB 模式下，IV 不会被实际使用

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置解密模式为 ECB
                    aes.Padding = PaddingMode.Zeros; // 设置填充模式为 Zeros
                    aes.Key = keyBytes; // 设置密钥
                    aes.IV = ivBytes; // 设置 IV（虽然 ECB 模式下 IV 不实际使用）

                    // 创建解密器
                    var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    // 将 Base64 编码的字符串转换为字节数组
                    var cipherBytes = Convert.FromBase64String(cipherText);

                    using (var ms = new MemoryStream(cipherBytes))
                    {
                        using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                        {
                            using (var output = new MemoryStream())
                            {
                                // 读取解密后的字节数据
                                cs.CopyTo(output);
                                return output.ToArray();
                            }
                        }
                    }
                }
            }

            /// <summary>
            /// Encrypts a byte array using AES encryption with ECB mode and returns the encrypted data as a byte array.
            /// 使用 ECB 模式的 AES 加密加密字节数组，并以字节数组的形式返回加密后的数据。
            /// </summary>
            /// <param name="data">The byte array to encrypt.<br></br>要加密的字节数组。</param>
            /// <param name="key">The encryption key, must be 32 characters long. It will be converted to a byte array.<br></br>加密密钥，必须为 32 个字符长。将被转换为字节数组。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被实际使用，但仍需提供。</param>
            /// <returns>The encrypted data as a byte array.<br></br>以字节数组形式返回的加密数据。</returns>
            /// <remarks>
            /// This method uses AES encryption in ECB mode.<br></br>Note: ECB mode is not recommended for secure encryption as it does not use an initialization vector and may expose patterns in the plaintext.<br></br>
            /// 该方法使用 ECB 模式的 AES 加密。<br></br>注意：ECB 模式不建议用于安全加密，因为它不使用初始化向量，并可能暴露明文中的模式。
            /// </remarks>
            public static byte[] EncryptBytes(byte[] data, string key, string iv)
            {
                // 确保密钥长度为32字节（256位），AES-256加密需要此长度
                if (key.Length != 32) throw new ArgumentException("密钥必须是32个字符长。");
                // 确保IV长度为16字节（128位），虽然ECB模式下不实际使用IV
                if (iv.Length != 16) throw new ArgumentException("IV必须是16个字符长。");

                // 将密钥和IV从字符串转换为字节数组
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv); // 在ECB模式下IV不会被实际使用

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置为ECB模式
                    aes.Padding = PaddingMode.Zeros; // 设置为Zeros填充模式
                    aes.Key = keyBytes; // 设置密钥
                    aes.IV = ivBytes; // 设置IV（在ECB模式下不实际使用）

                    // 创建加密器
                    var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                    using (var ms = new MemoryStream())
                    {
                        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            // 将数据写入CryptoStream以进行加密
                            cs.Write(data, 0, data.Length);
                            cs.FlushFinalBlock(); // 确保所有数据都已写入
                        }
                        // 返回加密后的字节数组
                        return ms.ToArray();
                    }
                }
            }

            /// <summary>
            /// Decrypts a byte array using AES decryption with ECB mode and returns the decrypted data as a byte array.
            /// 使用 ECB 模式的 AES 解密解密字节数组，并以字节数组的形式返回解密后的数据。
            /// </summary>
            /// <param name="cipherData">The byte array containing the encrypted data.<br></br>包含加密数据的字节数组。</param>
            /// <param name="key">The decryption key, must be 32 characters long. It will be converted to a byte array.<br></br>解密密钥，必须为 32 个字符长。将被转换为字节数组。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被实际使用，但仍需提供。</param>
            /// <returns>The decrypted data as a byte array.<br></br>以字节数组形式返回的解密数据。</returns>
            /// <remarks>
            /// This method uses AES decryption in ECB mode.<br></br>Note: ECB mode is not recommended for secure decryption as it does not use an initialization vector and may expose patterns in the ciphertext.<br></br>
            /// 该方法使用 ECB 模式的 AES 解密。<br></br>注意：ECB 模式不建议用于安全解密，因为它不使用初始化向量，并可能暴露密文中的模式。
            /// </remarks>
            public static byte[] DecryptBytes(byte[] cipherData, string key, string iv)
            {
                // 确保密钥长度为32字节（256位），AES-256解密需要此长度
                if (key.Length != 32) throw new ArgumentException("密钥必须是32个字符长。");
                // 确保IV长度为16字节（128位），虽然ECB模式下不实际使用IV
                if (iv.Length != 16) throw new ArgumentException("IV必须是16个字符长。");

                // 将密钥和IV从字符串转换为字节数组
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv); // 在ECB模式下IV不会被实际使用

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置为ECB模式
                    aes.Padding = PaddingMode.Zeros; // 设置为Zeros填充模式
                    aes.Key = keyBytes; // 设置密钥
                    aes.IV = ivBytes; // 设置IV（在ECB模式下不实际使用）

                    // 创建解密器
                    var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    using (var ms = new MemoryStream(cipherData))
                    {
                        using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                        {
                            using (var output = new MemoryStream())
                            {
                                // 从CryptoStream读取解密后的数据
                                cs.CopyTo(output);
                                // 返回解密后的字节数组
                                return output.ToArray();
                            }
                        }
                    }
                }
            }

            /// <summary>
            /// Encrypts a file using AES encryption in ECB mode and writes the encrypted data to an output file.
            /// 使用 ECB 模式的 AES 加密加密文件，并将加密后的数据写入输出文件。
            /// </summary>
            /// <param name="inputFilePath">The path to the input file that will be encrypted.<br></br>要加密的输入文件的路径。</param>
            /// <param name="outputFilePath">The path to the output file where the encrypted data will be saved.<br></br>加密数据将保存到的输出文件的路径。</param>
            /// <param name="key">The encryption key, must be 32 characters long. It will be converted to a byte array.<br></br>加密密钥，必须为 32 个字符长。将被转换为字节数组。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被实际使用，但仍需提供。</param>
            /// <exception cref="ArgumentException">Thrown when the key or IV is of incorrect length.<br></br>当密钥或 IV 长度不正确时抛出。</exception>
            /// <remarks>
            /// This method uses AES encryption in ECB mode, which does not use the IV and is not recommended for secure encryption due to potential security vulnerabilities.<br></br>Note: ECB mode can expose patterns in the plaintext.<br></br>该方法使用 ECB 模式的 AES 加密，不使用 IV，并且由于潜在的安全漏洞，不建议用于安全加密。<br></br>注意：ECB 模式可能暴露明文中的模式。
            /// </remarks>
            public static void EncryptFile(string inputFilePath, string outputFilePath, string key, string iv)
            {
                // 检查密钥长度，AES-256需要32字节的密钥
                if (key.Length != 32) throw new ArgumentException("密钥必须是32个字符长。");
                // 检查IV长度，虽然ECB模式下不使用IV，但仍需传递
                if (iv.Length != 16) throw new ArgumentException("IV必须是16个字符长。");

                // 将密钥和IV从字符串转换为字节数组
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv); // 在ECB模式下IV不会被实际使用

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置为ECB模式
                    aes.Padding = PaddingMode.Zeros; // 设置为Zeros填充模式
                    aes.Key = keyBytes; // 设置密钥
                    aes.IV = ivBytes; // 设置IV（在ECB模式下不实际使用）

                    // 创建加密器
                    var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                    using (var inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                    using (var outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    using (var cryptoStream = new CryptoStream(outputFileStream, encryptor, CryptoStreamMode.Write))
                    {
                        // 加密文件内容
                        inputFileStream.CopyTo(cryptoStream);
                        cryptoStream.FlushFinalBlock(); // 确保所有数据都已加密
                    }
                }
            }

            /// <summary>
            /// Decrypts a file using AES decryption in ECB mode and writes the decrypted data to an output file.
            /// 使用 ECB 模式的 AES 解密解密文件，并将解密后的数据写入输出文件。
            /// </summary>
            /// <param name="inputFilePath">The path to the input file that contains the encrypted data.<br></br>包含加密数据的输入文件的路径。</param>
            /// <param name="outputFilePath">The path to the output file where the decrypted data will be saved.<br></br>解密数据将保存到的输出文件的路径。</param>
            /// <param name="key">The decryption key, must be 32 characters long. It will be converted to a byte array.<br></br>解密密钥，必须为 32 个字符长。将被转换为字节数组。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被实际使用，但仍需提供。</param>
            /// <exception cref="ArgumentException">Thrown when the key or IV is of incorrect length.<br></br>当密钥或 IV 长度不正确时抛出。</exception>
            /// <remarks>
            /// This method uses AES decryption in ECB mode, which does not use the IV and is not recommended for secure decryption due to potential security vulnerabilities.<br></br>Note: ECB mode can expose patterns in the ciphertext.<br></br>该方法使用 ECB 模式的 AES 解密，不使用 IV，并且由于潜在的安全漏洞，不建议用于安全解密。<br></br>注意：ECB 模式可能暴露密文中的模式。
            /// </remarks>
            public static void DecryptFile(string inputFilePath, string outputFilePath, string key, string iv)
            {
                // 检查密钥长度，AES-256需要32字节的密钥
                if (key.Length != 32) throw new ArgumentException("密钥必须是32个字符长。");
                // 检查IV长度，虽然ECB模式下不使用IV，但仍需传递
                if (iv.Length != 16) throw new ArgumentException("IV必须是16个字符长。");

                // 将密钥和IV从字符串转换为字节数组
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv); // 在ECB模式下IV不会被实际使用

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置为ECB模式
                    aes.Padding = PaddingMode.Zeros; // 设置为Zeros填充模式
                    aes.Key = keyBytes; // 设置密钥
                    aes.IV = ivBytes; // 设置IV（在ECB模式下不实际使用）

                    // 创建解密器
                    var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    using (var inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                    using (var outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    using (var cryptoStream = new CryptoStream(outputFileStream, decryptor, CryptoStreamMode.Write))
                    {
                        // 解密文件内容
                        inputFileStream.CopyTo(cryptoStream);
                        cryptoStream.FlushFinalBlock(); // 确保所有数据都已解密
                    }
                }
            }

            /// <summary>
            /// Encrypts a file and returns the encrypted data as a byte array.
            /// 加密文件并返回加密数据的字节数组。
            /// </summary>
            /// <param name="inputFilePath">The path to the input file that will be encrypted.<br></br>要加密的输入文件的路径。</param>
            /// <param name="key">The encryption key, must be 32 characters long. It will be converted to a byte array.<br></br>加密密钥，必须为 32 个字符长。将被转换为字节数组。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被实际使用，但仍需提供。</param>
            /// <returns>A byte array containing the encrypted data.<br></br>包含加密数据的字节数组。</returns>
            /// <exception cref="ArgumentException">Thrown when the key or IV is of incorrect length.<br></br>当密钥或 IV 长度不正确时抛出。</exception>
            /// <remarks>
            /// This method uses AES encryption in ECB mode, which does not use the IV and is not recommended for secure encryption due to potential security vulnerabilities.<br></br>Note: ECB mode can expose patterns in the plaintext.<br></br>该方法使用 ECB 模式的 AES 加密，不使用 IV，并且由于潜在的安全漏洞，不建议用于安全加密。<br></br>注意：ECB 模式可能暴露明文中的模式。
            /// </remarks>
            public static byte[] EncryptFileToBytes(string inputFilePath, string key, string iv)
            {
                // 确保密钥长度为32字节（256位），AES-256需要此长度
                if (key.Length != 32) throw new ArgumentException("密钥必须是32个字符长。");
                // 确保IV长度为16字节（128位），虽然ECB模式下不实际使用IV
                if (iv.Length != 16) throw new ArgumentException("IV必须是16个字符长。");

                // 将密钥和IV从字符串转换为字节数组
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv); // 在ECB模式下IV不会被实际使用

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置为ECB模式
                    aes.Padding = PaddingMode.Zeros; // 设置为Zeros填充模式
                    aes.Key = keyBytes; // 设置密钥
                    aes.IV = ivBytes; // 设置IV（在ECB模式下不实际使用）

                    // 创建加密器
                    var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                    using (var inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                    using (var ms = new MemoryStream())
                    using (var cryptoStream = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        // 将文件内容复制到CryptoStream进行加密
                        inputFileStream.CopyTo(cryptoStream);
                        cryptoStream.FlushFinalBlock(); // 确保所有数据都已加密

                        // 返回加密后的字节数组
                        return ms.ToArray();
                    }
                }
            }

            /// <summary>
            /// Decrypts a byte array containing encrypted data and returns the decrypted data as a byte array.
            /// 解密包含加密数据的字节数组，并返回解密后的数据的字节数组。
            /// </summary>
            /// <param name="cipherData">The byte array containing the encrypted data.<br></br>包含加密数据的字节数组。</param>
            /// <param name="key">The decryption key, must be 32 characters long. It will be converted to a byte array.<br></br>解密密钥，必须为 32 个字符长。将被转换为字节数组。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被实际使用，但仍需提供。</param>
            /// <returns>A byte array containing the decrypted data.<br></br>包含解密数据的字节数组。</returns>
            /// <exception cref="ArgumentException">Thrown when the key or IV is of incorrect length.<br></br>当密钥或 IV 长度不正确时抛出。</exception>
            /// <remarks>
            /// This method uses AES decryption in ECB mode, which does not use the IV and is not recommended for secure decryption due to potential security vulnerabilities.<br></br>Note: ECB mode can expose patterns in the ciphertext.<br></br>该方法使用 ECB 模式的 AES 解密，不使用 IV，并且由于潜在的安全漏洞，不建议用于安全解密。<br></br>注意：ECB 模式可能暴露密文中的模式。
            /// </remarks>
            public static byte[] DecryptBytesToFile(byte[] cipherData, string key, string iv)
            {
                // 确保密钥长度为32字节（256位），AES-256需要此长度
                if (key.Length != 32) throw new ArgumentException("密钥必须是32个字符长。");
                // 确保IV长度为16字节（128位），虽然ECB模式下不实际使用IV
                if (iv.Length != 16) throw new ArgumentException("IV必须是16个字符长。");

                // 将密钥和IV从字符串转换为字节数组
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv); // 在ECB模式下IV不会被实际使用

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置为ECB模式
                    aes.Padding = PaddingMode.Zeros; // 设置为Zeros填充模式
                    aes.Key = keyBytes; // 设置密钥
                    aes.IV = ivBytes; // 设置IV（在ECB模式下不实际使用）

                    // 创建解密器
                    var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    using (var ms = new MemoryStream(cipherData))
                    using (var cryptoStream = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    using (var output = new MemoryStream())
                    {
                        // 从CryptoStream读取解密后的数据
                        cryptoStream.CopyTo(output);
                        // 返回解密后的字节数组
                        return output.ToArray();
                    }
                }
            }

            /// <summary>
            /// Encrypts the given byte array and writes the encrypted data to a file.
            /// 加密给定的字节数组，并将加密后的数据写入文件。
            /// </summary>
            /// <param name="data">The byte array containing the data to encrypt.<br></br>包含要加密的数据的字节数组。</param>
            /// <param name="outputFilePath">The path to the output file where the encrypted data will be written.<br></br>加密数据将被写入的输出文件路径。</param>
            /// <param name="key">The encryption key, must be 32 characters long. This key will be converted to a byte array.<br></br>加密密钥，必须为 32 个字符长。该密钥将被转换为字节数组。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被实际使用，但仍需提供。</param>
            /// <exception cref="ArgumentException">Thrown when the key or IV is of incorrect length.<br></br>当密钥或 IV 长度不正确时抛出。</exception>
            /// <remarks>
            /// This method uses AES encryption in ECB mode. Note that ECB mode does not use the IV and is generally not recommended for secure encryption due to its vulnerability to certain attacks.<br></br>该方法使用 ECB 模式的 AES 加密。注意，ECB 模式不使用 IV，并且通常不建议用于安全加密，因为它容易受到某些攻击。
            /// </remarks>
            public static void EncryptBytesToFile(byte[] data, string outputFilePath, string key, string iv)
            {
                // 确保密钥长度为32字节（256位），AES-256需要此长度
                if (key.Length != 32) throw new ArgumentException("密钥必须是32个字符长。");
                // 确保IV长度为16字节（128位），虽然ECB模式下IV不会被实际使用
                if (iv.Length != 16) throw new ArgumentException("IV必须是16个字符长。");

                // 将密钥和IV从字符串转换为字节数组
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv); // 在ECB模式下IV不会被实际使用

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置为ECB模式
                    aes.Padding = PaddingMode.Zeros; // 设置为Zeros填充模式
                    aes.Key = keyBytes; // 设置密钥
                    aes.IV = ivBytes; // 设置IV（在ECB模式下不实际使用）

                    // 创建加密器
                    var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                    using (var outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    using (var cryptoStream = new CryptoStream(outputFileStream, encryptor, CryptoStreamMode.Write))
                    {
                        // 将数据写入CryptoStream进行加密
                        cryptoStream.Write(data, 0, data.Length);
                        cryptoStream.FlushFinalBlock(); // 确保所有数据都已加密
                    }
                }
            }

            /// <summary>
            /// Decrypts the data from a file and returns the decrypted byte array.
            /// 从文件中解密数据并返回解密后的字节数组。
            /// </summary>
            /// <param name="inputFilePath">The path to the input file containing the encrypted data.<br></br>包含加密数据的输入文件路径。</param>
            /// <param name="key">The decryption key, must be 32 characters long. This key will be converted to a byte array.<br></br>解密密钥，必须为 32 个字符长。该密钥将被转换为字节数组。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被实际使用，但仍需提供。</param>
            /// <returns>A byte array containing the decrypted data.<br></br>包含解密数据的字节数组。</returns>
            /// <exception cref="ArgumentException">Thrown when the key or IV is of incorrect length.<br></br>当密钥或 IV 长度不正确时抛出。</exception>
            /// <remarks>
            /// This method uses AES decryption in ECB mode. Note that ECB mode does not use the IV and is generally not recommended for secure decryption due to its vulnerability to certain attacks.<br></br>该方法使用 ECB 模式的 AES 解密。注意，ECB 模式不使用 IV，并且通常不建议用于安全解密，因为它容易受到某些攻击。
            /// </remarks>
            public static byte[] DecryptFileToBytes(string inputFilePath, string key, string iv)
            {
                // 确保密钥长度为32字节（256位），AES-256需要此长度
                if (key.Length != 32) throw new ArgumentException("密钥必须是32个字符长。");
                // 确保IV长度为16字节（128位），虽然ECB模式下IV不会被实际使用
                if (iv.Length != 16) throw new ArgumentException("IV必须是16个字符长。");

                // 将密钥和IV从字符串转换为字节数组
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv); // 在ECB模式下IV不会被实际使用

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置为ECB模式
                    aes.Padding = PaddingMode.Zeros; // 设置为Zeros填充模式
                    aes.Key = keyBytes; // 设置密钥
                    aes.IV = ivBytes; // 设置IV（在ECB模式下不实际使用）

                    // 创建解密器
                    var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    using (var inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                    using (var cryptoStream = new CryptoStream(inputFileStream, decryptor, CryptoStreamMode.Read))
                    using (var ms = new MemoryStream())
                    {
                        // 从CryptoStream读取解密后的数据
                        cryptoStream.CopyTo(ms);
                        // 返回解密后的字节数组
                        return ms.ToArray();
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
            /// Encrypts a plain text string using AES encryption with ECB mode.<br></br>
            /// 使用 ECB 模式的 AES 加密对纯文本字符串进行加密。
            /// </summary>
            /// <param name="plainText">The plain text string to encrypt.<br></br>要加密的纯文本字符串。</param>
            /// <param name="key">The encryption key, must be 32 characters long.<br></br>加密密钥，必须为 32 个字符长。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被使用，但仍需提供。</param>
            /// <returns>The encrypted string in Base64 format.<br></br>以 Base64 格式返回的加密字符串。</returns>
            /// <remarks>
            /// This method uses AES encryption in ECB mode.<br></br>Note: ECB mode is not recommended for secure encryption as it does not use an initialization vector and has certain security vulnerabilities.<br></br>
            /// 该方法使用 ECB 模式的 AES 加密。<br></br>注意：ECB 模式不建议用于安全加密，因为它不使用初始化向量，并且具有某些安全漏洞。
            /// </remarks>
            public static string EncryptString(string plainText, string key, string iv)
            {
                if (key.Length != 32) throw new ArgumentException("Key must be 32 characters long.");
                if (iv.Length != 16) throw new ArgumentException("IV must be 16 characters long.");

                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv);

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置为 ECB 模式
                    aes.Padding = PaddingMode.ISO10126; // 设置填充模式
                    aes.Key = keyBytes;
                    aes.IV = ivBytes; // 在 ECB 模式下，IV 不会被使用，但仍需提供

                    var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                    var plainBytes = Encoding.UTF8.GetBytes(plainText);

                    using (var ms = new MemoryStream())
                    {
                        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            cs.Write(plainBytes, 0, plainBytes.Length);
                            cs.FlushFinalBlock();
                        }

                        return Convert.ToBase64String(ms.ToArray());
                    }
                }
            }

            /// <summary>
            /// Decrypts an encrypted string using AES decryption with ECB mode.<br></br>
            /// 使用 ECB 模式的 AES 解密对加密字符串进行解密。
            /// </summary>
            /// <param name="cipherText">The encrypted string in Base64 format to decrypt.<br></br>要解密的以 Base64 格式加密的字符串。</param>
            /// <param name="key">The decryption key, must be 32 characters long.<br></br>解密密钥，必须为 32 个字符长。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被使用，但仍需提供。</param>
            /// <returns>The decrypted plain text string.<br></br>解密后的纯文本字符串。</returns>
            /// <remarks>
            /// This method uses AES decryption in ECB mode.<br></br>Note: ECB mode is not recommended for secure decryption as it does not use an initialization vector and has certain security vulnerabilities.<br></br>
            /// 该方法使用 ECB 模式的 AES 解密。<br></br>注意：ECB 模式不建议用于安全解密，因为它不使用初始化向量，并且具有某些安全漏洞。
            /// </remarks>
            public static string DecryptString(string cipherText, string key, string iv)
            {
                if (key.Length != 32) throw new ArgumentException("Key must be 32 characters long.");
                if (iv.Length != 16) throw new ArgumentException("IV must be 16 characters long.");

                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv);

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置为 ECB 模式
                    aes.Padding = PaddingMode.ISO10126; // 设置填充模式
                    aes.Key = keyBytes;
                    aes.IV = ivBytes; // 在 ECB 模式下，IV 不会被使用，但仍需提供

                    var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    var cipherBytes = Convert.FromBase64String(cipherText);

                    using (var ms = new MemoryStream(cipherBytes))
                    {
                        using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                        {
                            using (var reader = new StreamReader(cs))
                            {
                                return reader.ReadToEnd();
                            }
                        }
                    }
                }
            }

            /// <summary>
            /// Encrypts a plain text string to a byte array using AES encryption with ECB mode.<br></br>
            /// 使用 ECB 模式的 AES 加密将纯文本字符串加密为字节数组。
            /// </summary>
            /// <param name="plainText">The plain text string to encrypt.<br></br>要加密的纯文本字符串。</param>
            /// <param name="key">The encryption key, must be 32 characters long.<br></br>加密密钥，必须为 32 个字符长。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被使用，但仍需提供。</param>
            /// <returns>The encrypted data as a byte array.<br></br>以字节数组形式返回的加密数据。</returns>
            /// <remarks>
            /// This method uses AES encryption in ECB mode.<br></br>Note: ECB mode is not recommended for secure encryption as it does not use an initialization vector and has certain security vulnerabilities.<br></br>
            /// 该方法使用 ECB 模式的 AES 加密。<br></br>注意：ECB 模式不建议用于安全加密，因为它不使用初始化向量，并且具有某些安全漏洞。
            /// </remarks>
            public static byte[] EncryptStringToBytes(string plainText, string key, string iv)
            {
                if (key.Length != 32) throw new ArgumentException("Key must be 32 characters long.");
                if (iv.Length != 16) throw new ArgumentException("IV must be 16 characters long.");

                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv);

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB;
                    aes.Padding = PaddingMode.ISO10126;
                    aes.Key = keyBytes;
                    aes.IV = ivBytes; // 在 ECB 模式下，IV 不会被使用，但仍需提供

                    var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
                    var plainBytes = Encoding.UTF8.GetBytes(plainText);

                    using (var ms = new MemoryStream())
                    {
                        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            cs.Write(plainBytes, 0, plainBytes.Length);
                            cs.FlushFinalBlock();
                        }
                        return ms.ToArray();
                    }
                }
            }

            /// <summary>
            /// Decrypts a byte array to a plain text string using AES decryption with ECB mode.<br></br>
            /// 使用 ECB 模式的 AES 解密将字节数组解密为纯文本字符串。
            /// </summary>
            /// <param name="cipherBytes">The encrypted data as a byte array to decrypt.<br></br>要解密的以字节数组形式的加密数据。</param>
            /// <param name="key">The decryption key, must be 32 characters long.<br></br>解密密钥，必须为 32 个字符长。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被使用，但仍需提供。</param>
            /// <returns>The decrypted plain text string.<br></br>解密后的纯文本字符串。</returns>
            /// <remarks>
            /// This method uses AES decryption in ECB mode.<br></br>Note: ECB mode is not recommended for secure decryption as it does not use an initialization vector and has certain security vulnerabilities.<br></br>
            /// 该方法使用 ECB 模式的 AES 解密。<br></br>注意：ECB 模式不建议用于安全解密，因为它不使用初始化向量，并且具有某些安全漏洞。
            /// </remarks>
            public static string DecryptBytesToString(byte[] cipherBytes, string key, string iv)
            {
                if (key.Length != 32) throw new ArgumentException("Key must be 32 characters long.");
                if (iv.Length != 16) throw new ArgumentException("IV must be 16 characters long.");

                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv);

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB;
                    aes.Padding = PaddingMode.ISO10126;
                    aes.Key = keyBytes;
                    aes.IV = ivBytes; // 在 ECB 模式下，IV 不会被使用，但仍需提供

                    var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    using (var ms = new MemoryStream(cipherBytes))
                    {
                        using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                        {
                            using (var reader = new StreamReader(cs, Encoding.UTF8))
                            {
                                return reader.ReadToEnd();
                            }
                        }
                    }
                }
            }

            /// <summary>
            /// Encrypts a byte array to a Base64-encoded string using AES encryption with ECB mode.<br></br>
            /// 使用 ECB 模式的 AES 加密将字节数组加密为 Base64 编码的字符串。
            /// </summary>
            /// <param name="data">The byte array to encrypt.<br></br>要加密的字节数组。</param>
            /// <param name="key">The encryption key, must be 32 characters long.<br></br>加密密钥，必须为 32 个字符长。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被实际使用，但仍需提供。</param>
            /// <returns>The encrypted data as a Base64-encoded string.<br></br>以 Base64 编码的字符串形式返回的加密数据。</returns>
            /// <remarks>
            /// This method uses AES encryption in ECB mode.<br></br>Note: ECB mode is not recommended for secure encryption as it does not use an initialization vector and has certain security vulnerabilities.<br></br>
            /// 该方法使用 ECB 模式的 AES 加密。<br></br>注意：ECB 模式不建议用于安全加密，因为它不使用初始化向量，并且具有某些安全漏洞。
            /// </remarks>
            public static string EncryptBytesToString(byte[] data, string key, string iv)
            {
                // 检查密钥长度，AES-256 需要 32 字节的密钥
                if (key.Length != 32) throw new ArgumentException("密钥必须为32个字符长。");
                // 检查初始化向量长度，虽然在 ECB 模式下不使用 IV，但仍需传递
                if (iv.Length != 16) throw new ArgumentException("IV必须为16个字符长。");

                // 将密钥和初始化向量从字符串转换为字节数组
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv); // 在 ECB 模式下，IV 不会被实际使用

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置加密模式为 ECB
                    aes.Padding = PaddingMode.ISO10126; // 设置填充模式为 ISO10126
                    aes.Key = keyBytes; // 设置密钥
                    aes.IV = ivBytes; // 设置 IV（虽然 ECB 模式下 IV 不实际使用）

                    // 创建加密器
                    var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                    using (var ms = new MemoryStream())
                    {
                        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            // 写入待加密的字节数据
                            cs.Write(data, 0, data.Length);
                            cs.FlushFinalBlock(); // 完成加密
                        }
                        // 将加密后的字节数据转换为 Base64 编码的字符串并返回
                        return Convert.ToBase64String(ms.ToArray());
                    }
                }
            }

            /// <summary>
            /// Decrypts a Base64-encoded string to a byte array using AES decryption with ECB mode.<br></br>
            /// 使用 ECB 模式的 AES 解密将 Base64 编码的字符串解密为字节数组。
            /// </summary>
            /// <param name="cipherText">The Base64-encoded string to decrypt.<br></br>要解密的 Base64 编码的字符串。</param>
            /// <param name="key">The decryption key, must be 32 characters long.<br></br>解密密钥，必须为 32 个字符长。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被实际使用，但仍需提供。</param>
            /// <returns>The decrypted data as a byte array.<br></br>解密后的字节数组。</returns>
            /// <remarks>
            /// This method uses AES decryption in ECB mode.<br></br>Note: ECB mode is not recommended for secure decryption as it does not use an initialization vector and has certain security vulnerabilities.<br></br>
            /// 该方法使用 ECB 模式的 AES 解密。<br></br>注意：ECB 模式不建议用于安全解密，因为它不使用初始化向量，并且具有某些安全漏洞。
            /// </remarks>
            public static byte[] DecryptStringToBytes(string cipherText, string key, string iv)
            {
                // 检查密钥长度，AES-256 需要 32 字节的密钥
                if (key.Length != 32) throw new ArgumentException("密钥必须为32个字符长。");
                // 检查初始化向量长度，虽然在 ECB 模式下不使用 IV，但仍需传递
                if (iv.Length != 16) throw new ArgumentException("IV必须为16个字符长。");

                // 将密钥和初始化向量从字符串转换为字节数组
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv); // 在 ECB 模式下，IV 不会被实际使用

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置解密模式为 ECB
                    aes.Padding = PaddingMode.ISO10126; // 设置填充模式为 ISO10126
                    aes.Key = keyBytes; // 设置密钥
                    aes.IV = ivBytes; // 设置 IV（虽然 ECB 模式下 IV 不实际使用）

                    // 创建解密器
                    var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    // 将 Base64 编码的字符串转换为字节数组
                    var cipherBytes = Convert.FromBase64String(cipherText);

                    using (var ms = new MemoryStream(cipherBytes))
                    {
                        using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                        {
                            using (var output = new MemoryStream())
                            {
                                // 读取解密后的字节数据
                                cs.CopyTo(output);
                                return output.ToArray();
                            }
                        }
                    }
                }
            }

            /// <summary>
            /// Encrypts a byte array using AES encryption with ECB mode and returns the encrypted data as a byte array.
            /// 使用 ECB 模式的 AES 加密加密字节数组，并以字节数组的形式返回加密后的数据。
            /// </summary>
            /// <param name="data">The byte array to encrypt.<br></br>要加密的字节数组。</param>
            /// <param name="key">The encryption key, must be 32 characters long. It will be converted to a byte array.<br></br>加密密钥，必须为 32 个字符长。将被转换为字节数组。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被实际使用，但仍需提供。</param>
            /// <returns>The encrypted data as a byte array.<br></br>以字节数组形式返回的加密数据。</returns>
            /// <remarks>
            /// This method uses AES encryption in ECB mode.<br></br>Note: ECB mode is not recommended for secure encryption as it does not use an initialization vector and may expose patterns in the plaintext.<br></br>
            /// 该方法使用 ECB 模式的 AES 加密。<br></br>注意：ECB 模式不建议用于安全加密，因为它不使用初始化向量，并可能暴露明文中的模式。
            /// </remarks>
            public static byte[] EncryptBytes(byte[] data, string key, string iv)
            {
                // 确保密钥长度为32字节（256位），AES-256加密需要此长度
                if (key.Length != 32) throw new ArgumentException("密钥必须是32个字符长。");
                // 确保IV长度为16字节（128位），虽然ECB模式下不实际使用IV
                if (iv.Length != 16) throw new ArgumentException("IV必须是16个字符长。");

                // 将密钥和IV从字符串转换为字节数组
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv); // 在ECB模式下IV不会被实际使用

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置为ECB模式
                    aes.Padding = PaddingMode.ISO10126; // 设置为ISO10126填充模式
                    aes.Key = keyBytes; // 设置密钥
                    aes.IV = ivBytes; // 设置IV（在ECB模式下不实际使用）

                    // 创建加密器
                    var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                    using (var ms = new MemoryStream())
                    {
                        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            // 将数据写入CryptoStream以进行加密
                            cs.Write(data, 0, data.Length);
                            cs.FlushFinalBlock(); // 确保所有数据都已写入
                        }
                        // 返回加密后的字节数组
                        return ms.ToArray();
                    }
                }
            }

            /// <summary>
            /// Decrypts a byte array using AES decryption with ECB mode and returns the decrypted data as a byte array.
            /// 使用 ECB 模式的 AES 解密解密字节数组，并以字节数组的形式返回解密后的数据。
            /// </summary>
            /// <param name="cipherData">The byte array containing the encrypted data.<br></br>包含加密数据的字节数组。</param>
            /// <param name="key">The decryption key, must be 32 characters long. It will be converted to a byte array.<br></br>解密密钥，必须为 32 个字符长。将被转换为字节数组。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被实际使用，但仍需提供。</param>
            /// <returns>The decrypted data as a byte array.<br></br>以字节数组形式返回的解密数据。</returns>
            /// <remarks>
            /// This method uses AES decryption in ECB mode.<br></br>Note: ECB mode is not recommended for secure decryption as it does not use an initialization vector and may expose patterns in the ciphertext.<br></br>
            /// 该方法使用 ECB 模式的 AES 解密。<br></br>注意：ECB 模式不建议用于安全解密，因为它不使用初始化向量，并可能暴露密文中的模式。
            /// </remarks>
            public static byte[] DecryptBytes(byte[] cipherData, string key, string iv)
            {
                // 确保密钥长度为32字节（256位），AES-256解密需要此长度
                if (key.Length != 32) throw new ArgumentException("密钥必须是32个字符长。");
                // 确保IV长度为16字节（128位），虽然ECB模式下不实际使用IV
                if (iv.Length != 16) throw new ArgumentException("IV必须是16个字符长。");

                // 将密钥和IV从字符串转换为字节数组
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv); // 在ECB模式下IV不会被实际使用

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置为ECB模式
                    aes.Padding = PaddingMode.ISO10126; // 设置为ISO10126填充模式
                    aes.Key = keyBytes; // 设置密钥
                    aes.IV = ivBytes; // 设置IV（在ECB模式下不实际使用）

                    // 创建解密器
                    var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    using (var ms = new MemoryStream(cipherData))
                    {
                        using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                        {
                            using (var output = new MemoryStream())
                            {
                                // 从CryptoStream读取解密后的数据
                                cs.CopyTo(output);
                                // 返回解密后的字节数组
                                return output.ToArray();
                            }
                        }
                    }
                }
            }

            /// <summary>
            /// Encrypts a file using AES encryption in ECB mode and writes the encrypted data to an output file.
            /// 使用 ECB 模式的 AES 加密加密文件，并将加密后的数据写入输出文件。
            /// </summary>
            /// <param name="inputFilePath">The path to the input file that will be encrypted.<br></br>要加密的输入文件的路径。</param>
            /// <param name="outputFilePath">The path to the output file where the encrypted data will be saved.<br></br>加密数据将保存到的输出文件的路径。</param>
            /// <param name="key">The encryption key, must be 32 characters long. It will be converted to a byte array.<br></br>加密密钥，必须为 32 个字符长。将被转换为字节数组。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被实际使用，但仍需提供。</param>
            /// <exception cref="ArgumentException">Thrown when the key or IV is of incorrect length.<br></br>当密钥或 IV 长度不正确时抛出。</exception>
            /// <remarks>
            /// This method uses AES encryption in ECB mode, which does not use the IV and is not recommended for secure encryption due to potential security vulnerabilities.<br></br>Note: ECB mode can expose patterns in the plaintext.<br></br>该方法使用 ECB 模式的 AES 加密，不使用 IV，并且由于潜在的安全漏洞，不建议用于安全加密。<br></br>注意：ECB 模式可能暴露明文中的模式。
            /// </remarks>
            public static void EncryptFile(string inputFilePath, string outputFilePath, string key, string iv)
            {
                // 检查密钥长度，AES-256需要32字节的密钥
                if (key.Length != 32) throw new ArgumentException("密钥必须是32个字符长。");
                // 检查IV长度，虽然ECB模式下不使用IV，但仍需传递
                if (iv.Length != 16) throw new ArgumentException("IV必须是16个字符长。");

                // 将密钥和IV从字符串转换为字节数组
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv); // 在ECB模式下IV不会被实际使用

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置为ECB模式
                    aes.Padding = PaddingMode.ISO10126; // 设置为ISO10126填充模式
                    aes.Key = keyBytes; // 设置密钥
                    aes.IV = ivBytes; // 设置IV（在ECB模式下不实际使用）

                    // 创建加密器
                    var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                    using (var inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                    using (var outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    using (var cryptoStream = new CryptoStream(outputFileStream, encryptor, CryptoStreamMode.Write))
                    {
                        // 加密文件内容
                        inputFileStream.CopyTo(cryptoStream);
                        cryptoStream.FlushFinalBlock(); // 确保所有数据都已加密
                    }
                }
            }

            /// <summary>
            /// Decrypts a file using AES decryption in ECB mode and writes the decrypted data to an output file.
            /// 使用 ECB 模式的 AES 解密解密文件，并将解密后的数据写入输出文件。
            /// </summary>
            /// <param name="inputFilePath">The path to the input file that contains the encrypted data.<br></br>包含加密数据的输入文件的路径。</param>
            /// <param name="outputFilePath">The path to the output file where the decrypted data will be saved.<br></br>解密数据将保存到的输出文件的路径。</param>
            /// <param name="key">The decryption key, must be 32 characters long. It will be converted to a byte array.<br></br>解密密钥，必须为 32 个字符长。将被转换为字节数组。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被实际使用，但仍需提供。</param>
            /// <exception cref="ArgumentException">Thrown when the key or IV is of incorrect length.<br></br>当密钥或 IV 长度不正确时抛出。</exception>
            /// <remarks>
            /// This method uses AES decryption in ECB mode, which does not use the IV and is not recommended for secure decryption due to potential security vulnerabilities.<br></br>Note: ECB mode can expose patterns in the ciphertext.<br></br>该方法使用 ECB 模式的 AES 解密，不使用 IV，并且由于潜在的安全漏洞，不建议用于安全解密。<br></br>注意：ECB 模式可能暴露密文中的模式。
            /// </remarks>
            public static void DecryptFile(string inputFilePath, string outputFilePath, string key, string iv)
            {
                // 检查密钥长度，AES-256需要32字节的密钥
                if (key.Length != 32) throw new ArgumentException("密钥必须是32个字符长。");
                // 检查IV长度，虽然ECB模式下不使用IV，但仍需传递
                if (iv.Length != 16) throw new ArgumentException("IV必须是16个字符长。");

                // 将密钥和IV从字符串转换为字节数组
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv); // 在ECB模式下IV不会被实际使用

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置为ECB模式
                    aes.Padding = PaddingMode.ISO10126; // 设置为ISO10126填充模式
                    aes.Key = keyBytes; // 设置密钥
                    aes.IV = ivBytes; // 设置IV（在ECB模式下不实际使用）

                    // 创建解密器
                    var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    using (var inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                    using (var outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    using (var cryptoStream = new CryptoStream(outputFileStream, decryptor, CryptoStreamMode.Write))
                    {
                        // 解密文件内容
                        inputFileStream.CopyTo(cryptoStream);
                        cryptoStream.FlushFinalBlock(); // 确保所有数据都已解密
                    }
                }
            }

            /// <summary>
            /// Encrypts a file and returns the encrypted data as a byte array.
            /// 加密文件并返回加密数据的字节数组。
            /// </summary>
            /// <param name="inputFilePath">The path to the input file that will be encrypted.<br></br>要加密的输入文件的路径。</param>
            /// <param name="key">The encryption key, must be 32 characters long. It will be converted to a byte array.<br></br>加密密钥，必须为 32 个字符长。将被转换为字节数组。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被实际使用，但仍需提供。</param>
            /// <returns>A byte array containing the encrypted data.<br></br>包含加密数据的字节数组。</returns>
            /// <exception cref="ArgumentException">Thrown when the key or IV is of incorrect length.<br></br>当密钥或 IV 长度不正确时抛出。</exception>
            /// <remarks>
            /// This method uses AES encryption in ECB mode, which does not use the IV and is not recommended for secure encryption due to potential security vulnerabilities.<br></br>Note: ECB mode can expose patterns in the plaintext.<br></br>该方法使用 ECB 模式的 AES 加密，不使用 IV，并且由于潜在的安全漏洞，不建议用于安全加密。<br></br>注意：ECB 模式可能暴露明文中的模式。
            /// </remarks>
            public static byte[] EncryptFileToBytes(string inputFilePath, string key, string iv)
            {
                // 确保密钥长度为32字节（256位），AES-256需要此长度
                if (key.Length != 32) throw new ArgumentException("密钥必须是32个字符长。");
                // 确保IV长度为16字节（128位），虽然ECB模式下不实际使用IV
                if (iv.Length != 16) throw new ArgumentException("IV必须是16个字符长。");

                // 将密钥和IV从字符串转换为字节数组
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv); // 在ECB模式下IV不会被实际使用

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置为ECB模式
                    aes.Padding = PaddingMode.ISO10126; // 设置为ISO10126填充模式
                    aes.Key = keyBytes; // 设置密钥
                    aes.IV = ivBytes; // 设置IV（在ECB模式下不实际使用）

                    // 创建加密器
                    var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                    using (var inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                    using (var ms = new MemoryStream())
                    using (var cryptoStream = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        // 将文件内容复制到CryptoStream进行加密
                        inputFileStream.CopyTo(cryptoStream);
                        cryptoStream.FlushFinalBlock(); // 确保所有数据都已加密

                        // 返回加密后的字节数组
                        return ms.ToArray();
                    }
                }
            }

            /// <summary>
            /// Decrypts a byte array containing encrypted data and returns the decrypted data as a byte array.
            /// 解密包含加密数据的字节数组，并返回解密后的数据的字节数组。
            /// </summary>
            /// <param name="cipherData">The byte array containing the encrypted data.<br></br>包含加密数据的字节数组。</param>
            /// <param name="key">The decryption key, must be 32 characters long. It will be converted to a byte array.<br></br>解密密钥，必须为 32 个字符长。将被转换为字节数组。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被实际使用，但仍需提供。</param>
            /// <returns>A byte array containing the decrypted data.<br></br>包含解密数据的字节数组。</returns>
            /// <exception cref="ArgumentException">Thrown when the key or IV is of incorrect length.<br></br>当密钥或 IV 长度不正确时抛出。</exception>
            /// <remarks>
            /// This method uses AES decryption in ECB mode, which does not use the IV and is not recommended for secure decryption due to potential security vulnerabilities.<br></br>Note: ECB mode can expose patterns in the ciphertext.<br></br>该方法使用 ECB 模式的 AES 解密，不使用 IV，并且由于潜在的安全漏洞，不建议用于安全解密。<br></br>注意：ECB 模式可能暴露密文中的模式。
            /// </remarks>
            public static byte[] DecryptBytesToFile(byte[] cipherData, string key, string iv)
            {
                // 确保密钥长度为32字节（256位），AES-256需要此长度
                if (key.Length != 32) throw new ArgumentException("密钥必须是32个字符长。");
                // 确保IV长度为16字节（128位），虽然ECB模式下不实际使用IV
                if (iv.Length != 16) throw new ArgumentException("IV必须是16个字符长。");

                // 将密钥和IV从字符串转换为字节数组
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv); // 在ECB模式下IV不会被实际使用

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置为ECB模式
                    aes.Padding = PaddingMode.ISO10126; // 设置为ISO10126填充模式
                    aes.Key = keyBytes; // 设置密钥
                    aes.IV = ivBytes; // 设置IV（在ECB模式下不实际使用）

                    // 创建解密器
                    var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    using (var ms = new MemoryStream(cipherData))
                    using (var cryptoStream = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    using (var output = new MemoryStream())
                    {
                        // 从CryptoStream读取解密后的数据
                        cryptoStream.CopyTo(output);
                        // 返回解密后的字节数组
                        return output.ToArray();
                    }
                }
            }

            /// <summary>
            /// Encrypts the given byte array and writes the encrypted data to a file.
            /// 加密给定的字节数组，并将加密后的数据写入文件。
            /// </summary>
            /// <param name="data">The byte array containing the data to encrypt.<br></br>包含要加密的数据的字节数组。</param>
            /// <param name="outputFilePath">The path to the output file where the encrypted data will be written.<br></br>加密数据将被写入的输出文件路径。</param>
            /// <param name="key">The encryption key, must be 32 characters long. This key will be converted to a byte array.<br></br>加密密钥，必须为 32 个字符长。该密钥将被转换为字节数组。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被实际使用，但仍需提供。</param>
            /// <exception cref="ArgumentException">Thrown when the key or IV is of incorrect length.<br></br>当密钥或 IV 长度不正确时抛出。</exception>
            /// <remarks>
            /// This method uses AES encryption in ECB mode. Note that ECB mode does not use the IV and is generally not recommended for secure encryption due to its vulnerability to certain attacks.<br></br>该方法使用 ECB 模式的 AES 加密。注意，ECB 模式不使用 IV，并且通常不建议用于安全加密，因为它容易受到某些攻击。
            /// </remarks>
            public static void EncryptBytesToFile(byte[] data, string outputFilePath, string key, string iv)
            {
                // 确保密钥长度为32字节（256位），AES-256需要此长度
                if (key.Length != 32) throw new ArgumentException("密钥必须是32个字符长。");
                // 确保IV长度为16字节（128位），虽然ECB模式下IV不会被实际使用
                if (iv.Length != 16) throw new ArgumentException("IV必须是16个字符长。");

                // 将密钥和IV从字符串转换为字节数组
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv); // 在ECB模式下IV不会被实际使用

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置为ECB模式
                    aes.Padding = PaddingMode.ISO10126; // 设置为ISO10126填充模式
                    aes.Key = keyBytes; // 设置密钥
                    aes.IV = ivBytes; // 设置IV（在ECB模式下不实际使用）

                    // 创建加密器
                    var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                    using (var outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    using (var cryptoStream = new CryptoStream(outputFileStream, encryptor, CryptoStreamMode.Write))
                    {
                        // 将数据写入CryptoStream进行加密
                        cryptoStream.Write(data, 0, data.Length);
                        cryptoStream.FlushFinalBlock(); // 确保所有数据都已加密
                    }
                }
            }

            /// <summary>
            /// Decrypts the data from a file and returns the decrypted byte array.
            /// 从文件中解密数据并返回解密后的字节数组。
            /// </summary>
            /// <param name="inputFilePath">The path to the input file containing the encrypted data.<br></br>包含加密数据的输入文件路径。</param>
            /// <param name="key">The decryption key, must be 32 characters long. This key will be converted to a byte array.<br></br>解密密钥，必须为 32 个字符长。该密钥将被转换为字节数组。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被实际使用，但仍需提供。</param>
            /// <returns>A byte array containing the decrypted data.<br></br>包含解密数据的字节数组。</returns>
            /// <exception cref="ArgumentException">Thrown when the key or IV is of incorrect length.<br></br>当密钥或 IV 长度不正确时抛出。</exception>
            /// <remarks>
            /// This method uses AES decryption in ECB mode. Note that ECB mode does not use the IV and is generally not recommended for secure decryption due to its vulnerability to certain attacks.<br></br>该方法使用 ECB 模式的 AES 解密。注意，ECB 模式不使用 IV，并且通常不建议用于安全解密，因为它容易受到某些攻击。
            /// </remarks>
            public static byte[] DecryptFileToBytes(string inputFilePath, string key, string iv)
            {
                // 确保密钥长度为32字节（256位），AES-256需要此长度
                if (key.Length != 32) throw new ArgumentException("密钥必须是32个字符长。");
                // 确保IV长度为16字节（128位），虽然ECB模式下IV不会被实际使用
                if (iv.Length != 16) throw new ArgumentException("IV必须是16个字符长。");

                // 将密钥和IV从字符串转换为字节数组
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv); // 在ECB模式下IV不会被实际使用

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置为ECB模式
                    aes.Padding = PaddingMode.ISO10126; // 设置为ISO10126填充模式
                    aes.Key = keyBytes; // 设置密钥
                    aes.IV = ivBytes; // 设置IV（在ECB模式下不实际使用）

                    // 创建解密器
                    var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    using (var inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                    using (var cryptoStream = new CryptoStream(inputFileStream, decryptor, CryptoStreamMode.Read))
                    using (var ms = new MemoryStream())
                    {
                        // 从CryptoStream读取解密后的数据
                        cryptoStream.CopyTo(ms);
                        // 返回解密后的字节数组
                        return ms.ToArray();
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
            /// Encrypts a plain text string using AES encryption with ECB mode.<br></br>
            /// 使用 ECB 模式的 AES 加密对纯文本字符串进行加密。
            /// </summary>
            /// <param name="plainText">The plain text string to encrypt.<br></br>要加密的纯文本字符串。</param>
            /// <param name="key">The encryption key, must be 32 characters long.<br></br>加密密钥，必须为 32 个字符长。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被使用，但仍需提供。</param>
            /// <returns>The encrypted string in Base64 format.<br></br>以 Base64 格式返回的加密字符串。</returns>
            /// <remarks>
            /// This method uses AES encryption in ECB mode.<br></br>Note: ECB mode is not recommended for secure encryption as it does not use an initialization vector and has certain security vulnerabilities.<br></br>
            /// 该方法使用 ECB 模式的 AES 加密。<br></br>注意：ECB 模式不建议用于安全加密，因为它不使用初始化向量，并且具有某些安全漏洞。
            /// </remarks>
            public static string EncryptString(string plainText, string key, string iv)
            {
                if (key.Length != 32) throw new ArgumentException("Key must be 32 characters long.");
                if (iv.Length != 16) throw new ArgumentException("IV must be 16 characters long.");

                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv);

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置为 ECB 模式
                    aes.Padding = PaddingMode.ANSIX923; // 设置填充模式
                    aes.Key = keyBytes;
                    aes.IV = ivBytes; // 在 ECB 模式下，IV 不会被使用，但仍需提供

                    var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                    var plainBytes = Encoding.UTF8.GetBytes(plainText);

                    using (var ms = new MemoryStream())
                    {
                        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            cs.Write(plainBytes, 0, plainBytes.Length);
                            cs.FlushFinalBlock();
                        }

                        return Convert.ToBase64String(ms.ToArray());
                    }
                }
            }

            /// <summary>
            /// Decrypts an encrypted string using AES decryption with ECB mode.<br></br>
            /// 使用 ECB 模式的 AES 解密对加密字符串进行解密。
            /// </summary>
            /// <param name="cipherText">The encrypted string in Base64 format to decrypt.<br></br>要解密的以 Base64 格式加密的字符串。</param>
            /// <param name="key">The decryption key, must be 32 characters long.<br></br>解密密钥，必须为 32 个字符长。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被使用，但仍需提供。</param>
            /// <returns>The decrypted plain text string.<br></br>解密后的纯文本字符串。</returns>
            /// <remarks>
            /// This method uses AES decryption in ECB mode.<br></br>Note: ECB mode is not recommended for secure decryption as it does not use an initialization vector and has certain security vulnerabilities.<br></br>
            /// 该方法使用 ECB 模式的 AES 解密。<br></br>注意：ECB 模式不建议用于安全解密，因为它不使用初始化向量，并且具有某些安全漏洞。
            /// </remarks>
            public static string DecryptString(string cipherText, string key, string iv)
            {
                if (key.Length != 32) throw new ArgumentException("Key must be 32 characters long.");
                if (iv.Length != 16) throw new ArgumentException("IV must be 16 characters long.");

                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv);

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置为 ECB 模式
                    aes.Padding = PaddingMode.ANSIX923; // 设置填充模式
                    aes.Key = keyBytes;
                    aes.IV = ivBytes; // 在 ECB 模式下，IV 不会被使用，但仍需提供

                    var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    var cipherBytes = Convert.FromBase64String(cipherText);

                    using (var ms = new MemoryStream(cipherBytes))
                    {
                        using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                        {
                            using (var reader = new StreamReader(cs))
                            {
                                return reader.ReadToEnd();
                            }
                        }
                    }
                }
            }

            /// <summary>
            /// Encrypts a plain text string to a byte array using AES encryption with ECB mode.<br></br>
            /// 使用 ECB 模式的 AES 加密将纯文本字符串加密为字节数组。
            /// </summary>
            /// <param name="plainText">The plain text string to encrypt.<br></br>要加密的纯文本字符串。</param>
            /// <param name="key">The encryption key, must be 32 characters long.<br></br>加密密钥，必须为 32 个字符长。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被使用，但仍需提供。</param>
            /// <returns>The encrypted data as a byte array.<br></br>以字节数组形式返回的加密数据。</returns>
            /// <remarks>
            /// This method uses AES encryption in ECB mode.<br></br>Note: ECB mode is not recommended for secure encryption as it does not use an initialization vector and has certain security vulnerabilities.<br></br>
            /// 该方法使用 ECB 模式的 AES 加密。<br></br>注意：ECB 模式不建议用于安全加密，因为它不使用初始化向量，并且具有某些安全漏洞。
            /// </remarks>
            public static byte[] EncryptStringToBytes(string plainText, string key, string iv)
            {
                if (key.Length != 32) throw new ArgumentException("Key must be 32 characters long.");
                if (iv.Length != 16) throw new ArgumentException("IV must be 16 characters long.");

                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv);

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB;
                    aes.Padding = PaddingMode.ANSIX923;
                    aes.Key = keyBytes;
                    aes.IV = ivBytes; // 在 ECB 模式下，IV 不会被使用，但仍需提供

                    var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
                    var plainBytes = Encoding.UTF8.GetBytes(plainText);

                    using (var ms = new MemoryStream())
                    {
                        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            cs.Write(plainBytes, 0, plainBytes.Length);
                            cs.FlushFinalBlock();
                        }
                        return ms.ToArray();
                    }
                }
            }

            /// <summary>
            /// Decrypts a byte array to a plain text string using AES decryption with ECB mode.<br></br>
            /// 使用 ECB 模式的 AES 解密将字节数组解密为纯文本字符串。
            /// </summary>
            /// <param name="cipherBytes">The encrypted data as a byte array to decrypt.<br></br>要解密的以字节数组形式的加密数据。</param>
            /// <param name="key">The decryption key, must be 32 characters long.<br></br>解密密钥，必须为 32 个字符长。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被使用，但仍需提供。</param>
            /// <returns>The decrypted plain text string.<br></br>解密后的纯文本字符串。</returns>
            /// <remarks>
            /// This method uses AES decryption in ECB mode.<br></br>Note: ECB mode is not recommended for secure decryption as it does not use an initialization vector and has certain security vulnerabilities.<br></br>
            /// 该方法使用 ECB 模式的 AES 解密。<br></br>注意：ECB 模式不建议用于安全解密，因为它不使用初始化向量，并且具有某些安全漏洞。
            /// </remarks>
            public static string DecryptBytesToString(byte[] cipherBytes, string key, string iv)
            {
                if (key.Length != 32) throw new ArgumentException("Key must be 32 characters long.");
                if (iv.Length != 16) throw new ArgumentException("IV must be 16 characters long.");

                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv);

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB;
                    aes.Padding = PaddingMode.ANSIX923;
                    aes.Key = keyBytes;
                    aes.IV = ivBytes; // 在 ECB 模式下，IV 不会被使用，但仍需提供

                    var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    using (var ms = new MemoryStream(cipherBytes))
                    {
                        using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                        {
                            using (var reader = new StreamReader(cs, Encoding.UTF8))
                            {
                                return reader.ReadToEnd();
                            }
                        }
                    }
                }
            }

            /// <summary>
            /// Encrypts a byte array to a Base64-encoded string using AES encryption with ECB mode.<br></br>
            /// 使用 ECB 模式的 AES 加密将字节数组加密为 Base64 编码的字符串。
            /// </summary>
            /// <param name="data">The byte array to encrypt.<br></br>要加密的字节数组。</param>
            /// <param name="key">The encryption key, must be 32 characters long.<br></br>加密密钥，必须为 32 个字符长。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被实际使用，但仍需提供。</param>
            /// <returns>The encrypted data as a Base64-encoded string.<br></br>以 Base64 编码的字符串形式返回的加密数据。</returns>
            /// <remarks>
            /// This method uses AES encryption in ECB mode.<br></br>Note: ECB mode is not recommended for secure encryption as it does not use an initialization vector and has certain security vulnerabilities.<br></br>
            /// 该方法使用 ECB 模式的 AES 加密。<br></br>注意：ECB 模式不建议用于安全加密，因为它不使用初始化向量，并且具有某些安全漏洞。
            /// </remarks>
            public static string EncryptBytesToString(byte[] data, string key, string iv)
            {
                // 检查密钥长度，AES-256 需要 32 字节的密钥
                if (key.Length != 32) throw new ArgumentException("密钥必须为32个字符长。");
                // 检查初始化向量长度，虽然在 ECB 模式下不使用 IV，但仍需传递
                if (iv.Length != 16) throw new ArgumentException("IV必须为16个字符长。");

                // 将密钥和初始化向量从字符串转换为字节数组
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv); // 在 ECB 模式下，IV 不会被实际使用

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置加密模式为 ECB
                    aes.Padding = PaddingMode.ANSIX923; // 设置填充模式为 ANSIX923
                    aes.Key = keyBytes; // 设置密钥
                    aes.IV = ivBytes; // 设置 IV（虽然 ECB 模式下 IV 不实际使用）

                    // 创建加密器
                    var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                    using (var ms = new MemoryStream())
                    {
                        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            // 写入待加密的字节数据
                            cs.Write(data, 0, data.Length);
                            cs.FlushFinalBlock(); // 完成加密
                        }
                        // 将加密后的字节数据转换为 Base64 编码的字符串并返回
                        return Convert.ToBase64String(ms.ToArray());
                    }
                }
            }

            /// <summary>
            /// Decrypts a Base64-encoded string to a byte array using AES decryption with ECB mode.<br></br>
            /// 使用 ECB 模式的 AES 解密将 Base64 编码的字符串解密为字节数组。
            /// </summary>
            /// <param name="cipherText">The Base64-encoded string to decrypt.<br></br>要解密的 Base64 编码的字符串。</param>
            /// <param name="key">The decryption key, must be 32 characters long.<br></br>解密密钥，必须为 32 个字符长。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被实际使用，但仍需提供。</param>
            /// <returns>The decrypted data as a byte array.<br></br>解密后的字节数组。</returns>
            /// <remarks>
            /// This method uses AES decryption in ECB mode.<br></br>Note: ECB mode is not recommended for secure decryption as it does not use an initialization vector and has certain security vulnerabilities.<br></br>
            /// 该方法使用 ECB 模式的 AES 解密。<br></br>注意：ECB 模式不建议用于安全解密，因为它不使用初始化向量，并且具有某些安全漏洞。
            /// </remarks>
            public static byte[] DecryptStringToBytes(string cipherText, string key, string iv)
            {
                // 检查密钥长度，AES-256 需要 32 字节的密钥
                if (key.Length != 32) throw new ArgumentException("密钥必须为32个字符长。");
                // 检查初始化向量长度，虽然在 ECB 模式下不使用 IV，但仍需传递
                if (iv.Length != 16) throw new ArgumentException("IV必须为16个字符长。");

                // 将密钥和初始化向量从字符串转换为字节数组
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv); // 在 ECB 模式下，IV 不会被实际使用

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置解密模式为 ECB
                    aes.Padding = PaddingMode.ANSIX923; // 设置填充模式为 ANSIX923
                    aes.Key = keyBytes; // 设置密钥
                    aes.IV = ivBytes; // 设置 IV（虽然 ECB 模式下 IV 不实际使用）

                    // 创建解密器
                    var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    // 将 Base64 编码的字符串转换为字节数组
                    var cipherBytes = Convert.FromBase64String(cipherText);

                    using (var ms = new MemoryStream(cipherBytes))
                    {
                        using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                        {
                            using (var output = new MemoryStream())
                            {
                                // 读取解密后的字节数据
                                cs.CopyTo(output);
                                return output.ToArray();
                            }
                        }
                    }
                }
            }

            /// <summary>
            /// Encrypts a byte array using AES encryption with ECB mode and returns the encrypted data as a byte array.
            /// 使用 ECB 模式的 AES 加密加密字节数组，并以字节数组的形式返回加密后的数据。
            /// </summary>
            /// <param name="data">The byte array to encrypt.<br></br>要加密的字节数组。</param>
            /// <param name="key">The encryption key, must be 32 characters long. It will be converted to a byte array.<br></br>加密密钥，必须为 32 个字符长。将被转换为字节数组。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被实际使用，但仍需提供。</param>
            /// <returns>The encrypted data as a byte array.<br></br>以字节数组形式返回的加密数据。</returns>
            /// <remarks>
            /// This method uses AES encryption in ECB mode.<br></br>Note: ECB mode is not recommended for secure encryption as it does not use an initialization vector and may expose patterns in the plaintext.<br></br>
            /// 该方法使用 ECB 模式的 AES 加密。<br></br>注意：ECB 模式不建议用于安全加密，因为它不使用初始化向量，并可能暴露明文中的模式。
            /// </remarks>
            public static byte[] EncryptBytes(byte[] data, string key, string iv)
            {
                // 确保密钥长度为32字节（256位），AES-256加密需要此长度
                if (key.Length != 32) throw new ArgumentException("密钥必须是32个字符长。");
                // 确保IV长度为16字节（128位），虽然ECB模式下不实际使用IV
                if (iv.Length != 16) throw new ArgumentException("IV必须是16个字符长。");

                // 将密钥和IV从字符串转换为字节数组
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv); // 在ECB模式下IV不会被实际使用

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置为ECB模式
                    aes.Padding = PaddingMode.ANSIX923; // 设置为ANSIX923填充模式
                    aes.Key = keyBytes; // 设置密钥
                    aes.IV = ivBytes; // 设置IV（在ECB模式下不实际使用）

                    // 创建加密器
                    var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                    using (var ms = new MemoryStream())
                    {
                        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            // 将数据写入CryptoStream以进行加密
                            cs.Write(data, 0, data.Length);
                            cs.FlushFinalBlock(); // 确保所有数据都已写入
                        }
                        // 返回加密后的字节数组
                        return ms.ToArray();
                    }
                }
            }

            /// <summary>
            /// Decrypts a byte array using AES decryption with ECB mode and returns the decrypted data as a byte array.
            /// 使用 ECB 模式的 AES 解密解密字节数组，并以字节数组的形式返回解密后的数据。
            /// </summary>
            /// <param name="cipherData">The byte array containing the encrypted data.<br></br>包含加密数据的字节数组。</param>
            /// <param name="key">The decryption key, must be 32 characters long. It will be converted to a byte array.<br></br>解密密钥，必须为 32 个字符长。将被转换为字节数组。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被实际使用，但仍需提供。</param>
            /// <returns>The decrypted data as a byte array.<br></br>以字节数组形式返回的解密数据。</returns>
            /// <remarks>
            /// This method uses AES decryption in ECB mode.<br></br>Note: ECB mode is not recommended for secure decryption as it does not use an initialization vector and may expose patterns in the ciphertext.<br></br>
            /// 该方法使用 ECB 模式的 AES 解密。<br></br>注意：ECB 模式不建议用于安全解密，因为它不使用初始化向量，并可能暴露密文中的模式。
            /// </remarks>
            public static byte[] DecryptBytes(byte[] cipherData, string key, string iv)
            {
                // 确保密钥长度为32字节（256位），AES-256解密需要此长度
                if (key.Length != 32) throw new ArgumentException("密钥必须是32个字符长。");
                // 确保IV长度为16字节（128位），虽然ECB模式下不实际使用IV
                if (iv.Length != 16) throw new ArgumentException("IV必须是16个字符长。");

                // 将密钥和IV从字符串转换为字节数组
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv); // 在ECB模式下IV不会被实际使用

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置为ECB模式
                    aes.Padding = PaddingMode.ANSIX923; // 设置为ANSIX923填充模式
                    aes.Key = keyBytes; // 设置密钥
                    aes.IV = ivBytes; // 设置IV（在ECB模式下不实际使用）

                    // 创建解密器
                    var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    using (var ms = new MemoryStream(cipherData))
                    {
                        using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                        {
                            using (var output = new MemoryStream())
                            {
                                // 从CryptoStream读取解密后的数据
                                cs.CopyTo(output);
                                // 返回解密后的字节数组
                                return output.ToArray();
                            }
                        }
                    }
                }
            }

            /// <summary>
            /// Encrypts a file using AES encryption in ECB mode and writes the encrypted data to an output file.
            /// 使用 ECB 模式的 AES 加密加密文件，并将加密后的数据写入输出文件。
            /// </summary>
            /// <param name="inputFilePath">The path to the input file that will be encrypted.<br></br>要加密的输入文件的路径。</param>
            /// <param name="outputFilePath">The path to the output file where the encrypted data will be saved.<br></br>加密数据将保存到的输出文件的路径。</param>
            /// <param name="key">The encryption key, must be 32 characters long. It will be converted to a byte array.<br></br>加密密钥，必须为 32 个字符长。将被转换为字节数组。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被实际使用，但仍需提供。</param>
            /// <exception cref="ArgumentException">Thrown when the key or IV is of incorrect length.<br></br>当密钥或 IV 长度不正确时抛出。</exception>
            /// <remarks>
            /// This method uses AES encryption in ECB mode, which does not use the IV and is not recommended for secure encryption due to potential security vulnerabilities.<br></br>Note: ECB mode can expose patterns in the plaintext.<br></br>该方法使用 ECB 模式的 AES 加密，不使用 IV，并且由于潜在的安全漏洞，不建议用于安全加密。<br></br>注意：ECB 模式可能暴露明文中的模式。
            /// </remarks>
            public static void EncryptFile(string inputFilePath, string outputFilePath, string key, string iv)
            {
                // 检查密钥长度，AES-256需要32字节的密钥
                if (key.Length != 32) throw new ArgumentException("密钥必须是32个字符长。");
                // 检查IV长度，虽然ECB模式下不使用IV，但仍需传递
                if (iv.Length != 16) throw new ArgumentException("IV必须是16个字符长。");

                // 将密钥和IV从字符串转换为字节数组
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv); // 在ECB模式下IV不会被实际使用

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置为ECB模式
                    aes.Padding = PaddingMode.ANSIX923; // 设置为ANSIX923填充模式
                    aes.Key = keyBytes; // 设置密钥
                    aes.IV = ivBytes; // 设置IV（在ECB模式下不实际使用）

                    // 创建加密器
                    var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                    using (var inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                    using (var outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    using (var cryptoStream = new CryptoStream(outputFileStream, encryptor, CryptoStreamMode.Write))
                    {
                        // 加密文件内容
                        inputFileStream.CopyTo(cryptoStream);
                        cryptoStream.FlushFinalBlock(); // 确保所有数据都已加密
                    }
                }
            }

            /// <summary>
            /// Decrypts a file using AES decryption in ECB mode and writes the decrypted data to an output file.
            /// 使用 ECB 模式的 AES 解密解密文件，并将解密后的数据写入输出文件。
            /// </summary>
            /// <param name="inputFilePath">The path to the input file that contains the encrypted data.<br></br>包含加密数据的输入文件的路径。</param>
            /// <param name="outputFilePath">The path to the output file where the decrypted data will be saved.<br></br>解密数据将保存到的输出文件的路径。</param>
            /// <param name="key">The decryption key, must be 32 characters long. It will be converted to a byte array.<br></br>解密密钥，必须为 32 个字符长。将被转换为字节数组。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被实际使用，但仍需提供。</param>
            /// <exception cref="ArgumentException">Thrown when the key or IV is of incorrect length.<br></br>当密钥或 IV 长度不正确时抛出。</exception>
            /// <remarks>
            /// This method uses AES decryption in ECB mode, which does not use the IV and is not recommended for secure decryption due to potential security vulnerabilities.<br></br>Note: ECB mode can expose patterns in the ciphertext.<br></br>该方法使用 ECB 模式的 AES 解密，不使用 IV，并且由于潜在的安全漏洞，不建议用于安全解密。<br></br>注意：ECB 模式可能暴露密文中的模式。
            /// </remarks>
            public static void DecryptFile(string inputFilePath, string outputFilePath, string key, string iv)
            {
                // 检查密钥长度，AES-256需要32字节的密钥
                if (key.Length != 32) throw new ArgumentException("密钥必须是32个字符长。");
                // 检查IV长度，虽然ECB模式下不使用IV，但仍需传递
                if (iv.Length != 16) throw new ArgumentException("IV必须是16个字符长。");

                // 将密钥和IV从字符串转换为字节数组
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv); // 在ECB模式下IV不会被实际使用

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置为ECB模式
                    aes.Padding = PaddingMode.ANSIX923; // 设置为ANSIX923填充模式
                    aes.Key = keyBytes; // 设置密钥
                    aes.IV = ivBytes; // 设置IV（在ECB模式下不实际使用）

                    // 创建解密器
                    var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    using (var inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                    using (var outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    using (var cryptoStream = new CryptoStream(outputFileStream, decryptor, CryptoStreamMode.Write))
                    {
                        // 解密文件内容
                        inputFileStream.CopyTo(cryptoStream);
                        cryptoStream.FlushFinalBlock(); // 确保所有数据都已解密
                    }
                }
            }

            /// <summary>
            /// Encrypts a file and returns the encrypted data as a byte array.
            /// 加密文件并返回加密数据的字节数组。
            /// </summary>
            /// <param name="inputFilePath">The path to the input file that will be encrypted.<br></br>要加密的输入文件的路径。</param>
            /// <param name="key">The encryption key, must be 32 characters long. It will be converted to a byte array.<br></br>加密密钥，必须为 32 个字符长。将被转换为字节数组。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被实际使用，但仍需提供。</param>
            /// <returns>A byte array containing the encrypted data.<br></br>包含加密数据的字节数组。</returns>
            /// <exception cref="ArgumentException">Thrown when the key or IV is of incorrect length.<br></br>当密钥或 IV 长度不正确时抛出。</exception>
            /// <remarks>
            /// This method uses AES encryption in ECB mode, which does not use the IV and is not recommended for secure encryption due to potential security vulnerabilities.<br></br>Note: ECB mode can expose patterns in the plaintext.<br></br>该方法使用 ECB 模式的 AES 加密，不使用 IV，并且由于潜在的安全漏洞，不建议用于安全加密。<br></br>注意：ECB 模式可能暴露明文中的模式。
            /// </remarks>
            public static byte[] EncryptFileToBytes(string inputFilePath, string key, string iv)
            {
                // 确保密钥长度为32字节（256位），AES-256需要此长度
                if (key.Length != 32) throw new ArgumentException("密钥必须是32个字符长。");
                // 确保IV长度为16字节（128位），虽然ECB模式下不实际使用IV
                if (iv.Length != 16) throw new ArgumentException("IV必须是16个字符长。");

                // 将密钥和IV从字符串转换为字节数组
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv); // 在ECB模式下IV不会被实际使用

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置为ECB模式
                    aes.Padding = PaddingMode.ANSIX923; // 设置为ANSIX923填充模式
                    aes.Key = keyBytes; // 设置密钥
                    aes.IV = ivBytes; // 设置IV（在ECB模式下不实际使用）

                    // 创建加密器
                    var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                    using (var inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                    using (var ms = new MemoryStream())
                    using (var cryptoStream = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        // 将文件内容复制到CryptoStream进行加密
                        inputFileStream.CopyTo(cryptoStream);
                        cryptoStream.FlushFinalBlock(); // 确保所有数据都已加密

                        // 返回加密后的字节数组
                        return ms.ToArray();
                    }
                }
            }

            /// <summary>
            /// Decrypts a byte array containing encrypted data and returns the decrypted data as a byte array.
            /// 解密包含加密数据的字节数组，并返回解密后的数据的字节数组。
            /// </summary>
            /// <param name="cipherData">The byte array containing the encrypted data.<br></br>包含加密数据的字节数组。</param>
            /// <param name="key">The decryption key, must be 32 characters long. It will be converted to a byte array.<br></br>解密密钥，必须为 32 个字符长。将被转换为字节数组。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被实际使用，但仍需提供。</param>
            /// <returns>A byte array containing the decrypted data.<br></br>包含解密数据的字节数组。</returns>
            /// <exception cref="ArgumentException">Thrown when the key or IV is of incorrect length.<br></br>当密钥或 IV 长度不正确时抛出。</exception>
            /// <remarks>
            /// This method uses AES decryption in ECB mode, which does not use the IV and is not recommended for secure decryption due to potential security vulnerabilities.<br></br>Note: ECB mode can expose patterns in the ciphertext.<br></br>该方法使用 ECB 模式的 AES 解密，不使用 IV，并且由于潜在的安全漏洞，不建议用于安全解密。<br></br>注意：ECB 模式可能暴露密文中的模式。
            /// </remarks>
            public static byte[] DecryptBytesToFile(byte[] cipherData, string key, string iv)
            {
                // 确保密钥长度为32字节（256位），AES-256需要此长度
                if (key.Length != 32) throw new ArgumentException("密钥必须是32个字符长。");
                // 确保IV长度为16字节（128位），虽然ECB模式下不实际使用IV
                if (iv.Length != 16) throw new ArgumentException("IV必须是16个字符长。");

                // 将密钥和IV从字符串转换为字节数组
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv); // 在ECB模式下IV不会被实际使用

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置为ECB模式
                    aes.Padding = PaddingMode.ANSIX923; // 设置为ANSIX923填充模式
                    aes.Key = keyBytes; // 设置密钥
                    aes.IV = ivBytes; // 设置IV（在ECB模式下不实际使用）

                    // 创建解密器
                    var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    using (var ms = new MemoryStream(cipherData))
                    using (var cryptoStream = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    using (var output = new MemoryStream())
                    {
                        // 从CryptoStream读取解密后的数据
                        cryptoStream.CopyTo(output);
                        // 返回解密后的字节数组
                        return output.ToArray();
                    }
                }
            }

            /// <summary>
            /// Encrypts the given byte array and writes the encrypted data to a file.
            /// 加密给定的字节数组，并将加密后的数据写入文件。
            /// </summary>
            /// <param name="data">The byte array containing the data to encrypt.<br></br>包含要加密的数据的字节数组。</param>
            /// <param name="outputFilePath">The path to the output file where the encrypted data will be written.<br></br>加密数据将被写入的输出文件路径。</param>
            /// <param name="key">The encryption key, must be 32 characters long. This key will be converted to a byte array.<br></br>加密密钥，必须为 32 个字符长。该密钥将被转换为字节数组。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被实际使用，但仍需提供。</param>
            /// <exception cref="ArgumentException">Thrown when the key or IV is of incorrect length.<br></br>当密钥或 IV 长度不正确时抛出。</exception>
            /// <remarks>
            /// This method uses AES encryption in ECB mode. Note that ECB mode does not use the IV and is generally not recommended for secure encryption due to its vulnerability to certain attacks.<br></br>该方法使用 ECB 模式的 AES 加密。注意，ECB 模式不使用 IV，并且通常不建议用于安全加密，因为它容易受到某些攻击。
            /// </remarks>
            public static void EncryptBytesToFile(byte[] data, string outputFilePath, string key, string iv)
            {
                // 确保密钥长度为32字节（256位），AES-256需要此长度
                if (key.Length != 32) throw new ArgumentException("密钥必须是32个字符长。");
                // 确保IV长度为16字节（128位），虽然ECB模式下IV不会被实际使用
                if (iv.Length != 16) throw new ArgumentException("IV必须是16个字符长。");

                // 将密钥和IV从字符串转换为字节数组
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv); // 在ECB模式下IV不会被实际使用

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置为ECB模式
                    aes.Padding = PaddingMode.ANSIX923; // 设置为ANSIX923填充模式
                    aes.Key = keyBytes; // 设置密钥
                    aes.IV = ivBytes; // 设置IV（在ECB模式下不实际使用）

                    // 创建加密器
                    var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                    using (var outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    using (var cryptoStream = new CryptoStream(outputFileStream, encryptor, CryptoStreamMode.Write))
                    {
                        // 将数据写入CryptoStream进行加密
                        cryptoStream.Write(data, 0, data.Length);
                        cryptoStream.FlushFinalBlock(); // 确保所有数据都已加密
                    }
                }
            }

            /// <summary>
            /// Decrypts the data from a file and returns the decrypted byte array.
            /// 从文件中解密数据并返回解密后的字节数组。
            /// </summary>
            /// <param name="inputFilePath">The path to the input file containing the encrypted data.<br></br>包含加密数据的输入文件路径。</param>
            /// <param name="key">The decryption key, must be 32 characters long. This key will be converted to a byte array.<br></br>解密密钥，必须为 32 个字符长。该密钥将被转换为字节数组。</param>
            /// <param name="iv">The initialization vector, must be 16 characters long. In ECB mode, this value is not used but still needs to be provided.<br></br>初始化向量，必须为 16 个字符长。在 ECB 模式下，此值不会被实际使用，但仍需提供。</param>
            /// <returns>A byte array containing the decrypted data.<br></br>包含解密数据的字节数组。</returns>
            /// <exception cref="ArgumentException">Thrown when the key or IV is of incorrect length.<br></br>当密钥或 IV 长度不正确时抛出。</exception>
            /// <remarks>
            /// This method uses AES decryption in ECB mode. Note that ECB mode does not use the IV and is generally not recommended for secure decryption due to its vulnerability to certain attacks.<br></br>该方法使用 ECB 模式的 AES 解密。注意，ECB 模式不使用 IV，并且通常不建议用于安全解密，因为它容易受到某些攻击。
            /// </remarks>
            public static byte[] DecryptFileToBytes(string inputFilePath, string key, string iv)
            {
                // 确保密钥长度为32字节（256位），AES-256需要此长度
                if (key.Length != 32) throw new ArgumentException("密钥必须是32个字符长。");
                // 确保IV长度为16字节（128位），虽然ECB模式下IV不会被实际使用
                if (iv.Length != 16) throw new ArgumentException("IV必须是16个字符长。");

                // 将密钥和IV从字符串转换为字节数组
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var ivBytes = Encoding.UTF8.GetBytes(iv); // 在ECB模式下IV不会被实际使用

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB; // 设置为ECB模式
                    aes.Padding = PaddingMode.ANSIX923; // 设置为ANSIX923填充模式
                    aes.Key = keyBytes; // 设置密钥
                    aes.IV = ivBytes; // 设置IV（在ECB模式下不实际使用）

                    // 创建解密器
                    var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    using (var inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                    using (var cryptoStream = new CryptoStream(inputFileStream, decryptor, CryptoStreamMode.Read))
                    using (var ms = new MemoryStream())
                    {
                        // 从CryptoStream读取解密后的数据
                        cryptoStream.CopyTo(ms);
                        // 返回解密后的字节数组
                        return ms.ToArray();
                    }
                }
            }
        }
    }
}

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace DES.CBC
{
    /// <summary>
    /// It is used to encrypt DES in CBC mode.(Only for text.)<br></br>
    /// 用于以CBC模式加密DES。(仅限文本。)
    /// </summary>
    public class DesCbcTextCrypto
    {
        /// <summary>
        /// Encrypts a plain text string using DES encryption in CBC mode and returns the result as a Base64-encoded string.<br></br>
        /// 以CBC模式使用DES加密对纯文本字符串进行加密，并将结果作为base64编码的字符串返回。
        /// </summary>
        /// <param name="plainText">The plain text to encrypt.<br></br>要加密的纯文本。</param>
        /// <param name="key">The encryption key as a string. It should be 8 bytes long for DES.<br></br>加密密钥为字符串。对于DES，它应该是8字节长。</param>
        /// <param name="iv">The initialization vector (IV) as a string. It should be 8 bytes long for DES.<br></br>初始化向量(IV)为字符串。对于DES，它应该是8字节长。</param>
        /// <returns>A Base64-encoded string representing the encrypted data.|表示加密数据的base64编码字符串。</returns>
        /// <exception cref="ArgumentException">Thrown when the key or IV is not the correct length (8 bytes).|当key或IV不是正确的长度(8字节)时抛出。</exception>
        /// <remarks>
        /// DES encryption requires the key and IV to be exactly 8 bytes each. Ensure that both the key and IV are properly padded or truncated to 8 bytes as needed.<br></br>
        /// DES加密要求密钥和IV各为8字节。确保键和IV都被适当填充或根据需要截断为8字节。
        /// </remarks>
        public static string Encrypt(string plainText, string key, string iv)
        {
            byte[] plaintextBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] ivBytes = Encoding.UTF8.GetBytes(iv);

            using (System.Security.Cryptography.DES desAlg = System.Security.Cryptography.DES.Create())
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

        /// <summary>
        /// Decrypts a Base64-encoded encrypted text string using DES decryption in CBC mode and returns the result as a plain text string.<br></br>
        /// 使用CBC模式下的DES解密base64编码的加密文本字符串，并将结果作为纯文本字符串返回。
        /// </summary>
        /// <param name="encryptedText">The Base64-encoded encrypted text to decrypt.<br></br>要解密的base64编码的加密文本。</param>
        /// <param name="key">The decryption key as a string. It should be 8 bytes long for DES.<br></br>作为字符串的解密密钥。对于DES，它应该是8字节长。</param>
        /// <param name="iv">The initialization vector (IV) as a string. It should be 8 bytes long for DES.<br></br>初始化向量(IV)为字符串。对于DES，它应该是8字节长。</param>
        /// <returns>The decrypted plain text string.|解密后的纯文本字符串。</returns>
        /// <exception cref="ArgumentException">Thrown when the key or IV is not the correct length (8 bytes).<br></br>当key或IV不是正确的长度(8字节)时抛出。</exception>
        /// <remarks>
        /// DES decryption requires the key and IV to be exactly 8 bytes each. Ensure that both the key and IV are properly padded or truncated to 8 bytes as needed.<br></br>
        /// DES解密要求密钥和IV各为8字节。确保键和IV都被适当填充或根据需要截断为8字节。
        /// </remarks>
        public static string Decrypt(string encryptedText, string key, string iv)
        {
            byte[] cipherTextBytes = Convert.FromBase64String(encryptedText);
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] ivBytes = Encoding.UTF8.GetBytes(iv);

            using (System.Security.Cryptography.DES desAlg = System.Security.Cryptography.DES.Create())
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
}

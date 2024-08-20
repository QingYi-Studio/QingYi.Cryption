using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace DES.ECB
{
    /// <summary>
    /// Provides methods for encrypting and decrypting text using DES in ECB mode.<br></br>
    /// 提供在ECB模式下使用DES加密和解密文本的方法。
    /// </summary>
    public class DesEcbTextCrypto
    {
        private readonly byte[] _key;

        /// <summary>
        /// Initializes a new instance of the <see cref="DesEcbTextCryption"/> class with the specified key.<br></br>
        /// 用指定的密钥初始化 <see cref="DesEcbTextCryption"/> 类的新实例。
        /// </summary>
        /// <param name="key">The key used for encryption and decryption. It must be 8 bytes long.<br></br>用于加密和解密的密钥。长度必须为8字节。</param>
        /// <exception cref="ArgumentException">Thrown when the key length is not 8 bytes.|当密钥长度不是8字节时抛出。</exception>
        public DesEcbTextCrypto(string key)
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

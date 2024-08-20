using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace DES.ECB
{
    /// <summary>
    /// Provides methods for encrypting and decrypting files using DES encryption in ECB mode.<br></br>
    /// 提供在ECB模式下使用DES加密对文件进行加密和解密的方法。
    /// </summary>
    public class DesEcbFileCrypto
    {
        private readonly byte[] _key;

        /// <summary>
        /// Initializes a new instance of the <see cref="DesEcbFileCrypto"/> class with the specified DES key.<br></br>
        /// 使用指定的DES密钥初始化 <see cref="DesEcbFileCrypto"/> 类的新实例。
        /// </summary>
        /// <param name="key">The encryption key as a string. It must be exactly 8 bytes long.<br></br>加密密钥为字符串。它必须正好是8字节长。</param>
        /// <exception cref="ArgumentException">Thrown when the key length is not 8 bytes.<br></br>当密钥长度不是8字节时抛出。</exception>
        public DesEcbFileCrypto(string key)
        {
            if (key.Length != 8)
            {
                throw new ArgumentException("DES key must be 8 bytes long");
            }
            _key = Encoding.UTF8.GetBytes(key);
        }

        /// <summary>
        /// Encrypts the contents of the specified input file and writes the encrypted data to the specified output file using DES encryption in ECB mode.<br></br>
        /// 对指定输入文件的内容进行加密，加密后的数据以ECB方式采用DES加密方式写入指定输出文件。
        /// </summary>
        /// <param name="inputFilePath">The path to the input file containing the data to encrypt.<br></br>包含要加密的数据的输入文件的路径。</param>
        /// <param name="outputFilePath">The path to the output file where the encrypted data will be written.<br></br>将写入加密数据的输出文件的路径。</param>
        /// <exception cref="FileNotFoundException">Thrown when the input file does not exist.<br></br>当输入文件不存在时抛出。</exception>
        /// <exception cref="UnauthorizedAccessException">Thrown when the program lacks permissions to access the file system.<br></br>当程序缺乏访问文件系统的权限时抛出。</exception>
        public void Encrypt(string inputFilePath, string outputFilePath)
        {
            byte[] fileBytes = File.ReadAllBytes(inputFilePath);

            using (System.Security.Cryptography.DES des = System.Security.Cryptography.DES.Create())
            {
                des.Mode = CipherMode.ECB;
                des.Padding = PaddingMode.PKCS7;

                using (ICryptoTransform encryptor = des.CreateEncryptor(_key, null))
                {
                    byte[] encryptedBytes = PerformCryptography(fileBytes, encryptor);
                    File.WriteAllBytes(outputFilePath, encryptedBytes);
                }
            }
        }

        /// <summary>
        /// Decrypts the contents of the specified input file and writes the decrypted data to the specified output file using DES decryption in ECB mode.<br></br>
        /// 解密指定输入文件的内容，并使用ECB模式的DES解密将解密后的数据写入指定的输出文件。
        /// </summary>
        /// <param name="inputFilePath">The path to the input file containing the encrypted data.<br></br>包含加密数据的输入文件的路径。</param>
        /// <param name="outputFilePath">The path to the output file where the decrypted data will be written.<br></br>将在其中写入解密数据的输出文件的路径。</param>
        /// <exception cref="FileNotFoundException">Thrown when the input file does not exist.<br></br>当输入文件不存在时抛出。</exception>
        /// <exception cref="UnauthorizedAccessException">Thrown when the program lacks permissions to access the file system.<br></br>当程序缺乏访问文件系统的权限时抛出。</exception>
        public void Decrypt(string inputFilePath, string outputFilePath)
        {
            byte[] fileBytes = File.ReadAllBytes(inputFilePath);

            using (System.Security.Cryptography.DES des = System.Security.Cryptography.DES.Create())
            {
                des.Mode = CipherMode.ECB;
                des.Padding = PaddingMode.PKCS7;

                using (ICryptoTransform decryptor = des.CreateDecryptor(_key, null))
                {
                    byte[] decryptedBytes = PerformCryptography(fileBytes, decryptor);
                    File.WriteAllBytes(outputFilePath, decryptedBytes);
                }
            }
        }

        /// <summary>
        /// Performs encryption or decryption on the provided data using the specified cryptographic transform.<br></br>
        /// 使用指定的加密转换对提供的数据执行加密或解密。
        /// </summary>
        /// <param name="data">The data to encrypt or decrypt.<br></br>要加密或解密的数据。</param>
        /// <param name="cryptoTransform">The cryptographic transform to apply to the data.<br></br>要应用于数据的加密转换。</param>
        /// <returns>A byte array containing the transformed data.|包含已转换数据的字节数组。</returns>
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

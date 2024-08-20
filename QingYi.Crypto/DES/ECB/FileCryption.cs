﻿using System;
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
        /// <summary>
        /// Encrypts the contents of the specified input file and writes the encrypted data to the specified output file using DES encryption in ECB mode.<br></br>
        /// 对指定输入文件的内容进行加密，加密后的数据以ECB方式采用DES加密方式写入指定输出文件。
        /// </summary>
        /// <param name="inputFilePath">The path to the input file containing the data to encrypt.<br></br>包含要加密的数据的输入文件的路径。</param>
        /// <param name="outputFilePath">The path to the output file where the encrypted data will be written.<br></br>将写入加密数据的输出文件的路径。</param>
        /// <param name="key">The encryption key as a string. It should be 8 bytes long for DES.<br></br>加密密钥为字符串。对于DES，它应该是8字节长。</param>
        /// <exception cref="FileNotFoundException">Thrown when the input file does not exist.<br></br>当输入文件不存在时抛出。</exception>
        /// <exception cref="UnauthorizedAccessException">Thrown when the program lacks permissions to access the file system.<br></br>当程序缺乏访问文件系统的权限时抛出。</exception>
        public static void EncryptFile(string inputFilePath, string outputFilePath, string key)
        {
            byte[] fileBytes = File.ReadAllBytes(inputFilePath);

            using (System.Security.Cryptography.DES des = System.Security.Cryptography.DES.Create())
            {
                des.Mode = CipherMode.ECB;
                des.Padding = PaddingMode.PKCS7;

                using (ICryptoTransform encryptor = des.CreateEncryptor(Encoding.UTF8.GetBytes(key), null))
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
        /// <param name="key">The encryption key as a string. It should be 8 bytes long for DES.<br></br>加密密钥为字符串。对于DES，它应该是8字节长。</param>
        /// <exception cref="FileNotFoundException">Thrown when the input file does not exist.<br></br>当输入文件不存在时抛出。</exception>
        /// <exception cref="UnauthorizedAccessException">Thrown when the program lacks permissions to access the file system.<br></br>当程序缺乏访问文件系统的权限时抛出。</exception>
        public static void DecryptFile(string inputFilePath, string outputFilePath, string key)
        {
            byte[] fileBytes = File.ReadAllBytes(inputFilePath);

            using (System.Security.Cryptography.DES des = System.Security.Cryptography.DES.Create())
            {
                des.Mode = CipherMode.ECB;
                des.Padding = PaddingMode.PKCS7;

                using (ICryptoTransform decryptor = des.CreateDecryptor(Encoding.UTF8.GetBytes(key), null))
                {
                    byte[] decryptedBytes = PerformCryptography(fileBytes, decryptor);
                    File.WriteAllBytes(outputFilePath, decryptedBytes);
                }
            }
        }

        /// <summary>
        /// Encrypts the contents of the specified input file and writes the encrypted data to the specified output file using DES encryption in ECB mode.<br></br>
        /// 对指定输入文件的内容进行加密，加密后的数据以ECB方式采用DES加密方式写入指定输出文件。
        /// </summary>
        /// <param name="inputFilePath">The path to the input file containing the data to encrypt.<br></br>包含要加密的数据的输入文件的路径。</param>
        /// <param name="key">The encryption key as a string. It should be 8 bytes long for DES.<br></br>加密密钥为字符串。对于DES，它应该是8字节长。</param>
        /// <exception cref="FileNotFoundException">Thrown when the input file does not exist.<br></br>当输入文件不存在时抛出。</exception>
        /// <exception cref="UnauthorizedAccessException">Thrown when the program lacks permissions to access the file system.<br></br>当程序缺乏访问文件系统的权限时抛出。</exception>
        /// <returns>The encrypted file as a byte array.|加密文件作为字节数组。</returns>
        public static byte[] EncryptFileToBytes(string inputFilePath, string key)
        {
            byte[] fileBytes = File.ReadAllBytes(inputFilePath);

            using (System.Security.Cryptography.DES des = System.Security.Cryptography.DES.Create())
            {
                des.Mode = CipherMode.ECB;
                des.Padding = PaddingMode.PKCS7;

                using (ICryptoTransform encryptor = des.CreateEncryptor(Encoding.UTF8.GetBytes(key), null))
                {
                    byte[] encryptedBytes = PerformCryptography(fileBytes, encryptor);
                    return encryptedBytes;
                }
            }
        }

        /// <summary>
        /// Decrypts the contents of the specified input file and writes the decrypted data to the specified output file using DES decryption in ECB mode.<br></br>
        /// 解密指定输入文件的内容，并使用ECB模式的DES解密将解密后的数据写入指定的输出文件。
        /// </summary>
        /// <param name="fileBytes">An encrypted array of file bytes.<br></br>被加密的文件字节数组。</param>
        /// <param name="outputFilePath">The path to the output file where the decrypted data will be written.<br></br>将在其中写入解密数据的输出文件的路径。</param>
        /// <param name="key">The encryption key as a string. It should be 8 bytes long for DES.<br></br>加密密钥为字符串。对于DES，它应该是8字节长。</param>
        /// <exception cref="FileNotFoundException">Thrown when the input file does not exist.<br></br>当输入文件不存在时抛出。</exception>
        /// <exception cref="UnauthorizedAccessException">Thrown when the program lacks permissions to access the file system.<br></br>当程序缺乏访问文件系统的权限时抛出。</exception>
        public static void DecryptBytesToFile(byte[] fileBytes, string outputFilePath, string key)
        {
            using (System.Security.Cryptography.DES des = System.Security.Cryptography.DES.Create())
            {
                des.Mode = CipherMode.ECB;
                des.Padding = PaddingMode.PKCS7;

                using (ICryptoTransform decryptor = des.CreateDecryptor(Encoding.UTF8.GetBytes(key), null))
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
        private static byte[] PerformCryptography(byte[] data, ICryptoTransform cryptoTransform)
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

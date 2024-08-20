using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace DES.CBC
{
    /// <summary>
    /// It is used to encrypt DES in CBC mode.(Only for file.)<br></br>
    /// 用于以CBC方式加密DES。(仅供文件。)
    /// </summary>
    public class DesCbcFileCrypto
    {
        /// <summary>
        /// Encrypts the contents of a specified input file using DES encryption in CBC mode and writes the encrypted data to an output file.<br></br>
        /// 以CBC方式使用DES加密对指定输入文件的内容进行加密，并将加密后的数据写入输出文件。
        /// </summary>
        /// <param name="inputFile">The path to the input file containing the data to encrypt.<br></br>包含要加密的数据的输入文件的路径。</param>
        /// <param name="outputFile">The path to the output file where the encrypted data will be written.<br></br>将写入加密数据的输出文件的路径。</param>
        /// <param name="key">The encryption key as a string. It should be 8 bytes long for DES.<br></br>加密密钥为字符串。对于DES，它应该是8字节长。</param>
        /// <param name="iv">The initialization vector (IV) as a string. It should be 8 bytes long for DES.<br></br>初始化向量(IV)为字符串。对于DES，它应该是8字节长。</param>
        /// <exception cref="ArgumentException">Thrown when the key or IV is not the correct length (8 bytes).<br></br>当key或IV不是正确的长度(8字节)时抛出。</exception>
        /// <exception cref="FileNotFoundException">Thrown when the input file does not exist.<br></br>当输入文件不存在时抛出。</exception>
        /// <exception cref="UnauthorizedAccessException">Thrown when the program lacks permissions to access the file system.<br></br>当程序缺乏访问文件系统的权限时抛出。</exception>
        /// <remarks>
        /// DES encryption requires the key and IV to be exactly 8 bytes each. Ensure that both the key and IV are properly padded or truncated to 8 bytes as needed. The input file must exist, and the output file will be created or overwritten.<br></br>
        /// DES加密要求密钥和IV各为8字节。确保键和IV都被适当填充或根据需要截断为8字节。输入文件必须存在，输出文件将被创建或覆盖。
        /// </remarks>
        public static void EncryptFile(string inputFile, string outputFile, string key, string iv)
        {
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] ivBytes = Encoding.UTF8.GetBytes(iv);

            using (System.Security.Cryptography.DES desAlg = System.Security.Cryptography.DES.Create())
            {
                desAlg.Mode = CipherMode.CBC;
                desAlg.Key = keyBytes;
                desAlg.IV = ivBytes;

                using (FileStream fsInput = new FileStream(inputFile, FileMode.Open, FileAccess.Read))
                using (FileStream fsOutput = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
                {
                    using (CryptoStream csEncrypt = new CryptoStream(fsOutput, desAlg.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        int data;
                        while ((data = fsInput.ReadByte()) != -1)
                        {
                            csEncrypt.WriteByte((byte)data);
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Decrypts the contents of a specified input file using DES decryption in CBC mode and writes the decrypted data to an output file.<br></br>
        /// 在CBC模式下使用DES解密对指定输入文件的内容进行解密，并将解密后的数据写入输出文件。
        /// </summary>
        /// <param name="inputFile">The path to the input file containing the encrypted data.<br></br>包含加密数据的输入文件的路径。</param>
        /// <param name="outputFile">The path to the output file where the decrypted data will be written.<br></br>将在其中写入解密数据的输出文件的路径。</param>
        /// <param name="key">The decryption key as a string. It should be 8 bytes long for DES.<br></br>作为字符串的解密密钥。对于DES，它应该是8字节长。</param>
        /// <param name="iv">The initialization vector (IV) as a string. It should be 8 bytes long for DES.<br></br>初始化向量(IV)为字符串。对于DES，它应该是8字节长。</param>
        /// <exception cref="ArgumentException">Thrown when the key or IV is not the correct length (8 bytes).<br></br>当key或IV不是正确的长度(8字节)时抛出。</exception>
        /// <exception cref="FileNotFoundException">Thrown when the input file does not exist.<br></br>当输入文件不存在时抛出。</exception>
        /// <exception cref="UnauthorizedAccessException">Thrown when the program lacks permissions to access the file system.<br></br>当程序缺乏访问文件系统的权限时抛出。</exception>
        /// <remarks>
        /// DES decryption requires the key and IV to be exactly 8 bytes each. Ensure that both the key and IV are properly padded or truncated to 8 bytes as needed. The input file must exist, and the output file will be created or overwritten.<br></br>
        /// DES解密要求密钥和IV各为8字节。确保键和IV都被适当填充或根据需要截断为8字节。输入文件必须存在，输出文件将被创建或覆盖。
        /// </remarks>
        public static void DecryptFile(string inputFile, string outputFile, string key, string iv)
        {
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] ivBytes = Encoding.UTF8.GetBytes(iv);

            using (System.Security.Cryptography.DES desAlg = System.Security.Cryptography.DES.Create())
            {
                desAlg.Mode = CipherMode.CBC;
                desAlg.Key = keyBytes;
                desAlg.IV = ivBytes;

                using (FileStream fsInput = new FileStream(inputFile, FileMode.Open, FileAccess.Read))
                using (FileStream fsOutput = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(fsInput, desAlg.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        int data;
                        while ((data = csDecrypt.ReadByte()) != -1)
                        {
                            fsOutput.WriteByte((byte)data);
                        }
                    }
                }
            }
        }
    }
}

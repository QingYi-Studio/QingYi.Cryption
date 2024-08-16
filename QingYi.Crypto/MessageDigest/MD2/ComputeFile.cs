using System;
using System.IO;

namespace MessageDigest.MD2
{
    /// <summary>
    /// Calculate the MD2 of the file.<br></br>
    /// 计算文件的MD2。
    /// </summary>
    public class ComputeFileMD2
    {
        /// <summary>
        /// Computes the MD2 hash of the file at the specified path and returns the hash value as a hexadecimal string.<br></br>
        /// 计算指定路径文件的 MD2 哈希，并返回哈希值的十六进制字符串表示形式。
        /// </summary>
        /// <param name="filePath">The path of the file to hash.<br></br>要进行哈希的文件路径。</param>
        /// <returns>A hexadecimal string representation of the MD2 hash of the file contents.|文件内容的 MD2 哈希值的十六进制字符串表示形式。</returns>
        /// <exception cref="Exception">Thrown when an error occurs while reading the file or computing the MD2 hash.|当读取文件或计算 MD2 哈希时发生错误时抛出。</exception>
        public static string ComputeHex(string filePath)
        {
            try
            {
                // 读取文件内容
                byte[] fileData = File.ReadAllBytes(filePath);

                // 输出缓冲区，长度为 MD2 哈希的字节长度
                byte[] fileHashOutput = new byte[16];  // MD2 哈希的长度为 16 字节

                // 计算 MD2 哈希
                int fileResult = MD2.ComputeMD2Hash(fileHashOutput, fileData, fileData.Length);

                // 检查计算是否成功
                if (fileResult == 0)
                {
                    // 输出哈希值为十六进制格式
                    return BitConverter.ToString(fileHashOutput).Replace("-", "").ToLower();
                }
                else
                {
                    throw new Exception("MD2 Hash computation failed.");
                }
            }
            catch (Exception ex)
            {
                throw new Exception("An error occurred: " + ex.Message);
            }
        }

        /// <summary>
        /// Computes the MD2 hash of the file at the specified path and returns the hash value as a hexadecimal string.<br></br>
        /// 计算指定路径文件的 MD2 哈希，并返回哈希值的 Base64 编码字符串表示形式。
        /// </summary>
        /// <param name="filePath">The path of the file to hash.<br></br>要进行哈希的文件路径。</param>
        /// <returns>A hexadecimal string representation of the MD2 hash of the file contents.|文件内容的 MD2 哈希值的 Base64 编码字符串表示形式。</returns>
        /// <exception cref="Exception">Thrown when an error occurs while reading the file or computing the MD2 hash.|当读取文件或计算 MD2 哈希时发生错误时抛出。</exception>
        public static string ComputeBase64(string filePath)
        {
            try
            {
                // 读取文件内容
                byte[] fileData = File.ReadAllBytes(filePath);

                // 输出缓冲区，长度为 MD2 哈希的字节长度
                byte[] fileHashOutput = new byte[16];  // MD2 哈希的长度为 16 字节

                // 计算 MD2 哈希
                int fileResult = MD2.ComputeMD2Hash(fileHashOutput, fileData, fileData.Length);

                // 检查计算是否成功
                if (fileResult == 0)
                {
                    // 输出哈希值为 Base64 格式
                    return Convert.ToBase64String(fileHashOutput);
                }
                else
                {
                    throw new Exception("MD2 Hash computation failed.");
                }
            }
            catch (Exception ex)
            {
                throw new Exception("An error occurred: " + ex.Message);
            }
        }
    }
}

using System;
using System.Text;

namespace MessageDigest.MD2
{
    /// <summary>
    /// Calculate the MD2 of the text.<br></br>
    /// 计算文本的MD2。
    /// </summary>
    public class ComputeTextMD2
    {
        /// <summary>
        /// Computes the MD2 hash of the given input string and returns the hash value as a hexadecimal string.<br></br>
        /// 计算给定输入字符串的 MD2 哈希，并返回哈希值的十六进制字符串表示形式。
        /// </summary>
        /// <param name="input">The input string to hash.<br></br>要进行哈希的输入字符串。</param>
        /// <returns>A hexadecimal string representation of the MD2 hash of the input string.|输入字符串的 MD2 哈希值的十六进制字符串表示形式。</returns>
        /// <exception cref="Exception">Thrown when the MD2 hash computation fails.|当 MD2 哈希计算失败时抛出。</exception>
        public static string ComputeHex(string input)
        {
            // 输入数据
            byte[] inputData = Encoding.UTF8.GetBytes(input);

            // 输出缓冲区，长度为 MD2 哈希的字节长度
            byte[] hashOutput = new byte[16];  // MD2 哈希的长度为 16 字节

            // 计算 MD2 哈希
            int result = MD2.ComputeMD2Hash(hashOutput, inputData, inputData.Length);

            // 检查计算是否成功
            if (result == 0)
            {
                // 输出哈希值为十六进制格式
                return BitConverter.ToString(hashOutput).Replace("-", "").ToLower();
            }
            else
            {
                throw new Exception("MD2 Hash computation failed.");
            }
        }

        /// <summary>
        /// Computes the MD2 hash of the given input string and returns the hash value as a hexadecimal string.<br></br>
        /// 计算给定输入字符串的 MD2 哈希，并返回哈希值的十六进制字符串表示形式。
        /// </summary>
        /// <param name="input">The input string to hash.<br></br>要进行哈希的输入字符串。</param>
        /// <returns>A hexadecimal string representation of the MD2 hash of the input string.|输入字符串的 MD2 哈希值的 Base64 编码字符串表示形式。</returns>
        /// <exception cref="Exception">Thrown when the MD2 hash computation fails.|当 MD2 哈希计算失败时抛出。</exception>
        public static string ComputeBase64(string input)
        {
            // 输入数据
            byte[] inputData = Encoding.UTF8.GetBytes(input);

            // 输出缓冲区，长度为 MD2 哈希的字节长度
            byte[] hashOutput = new byte[16];  // MD2 哈希的长度为 16 字节

            // 计算 MD2 哈希
            int result = MD2.ComputeMD2Hash(hashOutput, inputData, inputData.Length);

            // 检查计算是否成功
            if (result == 0)
            {
                // 输出哈希值为 Base64 格式
                return Convert.ToBase64String(hashOutput);
            }
            else
            {
                throw new Exception("MD2 Hash computation failed.");
            }
        }
    }
}

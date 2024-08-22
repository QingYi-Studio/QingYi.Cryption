using System.Text;
using System;

namespace MessageDigest.MD5
{
    /// <summary>
    /// Calculate the MD5 of the string.<br></br>
    /// 计算字符串的MD5。
    /// </summary>
    public class ComputeText
    {
        /// <summary>
        /// Calculates the MD5 hash of the given string and returns it as a Base64 encoded string.<br></br>
        /// 计算给定字符串的 MD5 哈希值，并返回 Base64 编码的字符串。
        /// </summary>
        /// <param name="input">The input string to compute the MD5 hash for.<br></br>要计算 MD5 哈希值的输入字符串。</param>
        /// <returns>The Base64 encoded MD5 hash value.|MD5 哈希值的 Base64 编码字符串。</returns>
        public static string ComputeMD5Base64(string input)
        {
            using (System.Security.Cryptography.MD5 md5 = System.Security.Cryptography.MD5.Create())
            {
                byte[] inputBytes = Encoding.UTF8.GetBytes(input);
                byte[] hashBytes = md5.ComputeHash(inputBytes);
                return Convert.ToBase64String(hashBytes);
            }
        }

        /// <summary>
        /// Calculates the MD5 hash of the given string and returns it as a hexadecimal encoded string.<br></br>
        /// 计算给定字符串的 MD5 哈希值，并返回十六进制编码的字符串。
        /// </summary>
        /// <param name="input">The input string to compute the MD5 hash for.<br></br>要计算 MD5 哈希值的输入字符串。</param>
        /// <returns>The hexadecimal encoded MD5 hash value.|MD5 哈希值的十六进制编码字符串。</returns>
        public static string ComputeMD5Hex(string input)
        {
            using (System.Security.Cryptography.MD5 md5 = System.Security.Cryptography.MD5.Create())
            {
                byte[] inputBytes = Encoding.UTF8.GetBytes(input);
                byte[] hashBytes = md5.ComputeHash(inputBytes);
                StringBuilder sb = new StringBuilder();
                foreach (byte b in hashBytes)
                {
                    sb.Append(b.ToString("x2"));
                }
                return sb.ToString();
            }
        }
    }
}

using System.IO;
using System.Text;
using System;

namespace MessageDigest.MD5
{
    /// <summary>
    /// Calculate the MD5 of the file.<br></br>
    /// 计算文件的MD5。
    /// </summary>
    public class ComputeFile
    {
        /// <summary>
        /// Computes the MD5 hash of a file and returns it as a Base64 encoded string.<br></br>
        /// 计算文件的 MD5 哈希值，并返回 Base64 编码的字符串。
        /// </summary>
        /// <param name="filePath">The path of the file to compute the MD5 hash for.<br></br>要计算 MD5 哈希值的文件路径。</param>
        /// <returns>The Base64 encoded MD5 hash value.|MD5 哈希值的 Base64 编码字符串。</returns>
        public static string ComputeFileMD5Base64(string filePath)
        {
            using (System.Security.Cryptography.MD5 md5 = System.Security.Cryptography.MD5.Create())
            using (FileStream fileStream = File.OpenRead(filePath))
            {
                byte[] hashBytes = md5.ComputeHash(fileStream);
                return Convert.ToBase64String(hashBytes);
            }
        }

        /// <summary>
        /// Computes the MD5 hash of a file and returns it as a hexadecimal encoded string.<br></br>
        /// 计算文件的 MD5 哈希值，并返回十六进制编码的字符串。
        /// </summary>
        /// <param name="filePath">The path of the file to compute the MD5 hash for.<br></br>要计算 MD5 哈希值的文件路径。</param>
        /// <returns>The hexadecimal encoded MD5 hash value.|MD5 哈希值的十六进制编码字符串。</returns>
        public static string ComputeFileMD5Hex(string filePath)
        {
            using (System.Security.Cryptography.MD5 md5 = System.Security.Cryptography.MD5.Create())
            using (FileStream fileStream = File.OpenRead(filePath))
            {
                byte[] hashBytes = md5.ComputeHash(fileStream);
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

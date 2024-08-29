using System.Text;
using System;
using System.IO;

namespace SecureHashAlgorithm
{
    /// <summary>
    /// Compute SHA-1.
    /// 计算SHA-1值。
    /// </summary>
    public class SHA1
    {
        /// <summary>
        /// Computes the SHA1 hash of the input string and returns it as a Base64-encoded string.<br/>
        /// 计算输入字符串的SHA1散列，并将其作为base64编码的字符串返回。
        /// </summary>
        /// <param name="input">The input string to compute the SHA1 hash for.<br/>要计算SHA1哈希值的输入字符串。</param>
        /// <returns>A Base64-encoded string representing the SHA1 hash of the input string.<br/>一个Base64编码的字符串，表示输入字符串的SHA1哈希值。</returns>
        public static string ComputeString_Base64(string input)
        {
            // 将输入字符串转换为字节数组
            byte[] data = Encoding.UTF8.GetBytes(input);

            // 创建SHA1实例
            using (System.Security.Cryptography.SHA1 sha1 = System.Security.Cryptography.SHA1.Create())
            {
                // 计算哈希值
                byte[] hashBytes = sha1.ComputeHash(data);

                // 将哈希值转换为Base64字符串
                return Convert.ToBase64String(hashBytes);
            }
        }

        /// <summary>
        /// Computes the SHA1 hash of the input string and returns it as a hexadecimal string.<br/>
        /// 计算输入字符串的SHA1哈希值，并以十六进制字符串的形式返回。
        /// </summary>
        /// <param name="input">The input string to compute the SHA1 hash for.<br/>要计算SHA1哈希值的输入字符串。</param>
        /// <returns>A hexadecimal string representing the SHA1 hash of the input string.<br/>十六进制字符串，表示输入字符串的SHA1哈希值。</returns>
        public static string ComputeString_Hex(string input)
        {
            // 将输入字符串转换为字节数组
            byte[] data = Encoding.UTF8.GetBytes(input);

            // 创建SHA实例
            using (System.Security.Cryptography.SHA1 sha1 = System.Security.Cryptography.SHA1.Create())
            {
                // 计算哈希值
                byte[] hashBytes = sha1.ComputeHash(data);

                // 将哈希值转换为十六进制字符串
                StringBuilder sb = new StringBuilder();
                foreach (byte b in hashBytes)
                {
                    sb.Append(b.ToString("x2")); // 转换为十六进制格式
                }

                return sb.ToString();
            }
        }

        /// <summary>
        /// Computes the SHA1 hash of the file specified by the file path and returns it as a Base64-encoded string.<br/>
        /// 计算由文件路径指定的文件的SHA1哈希值，并将其作为Base64编码的字符串返回。
        /// </summary>
        /// <param name="filePath">The path to the file to compute the SHA1 hash for.<br/>要计算SHA1哈希值的文件的路径。</param>
        /// <returns>A Base64-encoded string representing the SHA1 hash of the file.<br/>Base64编码的字符串，表示文件的SHA1哈希值。</returns>
        public static string ComputeFile_Base64(string filePath)
        {
            using (FileStream fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            using (System.Security.Cryptography.SHA1 sha1 = System.Security.Cryptography.SHA1.Create())
            {
                // 计算文件哈希值
                byte[] hashBytes = sha1.ComputeHash(fileStream);

                // 将哈希值转换为Base64字符串
                return Convert.ToBase64String(hashBytes);
            }
        }

        /// <summary>
        /// Computes the SHA1 hash of the file specified by the file path and returns it as a hexadecimal string.<br/>
        /// 计算文件路径指定的文件的SHA1哈希值，并以十六进制字符串的形式返回。
        /// </summary>
        /// <param name="filePath">The path to the file to compute the SHA1 hash for.<br/>要计算SHA1哈希值的文件的路径。</param>
        /// <returns>A hexadecimal string representing the SHA1 hash of the file.<br/>十六进制字符串，表示文件的SHA1哈希值。</returns>
        public static string ComputeFile_Hex(string filePath)
        {
            using (FileStream fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            using (System.Security.Cryptography.SHA1 sha1 = System.Security.Cryptography.SHA1.Create())
            {
                // 计算文件哈希值
                byte[] hashBytes = sha1.ComputeHash(fileStream);

                // 将哈希值转换为十六进制字符串
                StringBuilder sb = new StringBuilder();
                foreach (byte b in hashBytes)
                {
                    sb.Append(b.ToString("x2")); // 转换为十六进制格式
                }

                return sb.ToString();
            }
        }

        /// <summary>
        /// Exports the SHA1 hash of the input string as a Base64-encoded string to a file.<br/>
        /// 将输入字符串的SHA1哈希作为base64编码的字符串导出到文件。
        /// </summary>
        /// <param name="input">The input string to compute the SHA1 hash for.<br/>要计算SHA1哈希值的输入字符串。</param>
        /// <param name="filePath">The path to the file where the Base64-encoded SHA1 hash should be saved.<br/>保存Base64编码的SHA1散列的文件的路径。</param>
        public static void ExportStringSha1_Base64(string input, string filePath)
        {
            Exporter.ExportFile(filePath, ".sha1", ComputeString_Base64(input));
        }

        /// <summary>
        /// Exports the SHA1 hash of the input string as a hexadecimal string to a file.<br/>
        /// 将输入字符串的SHA1哈希值以十六进制字符串的形式导出到文件中。
        /// </summary>
        /// <param name="input">The input string to compute the SHA1 hash for.<br/>要计算SHA1哈希值的输入字符串。</param>
        /// <param name="filePath">The path to the file where the hexadecimal SHA1 hash should be saved.<br/>保存十六进制SHA1哈希值的文件路径。</param>
        public static void ExportStringSha1_Hex(string input, string filePath)
        {
            Exporter.ExportFile(filePath, ".sha1", ComputeString_Hex(input));
        }

        /// <summary>
        /// Exports the SHA1 hash of the file specified by the file path as a Base64-encoded string to a file.<br/>
        /// 将文件路径指定的文件的SHA1哈希值以Base64编码字符串的形式导出到文件。
        /// </summary>
        /// <param name="filePath">The path to the file to compute the SHA1 hash for.<br/>要计算SHA1哈希值的文件的路径。</param>
        /// <param name="outputFilePath">The path to the file where the Base64-encoded SHA1 hash should be saved.<br/>应该保存base64编码的SHA1散列的文件的路径。</param>
        public static void ExportFileSha1_Base64(string filePath, string outputFilePath)
        {
            Exporter.ExportFile(outputFilePath, ".sha1", ComputeFile_Base64(filePath));
        }

        /// <summary>
        /// Exports the SHA1 hash of the file specified by the file path as a hexadecimal string to a file.<br/>
        /// 将文件路径指定的文件的SHA1哈希值以十六进制字符串形式导出到文件中。
        /// </summary>
        /// <param name="filePath">The path to the file to compute the SHA1 hash for.<br/>要计算SHA1哈希值的文件的路径。</param>
        /// <param name="outputFilePath">The path to the file where the hexadecimal SHA1 hash should be saved.<br/>保存十六进制SHA1哈希值的文件路径。</param>
        public static void ExportFileSha1_Hex(string filePath, string outputFilePath)
        {
            Exporter.ExportFile(outputFilePath, ".sha1", ComputeFile_Hex(filePath));
        }
    }
}

using System;
using System.IO;

namespace MessageDigest.MD4
{
    /// <summary>
    /// Calculate the MD4 of the file.<br></br>
    /// 计算文件的MD4。
    /// </summary>
    public class ComputeFile
    {
        private static readonly MD4 md4;

        /// <summary>
        /// <!--<strong>(Recommend)</strong>-->Returns a string that contains the hexadecimal hash<br></br>
        /// <!--<strong>(推荐)</strong>-->返回包含十六进制散列的字符串
        /// </summary>
        /// <param name = "filePath">file path to input<br></br>要输入的文件路径</param>
        /// <returns>String that contains the hex of the hash|包含哈希十六进制的字符串</returns>
        public static string GetHexHashFromFile(string filePath)
        {
            return md4.GetHexHashFromBytes(ReadBytes(filePath));
        }

        private static byte[] ReadBytes(string filePath)
        {
            if (string.IsNullOrEmpty(filePath))
                throw new ArgumentException("File path cannot be null or empty.", nameof(filePath));

            // 使用 FileStream 以二进制模式读取文件
            using (var fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            {
                // 获取文件大小
                long fileLength = fileStream.Length;
                byte[] fileBytes = new byte[fileLength];

                // 读取文件内容到字节数组
                int bytesRead = fileStream.Read(fileBytes, 0, (int)fileLength);

                // 检查读取的字节数是否与文件大小匹配
                if (bytesRead != fileLength)
                    throw new IOException("Unable to read the entire file.");

                return fileBytes;
            }
        }
    }
}

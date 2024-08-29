using System.IO;

namespace SecureHashAlgorithm
{
    internal class Exporter
    {
        /// <summary>
        /// 将指定的SHA值和版权信息导出到一个新文件中。
        /// </summary>
        /// <param name="filePath">源文件的完整路径，用于确定新文件的目录和名称。</param>
        /// <param name="newExtension">新文件的扩展名（包括点符号），例如 ".bak"。</param>
        /// <param name="sha">要写入新文件中的SHA值。</param>
        public static void ExportFile(string filePath, string newExtension, string sha)
        {
            // 要写入的新内容
            string[] lines = new string[]
            {
            sha,
            "Published by QingYi-Studio, Thanks for using."
            };

            // 创建新文件
            CreateNewFileWithContent(filePath, newExtension, lines);
        }

        /// <summary>
        /// 根据源文件路径和指定的扩展名创建一个新文件，并将内容写入新文件。
        /// </summary>
        /// <param name="filePath">源文件的完整路径，用于确定新文件的目录和名称。</param>
        /// <param name="newExtension">新文件的扩展名（包括点符号），例如 ".bak"。</param>
        /// <param name="content">要写入新文件中的内容，以字符串数组的形式提供。</param>
        static void CreateNewFileWithContent(string filePath, string newExtension, string[] content)
        {
            // 获取文件夹路径
            string directory = Path.GetDirectoryName(filePath);

            // 获取源文件名（不包含扩展名）
            string fileNameWithoutExtension = Path.GetFileNameWithoutExtension(filePath);

            // 创建新文件路径
            string newFilePath = Path.Combine(directory, fileNameWithoutExtension + newExtension);

            // 写入内容到新文件
            File.WriteAllLines(newFilePath, content);
        }
    }
}

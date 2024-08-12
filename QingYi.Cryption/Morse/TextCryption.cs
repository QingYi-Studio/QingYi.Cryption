using System.Collections.Generic;
using System.Text;
using System;
using System.IO;

namespace Morse
{
    /// <summary>
    /// Provides functionality to convert text to Morse code through Base64 encoding.<br></br>
    /// 提供通过Base64编码将文本转换为摩斯电码的功能。
    /// </summary>
    public class MorseTextCryption
    {
        private Dictionary<char, string> morseCodeMap;

        /// <summary>
        /// Initializes a new instance of the <see cref="MorseConverter"/> class.<br></br>
        /// Loads the default Morse code dictionary and optionally merges user-defined dictionary from a CSV file.<br></br>
        /// 初始化 <see cref="MorseConverter"/> 类的新实例。<br></br>
        /// 加载默认的摩斯电码字典，并可选择从CSV文件合并用户定义的字典。
        /// </summary>
        /// <param name="csvFilePath">The path to the CSV file containing user-defined Morse code mappings.<br></br>
        /// 包含用户自定义摩斯电码映射的CSV文件的路径。</param>
        public MorseTextCryption(string csvFilePath = null)
        {
            // 加载默认的摩斯电码字典
            morseCodeMap = LoadDefaultMorseCodeDictionary();

            // 可选：从CSV文件加载用户定义的摩斯电码字典
            if (!string.IsNullOrEmpty(csvFilePath))
            {
                var userDefinedMap = LoadMorseCodeDictionary(csvFilePath);
                if (userDefinedMap != null)
                {
                    // 合并用户定义字典，覆盖默认值
                    foreach (var kvp in userDefinedMap)
                    {
                        morseCodeMap[kvp.Key] = kvp.Value;
                    }
                }
            }
        }

        /// <summary>
        /// Loads the default Morse code dictionary.<br></br>
        /// 加载默认的摩斯电码字典。
        /// </summary>
        /// <returns>A dictionary containing default Morse code mappings.|包含默认摩斯电码映射的字典。</returns>
        private Dictionary<char, string> LoadDefaultMorseCodeDictionary()
        {
            return new Dictionary<char, string>
            {
                {'A', ".-"}, {'B', "-..."}, {'C', "-.-."}, {'D', "-.."}, {'E', "."},
                {'F', "..-."}, {'G', "--."}, {'H', "...."}, {'I', ".."}, {'J', ".---"},
                {'K', "-.-"}, {'L', ".-.."}, {'M', "--"}, {'N', "-."}, {'O', "---"},
                {'P', ".--."}, {'Q', "--.-"}, {'R', ".-."}, {'S', "..."}, {'T', "-"},
                {'U', "..-"}, {'V', "...-"}, {'W', ".--"}, {'X', "-..-"}, {'Y', "-.--"},
                {'Z', "--.."}, {'0', "-----"}, {'1', ".----"}, {'2', "..---"}, {'3', "...--"},
                {'4', "....-"}, {'5', "....."}, {'6', "-...."}, {'7', "--..."}, {'8', "---.."},
                {'9', "----."}, {' ', "/"}
            };
        }

        /// <summary>
        /// Loads a user-defined Morse code dictionary from a CSV file.<br></br>
        /// 从CSV文件加载用户定义的摩斯电码字典。
        /// </summary>
        /// <param name="filePath">The path to the CSV file.<br></br>CSV文件的路径。</param>
        /// <returns>A dictionary containing user-defined Morse code mappings, or null if an error occurs.|包含用户定义的摩斯电码映射的字典，如果发生错误，则为空。</returns>
        private Dictionary<char, string> LoadMorseCodeDictionary(string filePath)
        {
            var morseCodeMap = new Dictionary<char, string>();

            try
            {
                var lines = File.ReadAllLines(filePath);

                foreach (var line in lines)
                {
                    var parts = line.Split(',');
                    if (parts.Length == 2)
                    {
                        var character = parts[0].Trim().ToUpper()[0];
                        var morseCode = parts[1].Trim();
                        morseCodeMap[character] = morseCode;
                    }
                }

                return morseCodeMap;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error loading Morse code dictionary: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Converts a given text string to its Base64 encoded representation.<br></br>
        /// 将给定的文本字符串转换为其Base64编码表示形式。
        /// </summary>
        /// <param name="input">The input text string to convert.<br></br>要转换的输入文本字符串。</param>
        /// <returns>The Base64 encoded string.|Base64编码的字符串。</returns>
        public string ConvertTextToBase64(string input)
        {
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(input));
        }

        /// <summary>
        /// Converts a Base64 encoded string to its Morse code representation using the loaded dictionary.<br></br>
        /// 使用加载的字典将Base64编码的字符串转换为其摩斯电码表示形式。
        /// </summary>
        /// <param name="base64String">The Base64 encoded string to convert.<br></br>要转换的Base64编码字符串。</param>
        /// <returns>The Morse code representation of the Base64 encoded string.|Base64编码字符串的摩斯电码表示。</returns>
        public string ConvertBase64ToMorse(string base64String)
        {
            var sb = new StringBuilder();
            foreach (char c in base64String.ToUpper())
            {
                if (morseCodeMap.TryGetValue(c, out string morseCode))
                {
                    sb.Append(morseCode + " ");
                }
                else
                {
                    sb.Append(c + " "); // 保持字符不在映射中(例如，'+'或'/')
                }
            }

            return sb.ToString().Trim();
        }
    }
}

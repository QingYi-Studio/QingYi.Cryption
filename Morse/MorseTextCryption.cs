using System.Text;

namespace Morse
{
    /// <summary>
    /// Provides functionality to convert text to Morse code and vice versa through Base16 encoding.<br></br>
    /// 提供将文本转换为摩斯电码及其反向转换的功能，通过 Base16 编码进行处理。
    /// </summary>
    public class MorseTextCryption
    {
        private readonly Dictionary<char, string> morseCodeMap;
        private readonly Dictionary<string, char> reverseMorseCodeMap;

        public MorseTextCryption(Dictionary<char, string>? customMorseCodeMap = null)
        {
            morseCodeMap = customMorseCodeMap ?? LoadDefaultMorseCodeDictionary();
            reverseMorseCodeMap = CreateReverseMorseCodeMap(morseCodeMap);
        }

        /// <summary>
        /// Converts a text string to its Base16 (hexadecimal) representation.<br></br>
        /// 将文本字符串转换为其 Base16（十六进制）表示。
        /// </summary>
        /// <param name="text">The text string to convert.<br></br>要转换的文本字符串。</param>
        /// <returns>The Base16 (hexadecimal) representation of the text string.<br></br>文本字符串的 Base16（十六进制）表示。</returns>
        public string TextToBase16(string text)
        {
            var bytes = Encoding.UTF8.GetBytes(text);
            var sb = new StringBuilder(bytes.Length * 2);

            foreach (var b in bytes)
            {
                sb.AppendFormat("{0:X2}", b);
            }

            return sb.ToString();
        }

        /// <summary>
        /// Converts a Base16 (hexadecimal) string to its Morse code representation.<br></br>
        /// 将 Base16（十六进制）字符串转换为其摩斯电码表示。
        /// </summary>
        /// <param name="base16String">The Base16 (hexadecimal) string to convert.<br></br>要转换的 Base16（十六进制）字符串。</param>
        /// <returns>The Morse code representation of the Base16 (hexadecimal) string.<br></br>Base16（十六进制）字符串的摩斯电码表示。</returns>
        public string Base16ToMorse(string base16String)
        {
            var sb = new StringBuilder();

            foreach (char c in base16String.ToUpper())
            {
                if (morseCodeMap.TryGetValue(c, out string? morseCode))
                {
                    sb.Append(morseCode + " ");
                }
                else
                {
                    sb.Append(c + " "); // Keep characters not in the map as is (e.g., 'A', 'B', etc.)
                }
            }

            return sb.ToString().Trim();
        }

        /// <summary>
        /// Converts Morse code to Base16 (hexadecimal) representation.<br></br>
        /// 将摩斯电码转换为 Base16（十六进制）表示。
        /// </summary>
        /// <param name="morseCode">The Morse code string to convert.<br></br>要转换的摩斯电码字符串。</param>
        /// <returns>The Base16 (hexadecimal) representation of the Morse code.<br></br>摩斯电码的 Base16（十六进制）表示。</returns>
        public string MorseToBase16(string morseCode)
        {
            var sb = new StringBuilder();
            var morseWords = morseCode.Split(' ');

            foreach (var word in morseWords)
            {
                if (reverseMorseCodeMap.TryGetValue(word, out char character))
                {
                    sb.Append(character);
                }
                else
                {
                    sb.Append('?'); // Unknown Morse code
                }
            }

            return sb.ToString();
        }

        /// <summary>
        /// Converts Base16 (hexadecimal) representation back to original text.<br></br>
        /// 将 Base16（十六进制）表示转换回原始文本。
        /// </summary>
        /// <param name="base16String">The Base16 (hexadecimal) string to convert.<br></br>要转换的 Base16（十六进制）字符串。</param>
        /// <returns>The original text string.<br></br>原始文本字符串。</returns>
        public string Base16ToText(string base16String)
        {
            var bytes = new List<byte>();
            for (int i = 0; i < base16String.Length; i += 2)
            {
                var hex = base16String.Substring(i, 2);
                bytes.Add(Convert.ToByte(hex, 16));
            }

            return Encoding.UTF8.GetString(bytes.ToArray());
        }

        /// <summary>
        /// Loads the default Morse code dictionary.<br></br>
        /// 加载默认的摩斯电码字典。
        /// </summary>
        /// <returns>A dictionary containing default Morse code mappings.<br></br>包含默认摩斯电码映射的字典。</returns>
        private static Dictionary<char, string> LoadDefaultMorseCodeDictionary()
        {
            return new Dictionary<char, string>
        {
            {'0', "-----"}, {'1', ".----"}, {'2', "..---"}, {'3', "...--"}, {'4', "....-"}, {'5', "....."}, {'6', "-...."}, {'7', "--..."}, {'8', "---.."}, {'9', "----."},
            {'A', ".-"}, {'B', "-..."}, {'C', "-.-."}, {'D', "-.."}, {'E', "."}, {'F', "..-."}, {'G', "--."}, {'H', "...."}, {'I', ".."}, {'J', ".---"},
            {'K', "-.-"}, {'L', ".-.."}, {'M', "--"}, {'N', "-."}, {'O', "---"}, {'P', ".--."}, {'Q', "--.-"}, {'R', ".-."}, {'S', "..."}, {'T', "-"},
            {'U', "..-"}, {'V', "...-"}, {'W', ".--"}, {'X', "-..-"}, {'Y', "-.--"}, {'Z', "--.."},
            {' ', "/"},
            {'+', ".-.-."}, {'/', "-..-."}, {'=', "-...-"}
        };
        }

        /// <summary>
        /// Creates a reverse mapping of Morse code to characters.<br></br>
        /// 创建摩斯电码到字符的反向映射。
        /// </summary>
        /// <param name="morseCodeMap">The dictionary containing Morse code mappings.<br></br>包含摩斯电码映射的字典。</param>
        /// <returns>A dictionary containing the reverse Morse code mappings.<br></br>包含反向摩斯电码映射的字典。</returns>
        private static Dictionary<string, char> CreateReverseMorseCodeMap(Dictionary<char, string> morseCodeMap)
        {
            var reverseMap = new Dictionary<string, char>();
            foreach (var kvp in morseCodeMap)
            {
                reverseMap[kvp.Value] = kvp.Key;
            }
            return reverseMap;
        }
    }
}

using System.Text;

namespace QingYi.Cryption.Caesar
{
    public class CaesarTextCryption
    {
        /// <summary>
        /// Encrypts the specified text using Caesar cipher. Caesar cipher encrypts the text by shifting each character's Unicode value by a specified amount.<br></br>
        /// 对指定的文本进行凯撒加密。凯撒加密通过将每个字符的Unicode值按指定的位移量进行偏移来加密文本。
        /// </summary>
        /// <param name="text">
        /// The string to be encrypted. It can contain any Unicode characters, such as English, Chinese, special symbols, etc.<br></br>
        /// 要加密的字符串。可以包含任何Unicode字符，如英文、中文、特殊符号等。
        /// </param>
        /// <param name="shift">
        /// The amount of shift used for encryption. It can be a positive integer (shift to the right) or a negative integer (shift to the left).<br></br>
        /// 用于加密的位移量。可以是正整数（向右偏移）或负整数（向左偏移）。
        /// </param>
        /// <returns>
        /// The encrypted string. Each character in the string is shifted by the specified amount.<br></br>
        /// 加密后的字符串。该字符串中的每个字符都被移位了指定的位移量。
        /// </returns>
        public static string Encrypt(string text, int shift)
        {
            return CaesarEncrypt(text, shift);
        }

        /// <summary>
        /// Decrypts the specified encrypted text using Caesar cipher. Caesar decryption shifts each character's Unicode value in the reverse direction by a specified amount to decrypt the text.<br></br>
        /// 对指定的加密文本进行凯撒解密。凯撒解密通过将每个字符的Unicode值按指定的位移量进行反向偏移来解密文本。
        /// </summary>
        /// <param name="text">
        /// The encrypted string to be decrypted. It can contain any Unicode characters, such as English, Chinese, special symbols, etc.<br></br>
        /// 要解密的加密字符串。可以包含任何Unicode字符，如英文、中文、特殊符号等。
        /// </param>
        /// <param name="shift">
        /// The amount of shift used for decryption. It should be the same as the shift amount used for encryption.<br></br>
        /// 用于解密的位移量。应与加密时使用的位移量相同。
        /// </param>
        /// <returns>
        /// The decrypted string. Each character in the string is shifted by the specified amount to restore the original text.<br></br>
        /// 解密后的字符串。该字符串中的每个字符都被移位了指定的位移量，恢复到原始文本。
        /// </returns>
        public static string Decrypt(string text, int shift)
        {
            return CaesarDecrypt(text, shift);
        }

        private static string CaesarEncrypt(string text, int shift)
        {
            // 创建一个StringBuilder对象，用于存储加密后的字符
            StringBuilder result = new StringBuilder();
            // 遍历字符串中的每一个字符
            foreach (char c in text)
            {
                // 将字符加密shift位
                char encryptedChar = (char)(c + shift);
                // 将加密后的字符添加到StringBuilder对象中
                result.Append(encryptedChar);
            }
            // 将StringBuilder对象转换为字符串并返回
            return result.ToString();
        }

        private static string CaesarDecrypt(string text, int shift)
        {
            // 创建一个StringBuilder对象，用于存储解密后的字符
            StringBuilder result = new StringBuilder();
            // 遍历字符串中的每一个字符
            foreach (char c in text)
            {
                // 将字符解密shift位
                char decryptedChar = (char)(c - shift);
                // 将解密后的字符添加到StringBuilder对象中
                result.Append(decryptedChar);
            }
            // 将StringBuilder对象转换为字符串并返回
            return result.ToString();
        }
    }
}

namespace MessageDigest.MD4
{
    /// <summary>
    /// Calculate the MD4 of the string.<br></br>
    /// 计算字符串的MD4。
    /// </summary>
    public class ComputeText
    {
        private static readonly MD4 md4;

        /// <summary>
        /// Returns a string that contains the hexadecimal hash<br></br>
        /// 返回包含十六进制散列的字符串
        /// </summary>
        /// <param name = "s">string to hash<br></br>字符串到散列</param>
        /// <returns>String that contains the hex of the hash|包含哈希十六进制的字符串</returns>
        public static string GetHexHashFromString(string s)
        {
            return md4.GetHexHashFromString(s);
        }
    }
}

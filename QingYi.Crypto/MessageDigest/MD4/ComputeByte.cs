namespace MessageDigest.MD4
{
    /// <summary>
    /// Calculate the MD4 of the byte.<br></br>
    /// 计算字节的MD4。
    /// </summary>
    public class ComputeByte
    {
        private static readonly MD4 md4;

        /// <summary>
        /// Returns a string that contains the hexadecimal hash<br></br>
        /// 返回包含十六进制散列的字符串
        /// </summary>
        /// <param name = "b">byte-array to input<br></br>要输入的字节数组</param>
        /// <returns>String that contains the hex of the hash<br></br>包含哈希十六进制的字符串</returns>
        public static string GetHexHashFromBytes(byte[] b)
        {
            return md4.GetHexHashFromBytes(b);
        }

        /// <summary>
        /// Returns a byte hash from the input byte<br></br>
        /// 从输入字节返回字节哈希值
        /// </summary>
        /// <param name = "b">byte to hash<br></br>字节到散列</param>
        /// <returns>binary hash of the input byte<br></br>输入字节的二进制哈希值</returns>
        public static byte[] GetByteHashFromByte(byte b)
        {
            return md4.GetByteHashFromByte(b);
        }
    }
}

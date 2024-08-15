using MD2T;

// 示例输入数据
byte[] inputData = System.Text.Encoding.UTF8.GetBytes("Hello, world!");

// 输出缓冲区，长度为 MD2 哈希的字节长度
byte[] hashOutput = new byte[16];  // MD2 哈希的长度为 16 字节

// 计算 MD2 哈希
int result = MD2.ComputeMD2Hash(hashOutput, inputData, inputData.Length);

// 检查计算是否成功
if (result == 0)
{
    // 输出哈希值为十六进制格式
    Console.WriteLine("MD2 Hash (Hex): " + BitConverter.ToString(hashOutput).Replace("-", "").ToLower());
}
else
{
    Console.WriteLine("MD2 Hash computation failed.");
}

string filePath = "test.txt";

try
{
    // 读取文件内容
    byte[] fileData = File.ReadAllBytes(filePath);

    // 输出缓冲区，长度为 MD2 哈希的字节长度
    byte[] fileHashOutput = new byte[16];  // MD2 哈希的长度为 16 字节

    // 计算 MD2 哈希
    int fileResult = MD2.ComputeMD2Hash(fileHashOutput, fileData, fileData.Length);

    // 检查计算是否成功
    if (fileResult == 0)
    {
        // 输出哈希值为十六进制格式
        Console.WriteLine("MD2 Hash (Hex): " + BitConverter.ToString(fileHashOutput).Replace("-", "").ToLower());
    }
    else
    {
        Console.WriteLine("MD2 Hash computation failed.");
    }
}
catch (Exception ex)
{
    Console.WriteLine("An error occurred: " + ex.Message);
}

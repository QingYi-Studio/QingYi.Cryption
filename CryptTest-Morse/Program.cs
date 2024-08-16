using Morse;

var morseCryption = new MorseTextCryption(); // 使用默认字典
string text = "Hello";
string base16 = morseCryption.TextToBase16(text);
string morseCode = morseCryption.Base16ToMorse(base16);

Console.WriteLine($"Text: {text}");
Console.WriteLine($"Base16: {base16}");
Console.WriteLine($"Morse Code: {morseCode}");

string decodedBase16 = morseCryption.MorseToBase16(morseCode);
string decodedText = morseCryption.Base16ToText(decodedBase16);

Console.WriteLine($"Decoded Base16: {decodedBase16}");
Console.WriteLine($"Decoded Text: {decodedText}");

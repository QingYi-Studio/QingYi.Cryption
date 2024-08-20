# Example

```
using System;
using System.Collections.Generic;

class Program
{
    static void Main()
    {
        // Create a custom Morse code dictionary
        var customMorseCodeMap = new Dictionary<char, string>
        {
            {'A', ".-"}, {'B', "-..."}, {'C', "-.-."}, {'D', "-.."}, {'E', "."}, {'F', "..-."},
            {'G', "--."}, {'H', "...."}, {'I', ".."}, {'J', ".---"}, {'K', "-.-"}, {'L', ".-.."},
            {'M', "--"}, {'N', "-."}, {'O', "---"}, {'P', ".--."}, {'Q', "--.-"}, {'R', ".-."},
            {'S', "..."}, {'T', "-"}, {'U', "..-"}, {'V', "...-"}, {'W', ".--"}, {'X', "-..-"},
            {'Y', "-.--"}, {'Z', "--.."}, {' ', "/"}
        };

        // Create an instance of MorseTextCryption and pass in the custom dictionary
        var morseCryption = new MorseTextCryption(customMorseCodeMap);

        // Sample text
        string text = "HELLO";

        // The text goes to Base16
        string base16 = morseCryption.TextToBase16(text);

        // Base16 turns Morse code
        string morseCode = morseCryption.Base16ToMorse(base16);

        // Output result
        Console.WriteLine($"Text: {text}");
        Console.WriteLine($"Base16: {base16}");
        Console.WriteLine($"Morse Code: {morseCode}");

        // Morse code to Base16
        string decodedBase16 = morseCryption.MorseToBase16(morseCode);

        // Base16 to text
        string decodedText = morseCryption.Base16ToText(decodedBase16);

        // Output decoding result
        Console.WriteLine($"Decoded Base16: {decodedBase16}");
        Console.WriteLine($"Decoded Text: {decodedText}");
    }
}

```
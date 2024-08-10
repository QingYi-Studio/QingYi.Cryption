$Script:key = "3567d8cndkei%*x9(-32[]KDF(32222"
 
function Decode($cyphertext) {
    $keyArray =[System.Text.Encoding]::ASCII.GetBytes($key)
    $encodedArray= [System.Text.Encoding]::ASCII.GetBytes([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($cyphertext)))
    $plainText = ""
    $keyposition = 0
    $encodedArray | foreach-object -process {
        $plainText += [char]($_ -bxor $KeyArray[$keyposition % $KeyArray.Length])
        $keyposition += 1
    }
 
    return $plainText
}
 
function Encode($plainText)
{
    $KeyArray= [System.Text.Encoding]::ASCII.GetBytes($key)
    $cyphertext = [System.Byte[]]::new($plainText.Length);
    $keyposition = 0
    $plainText.ToCharArray() | foreach-object -process {
        $cyphertext[$keyposition] = $_ -bxor $KeyArray[$keyposition % $KeyArray.Length]
        $keyposition += 1
    }
 
    return [Convert]::ToBase64String($cyphertext)
}
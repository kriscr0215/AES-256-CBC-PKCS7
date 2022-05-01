using System.Security.Cryptography;
using System.Text;
static string Encrypt(string plaintext, string password, string IV)
{
    byte[] pwd = ASCIIEncoding.UTF8.GetBytes(password);
    byte[] iv = ASCIIEncoding.UTF8.GetBytes(IV);
    string encrypted = "";
    RijndaelManaged rm = new RijndaelManaged();
    rm.Key = pwd;
    rm.IV = iv;
    rm.Mode = CipherMode.CBC;
    rm.Padding = PaddingMode.PKCS7;
    MemoryStream ms = new MemoryStream();
    using (CryptoStream cs = new CryptoStream(ms, rm.CreateEncryptor(pwd, iv), CryptoStreamMode.Write))
    {
        using (StreamWriter sw = new StreamWriter(cs))
        {
            sw.Write(plaintext);
            sw.Close();
        }
        cs.Close();
    }
    byte[] encoded = ms.ToArray();
    encrypted = Convert.ToBase64String(encoded);

    ms.Close();
    return encrypted;
}

static string Decrypt(string ciphertext, string password, string IV)
{
    byte[] key = Encoding.UTF8.GetBytes(password);
    byte[] iv = Encoding.UTF8.GetBytes(IV);
    using (var rijndaelManaged = new RijndaelManaged { Key = key, IV = iv, Mode = CipherMode.CBC })
    using (var memoryStream = new MemoryStream(Convert.FromBase64String(ciphertext)))
    using (var cryptoStream = new CryptoStream(memoryStream, rijndaelManaged.CreateDecryptor(key, iv), CryptoStreamMode.Read))
    {
        return new StreamReader(cryptoStream).ReadToEnd();
    }
}

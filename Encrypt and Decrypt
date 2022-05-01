using System.Security.Cryptography;
using System.Text;
static string Encrypt(string message, string password, string IVString)
{
    byte[] pwd = ASCIIEncoding.UTF8.GetBytes(password);
    byte[] IV = ASCIIEncoding.UTF8.GetBytes(IVString);
    string encrypted = "";
    RijndaelManaged rm = new RijndaelManaged();
    rm.Key = pwd;
    rm.IV = IV;
    rm.Mode = CipherMode.CBC;
    rm.Padding = PaddingMode.PKCS7;
    MemoryStream ms = new MemoryStream();
    using (CryptoStream cs = new CryptoStream(ms, rm.CreateEncryptor(pwd, IV), CryptoStreamMode.Write))
    {
        using (StreamWriter sw = new StreamWriter(cs))
        {
            sw.Write(message);
            sw.Close();
        }
        cs.Close();
    }
    byte[] encoded = ms.ToArray();
    encrypted = Convert.ToBase64String(encoded);

    ms.Close();
    return encrypted;
}

static string Decrypt(string cipherData, string password, string ivString)
{
    byte[] key = Encoding.UTF8.GetBytes(password);
    byte[] iv = Encoding.UTF8.GetBytes(ivString);
    using (var rijndaelManaged = new RijndaelManaged { Key = key, IV = iv, Mode = CipherMode.CBC })
    using (var memoryStream = new MemoryStream(Convert.FromBase64String(cipherData)))
    using (var cryptoStream = new CryptoStream(memoryStream, rijndaelManaged.CreateDecryptor(key, iv), CryptoStreamMode.Read))
    {
        return new StreamReader(cryptoStream).ReadToEnd();
    }
}

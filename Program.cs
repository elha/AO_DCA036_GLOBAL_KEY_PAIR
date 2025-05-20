using System.Text;
using System.Security.Cryptography;

/// <summary>
/// decode passphrase for the PGP PrivateKey für a popular
/// confluence module, just in case you would like to switch *g*
/// Security and Encryption for Conf.
/// 
/// info:
/// all PGP Blocks contained within content can be decoded with
/// the PGP "PRIVATE_KEY" stored in Table "AO_DCA036_GLOBAL_KEY_PAIR"
/// using the decoded passphrase
/// </summary>
public class Program
{
	// Offsets in the composite string:
	private const int PassphraseLength = 8;
	private const int SaltHexLength = 16; // yields 8 bytes
	private const int IvHexLength = 32; // yields 16 bytes

	public static void Main()
	{
		const string passPhrase = /* VALUE FROM "SELECT PASS_PHRASE FROM AO_DCA036_GLOBAL_KEY_PAIR;" */;

		string pgpPass = DecryptPgPPassphrase(passPhrase);
		Console.WriteLine("Recovered PGP Passphrase: " + pgpPass);
	}

	private static string DecryptPgPPassphrase(string composite)
	{
		// split into the four parts
		string pass = composite.Substring(0, PassphraseLength);
		string saltHex = composite.Substring(PassphraseLength, SaltHexLength);
		string ivHex = composite.Substring(PassphraseLength + SaltHexLength, IvHexLength);
		string cipherB64 = composite.Substring(PassphraseLength + SaltHexLength + IvHexLength);

		// derive key
		using var derivation = new Rfc2898DeriveBytes(
			pass,
			Convert.FromHexString(saltHex),
			iterations: 1000,
			HashAlgorithmName.SHA1
		);

		// decrypt
		using var aes = Aes.Create();
		aes.KeySize = 128;
		aes.Mode = CipherMode.CBC;
		aes.Padding = PaddingMode.PKCS7;
		aes.Key = derivation.GetBytes(128 / 8);
		aes.IV = Convert.FromHexString(ivHex);

		using var decryptor = aes.CreateDecryptor();
		byte[] cipher = Convert.FromBase64String(cipherB64);
		byte[] plain = decryptor.TransformFinalBlock(cipher, 0, cipher.Length);

		return Encoding.UTF8.GetString(plain);
	}
}

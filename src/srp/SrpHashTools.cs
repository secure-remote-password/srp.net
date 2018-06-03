using System.Security.Cryptography;

namespace SecureRemotePassword
{
	/// <summary>
	/// Hashing tools.
	/// </summary>
	public class SrpHashTools
	{
		/// <summary>
		/// Creates the hasher for the given hashing algorithm.
		/// </summary>
		/// <param name="algorithm">The name of the hashing algorithm.</param>
		public static HashAlgorithm CreateHasher(string algorithm)
		{
			var result = default(HashAlgorithm);

			// CryptoConfig is not available on .NET Standard 1.6
			#if USE_CRYPTO_CONFIG
			result = (HashAlgorithm)CryptoConfig.CreateFromName(algorithm);
			#endif

			if (result == null)
			{
				switch (algorithm.ToLowerInvariant())
				{
					case "sha1":
						return SHA1.Create();

					case "sha256":
						return SHA256.Create();

					case "sha384":
						return SHA256.Create();

					case "sha512":
						return SHA256.Create();
				}
			}

			return result;
		}
	}
}

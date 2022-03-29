using System.Collections.Generic;
using System.Security.Cryptography;
using NUnit.Framework;
using StringPair = System.Collections.Generic.KeyValuePair<string, string>;

namespace SecureRemotePassword.Tests
{
	/// <summary>
	/// <see cref="SrpServer"/> tests.
	///</summary>
	[TestFixture]
	public class SrpUtilityTests
	{
		private static Dictionary<int, StringPair> Primes { get; } = new Dictionary<int, StringPair>
		{
			[1024] = new StringPair(SrpConstants.SafePrime1024, SrpConstants.Generator1024),
			[1536] = new StringPair(SrpConstants.SafePrime1536, SrpConstants.Generator1536),
			[2048] = new StringPair(SrpConstants.SafePrime2048, SrpConstants.Generator2048),
			[3072] = new StringPair(SrpConstants.SafePrime3072, SrpConstants.Generator3072),
			[4096] = new StringPair(SrpConstants.SafePrime4096, SrpConstants.Generator4096),
			[6144] = new StringPair(SrpConstants.SafePrime6144, SrpConstants.Generator6144),
			[8192] = new StringPair(SrpConstants.SafePrime8192, SrpConstants.Generator8192),
		};

		[TestCase(1024)]
		[TestCase(1536)]
		[TestCase(2048)]
		[TestCase(3072)]
		[TestCase(4096)]
		[TestCase(6144)]
		[TestCase(8192)]
		public void SrpImplementationGeneratesValidSaltAndVerifier(int bits)
		{
			var primes = Primes[bits];
			var prime = primes.Key;
			var generator = primes.Value;

			SrpImplementationGeneratesValidSaltAndVerifier<MD5>(prime, generator);
			SrpImplementationGeneratesValidSaltAndVerifier<SHA1>(prime, generator);
			SrpImplementationGeneratesValidSaltAndVerifier<SHA256>(prime, generator);
			SrpImplementationGeneratesValidSaltAndVerifier<SHA384>(prime, generator);
			SrpImplementationGeneratesValidSaltAndVerifier<SHA512>(prime, generator);
		}

		private void SrpImplementationGeneratesValidSaltAndVerifier<T>(string prime, string generator)
			where T : HashAlgorithm
		{
			// generate values
			var parameters = SrpParameters.Create<T>(prime, generator);
			var client = new SrpClient(parameters);
			var salt = client.GenerateSalt();
			var privateKey = client.DerivePrivateKey(salt, "root", "123");
			var verifier = client.DeriveVerifier(privateKey);

			// verify generated values
			Assert.IsTrue(parameters.IsValidSalt(salt));
			Assert.IsTrue(parameters.IsValidVerifier(verifier));
		}

		[Test]
		public void InvalidSaltAndVerifierAreReported()
		{
			var client = new SrpClient();
			var server = new SrpServer();
			var parameters = server.Parameters;
			var salt = client.GenerateSalt();
			var privateKey = client.DerivePrivateKey(salt, "root", "123");
			var verifier = client.DeriveVerifier(privateKey);

			// valid examples
			Assert.IsTrue(parameters.IsValidSalt(salt));
			Assert.IsTrue(parameters.IsValidVerifier(verifier));

			// invalid examples
			Assert.IsFalse(parameters.IsValidSalt(null));
			Assert.IsFalse(parameters.IsValidVerifier(null));
			Assert.IsFalse(parameters.IsValidSalt("123"));
			Assert.IsFalse(parameters.IsValidVerifier("123"));
			Assert.IsFalse(parameters.IsValidSalt(salt + "01"));
			Assert.IsFalse(parameters.IsValidVerifier(verifier + "01"));
			Assert.IsFalse(parameters.IsValidSalt(salt.Substring(2)));
			Assert.IsFalse(parameters.IsValidVerifier(verifier.Substring(2)));
			Assert.IsFalse(parameters.IsValidSalt(salt.Replace(salt[0], 'g')));
			Assert.IsFalse(parameters.IsValidVerifier(verifier.Replace(salt[0], 'h')));
			Assert.IsFalse(parameters.IsValidSalt(verifier));
			Assert.IsFalse(parameters.IsValidVerifier(salt));
		}
	}
}

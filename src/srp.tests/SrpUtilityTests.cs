using System.Security.Cryptography;
using NUnit.Framework;

namespace SecureRemotePassword.Tests
{
	/// <summary>
	/// <see cref="SrpServer"/> tests.
	///</summary>
	[TestFixture]
	public class SrpUtilityTests
	{
		[TestCase(SrpConstants.SafePrime1024, SrpConstants.Generator1024)]
		[TestCase(SrpConstants.SafePrime1536, SrpConstants.Generator1536)]
		[TestCase(SrpConstants.SafePrime2048, SrpConstants.Generator2048)]
		[TestCase(SrpConstants.SafePrime3072, SrpConstants.Generator3072)]
		[TestCase(SrpConstants.SafePrime4096, SrpConstants.Generator4096)]
		[TestCase(SrpConstants.SafePrime6144, SrpConstants.Generator6144)]
		[TestCase(SrpConstants.SafePrime8192, SrpConstants.Generator8192)]
		public void SrpImplementationGeneratesValidSaltAndVerifier(string prime, string generator)
		{
			SrpImplementationGeneratesValidSaltAndVerifier<MD5>(prime, generator);
			SrpImplementationGeneratesValidSaltAndVerifier<SHA1>(prime, generator);
			SrpImplementationGeneratesValidSaltAndVerifier<SHA256>(prime, generator);
			SrpImplementationGeneratesValidSaltAndVerifier<SHA384>(prime, generator);
			SrpImplementationGeneratesValidSaltAndVerifier<SHA512>(prime, generator);
		}

		private void SrpImplementationGeneratesValidSaltAndVerifier<T>(string prime, string generator)
			where T : HashAlgorithm
		{
			// set up parameters
			var parameters = SrpParameters.Create<T>(prime, generator);
			var client = new SrpClient(parameters);
			var server = new SrpServer(parameters);

			// sign up
			var salt = client.GenerateSalt();
			var privateKey = client.DerivePrivateKey(salt, "root", "123");
			var verifier = client.DeriveVerifier(privateKey);

			// verify generated values
			Assert.IsTrue(parameters.IsValidSalt(salt));
			Assert.IsTrue(parameters.IsValidVerifier(verifier));
		}
	}
}

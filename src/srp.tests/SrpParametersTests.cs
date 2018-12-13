using System.Security.Cryptography;
using NUnit.Framework;

namespace SecureRemotePassword.Tests
{
	[TestFixture]
	public class SrpParametersTests
	{
		[Test]
		public void SrpParameterDefaultsAreReasonable()
		{
			var parameters = new SrpParameters();
			Assert.NotNull(parameters.Prime);
			Assert.NotNull(parameters.Generator);
			Assert.AreEqual(32, parameters.HashSizeBytes);
			Assert.AreEqual(512, parameters.PaddedLength);
		}

		[Test]
		public void SrpParametersCanUseCustomHashAlgorithm()
		{
			var parameters = new SrpParameters(MD5.Create);
			Assert.NotNull(parameters.Prime);
			Assert.NotNull(parameters.Generator);
			Assert.AreEqual(16, parameters.HashSizeBytes);
			Assert.AreEqual(512, parameters.PaddedLength);
		}

		[Test]
		public void SrpParametersUsePadding()
		{
			var value = SrpInteger.FromHex("1234");
			var parameters = new SrpParameters(paddedLength: 10);
			Assert.AreEqual("0000001234", parameters.Pad(value).ToHex());
		}
	}
}

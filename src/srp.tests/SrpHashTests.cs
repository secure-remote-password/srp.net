using System.Security.Cryptography;
using NUnit.Framework;

namespace SecureRemotePassword.Tests
{
	using H = SrpParameters.SrpHashFunction;

	/// <summary>
	/// <see cref="SrpHash"/> tests.
	/// </summary>
	[TestFixture]
	public class SrpHashTests
	{
		[Test]
		public void CreateHasherTests()
		{
			var sha1 = SrpHash<SHA1>.CreateHasher();
			Assert.NotNull(sha1);

			var sha256 = SrpHash<SHA256>.CreateHasher();
			Assert.NotNull(sha256);

			var sha384 = SrpHash<SHA384>.CreateHasher();
			Assert.NotNull(sha384);

			var sha512 = SrpHash<SHA512>.CreateHasher();
			Assert.NotNull(sha512);
		}

		[Test]
		public void CreateHasherByNameTests()
		{
			var sha1 = SrpHash.CreateHasher("sha1");
			Assert.NotNull(sha1);

			var sha256 = SrpHash.CreateHasher("sha256");
			Assert.NotNull(sha256);

			var sha384 = SrpHash.CreateHasher("sha384");
			Assert.NotNull(sha384);

			var sha512 = SrpHash.CreateHasher("sha512");
			Assert.NotNull(sha512);
		}
		
		#if NETCOREAPP2_0_OR_GREATER
		[Test]
		public void CreateHasherByRegisteredNameTests()
		{
			const string hashName = "MyHasher";
			var custom = SrpHash.CreateHasher(hashName);
			Assert.Null(custom);

			CryptoConfig.AddAlgorithm(typeof(SHA256Managed), hashName);

			custom = SrpHash.CreateHasher(hashName);
			Assert.NotNull(custom);
		}
		#endif
		
		[Test]
		public void SrpHashComputesValidStringHashes()
		{
			var parts = new[] { "D4C7F8A2B32", "C11B8FBA9581EC4BA4F1B0421", string.Empty, "5642EF7355E37C0FC0443EF7", "56EA2C6B8EEB755A1C72302", "7663CAA265EF785B8FF6A9B35227A52D86633DBDFCA43" };
			var sample = string.Concat(parts);
			var srpint = SrpInteger.FromHex(sample);

			H md5 = new SrpHash<MD5>().ComputeHash;
			var hashmd5 = SrpInteger.FromHex("34ada39bbabfa6e663f1aad3d7814121");
			Assert.AreEqual(hashmd5, md5(srpint.ToHex().ToUpper()));
			Assert.AreEqual(hashmd5, md5(sample));
			Assert.AreEqual(hashmd5, md5(parts));
			Assert.AreEqual(16, new SrpHash<MD5>().HashSizeBytes);

			H sha256 = new SrpHash<SHA256>().ComputeHash;
			var hash256 = SrpInteger.FromHex("1767fe8c94508ad3514b8332493fab5396757fe347023fc9d1fef6d26c3a70d3");
			Assert.AreEqual(hash256, sha256(srpint.ToHex().ToUpper()));
			Assert.AreEqual(hash256, sha256(sample));
			Assert.AreEqual(hash256, sha256(parts));
			Assert.AreEqual(256 / 8, new SrpHash<SHA256>().HashSizeBytes);

			H sha512 = new SrpHash<SHA512>().ComputeHash;
			var hash512 = SrpInteger.FromHex("f2406fd4b33b15a6b47ff78ccac7cd80eec7944092425b640d740e7dc695fdd42f583a9b4a4b98ffa5409680181999bfe319f2a3b50ddb111e8405019a8c552a");
			Assert.AreEqual(hash512, sha512(srpint.ToHex().ToUpper()));
			Assert.AreEqual(hash512, sha512(sample));
			Assert.AreEqual(hash512, sha512(parts));
			Assert.AreEqual(512 / 8, new SrpHash<SHA512>().HashSizeBytes);
		}

		[Test]
		public void SrpHashComputesValidSrpIntegerHashes()
		{
			var parts = new[] { "Hello", " ", "world!" };
			var sample = string.Concat(parts);
			var srpint = SrpInteger.FromHex("48 65 6C 6C 6F 20 77 6F 72 6c 64 21");

			H md5 = new SrpHash<MD5>().ComputeHash;
			var hashmd5 = SrpInteger.FromHex("86FB269D190D2C85F6E0468CECA42A20");
			Assert.AreEqual(hashmd5, md5(srpint));
			Assert.AreEqual(hashmd5, md5(sample));
			Assert.AreEqual(hashmd5, md5(parts));
			Assert.AreEqual(16, new SrpHash<MD5>().HashSizeBytes);

			H sha256 = new SrpHash<SHA256>().ComputeHash;
			var hash256 = SrpInteger.FromHex("C0535E4BE2B79FFD93291305436BF889314E4A3FAEC05ECFFCBB7DF31AD9E51A");
			Assert.AreEqual(hash256, sha256(srpint));
			Assert.AreEqual(hash256, sha256(sample));
			Assert.AreEqual(hash256, sha256(parts));
			Assert.AreEqual(256 / 8, new SrpHash<SHA256>().HashSizeBytes);

			H sha512 = new SrpHash<SHA512>().ComputeHash;
			var hash512 = SrpInteger.FromHex("F6CDE2A0F819314CDDE55FC227D8D7DAE3D28CC556222A0A8AD66D91CCAD4AAD6094F517A2182360C9AACF6A3DC323162CB6FD8CDFFEDB0FE038F55E85FFB5B6");
			Assert.AreEqual(hash512, sha512(srpint));
			Assert.AreEqual(hash512, sha512(sample));
			Assert.AreEqual(hash512, sha512(parts));
			Assert.AreEqual(512 / 8, new SrpHash<SHA512>().HashSizeBytes);
		}

		[Test]
		public void SrpHashMiscTests()
		{
			var hash = new SrpHash(() => MD5.Create());
			Assert.IsNotEmpty(hash.AlgorithmName);

			var tmp = hash.ComputeHash(null, null, null);
		}
	}
}

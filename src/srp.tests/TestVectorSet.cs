using System.Security.Cryptography;
using Blake2Sharp;

namespace SecureRemotePassword.Tests
{
	/// <summary>
	/// Describes the set of test vectors for the Srp validation.
	/// </summary>
	public class TestVectorSet
	{
		public string Comments { get; set; }
		public string Url { get; set; }
		public TestVector[] TestVectors { get; set; }

		public class TestVector
		{
			public string H { get; set; }
			public int Size { get; set; }
			public string N { get; set; }
			public string g { get; set; }
			public string I { get; set; }
			public string P { get; set; }
			public string s { get; set; }
			public string k { get; set; }
			public string x { get; set; }
			public string v { get; set; }
			public string a { get; set; }
			public string b { get; set; }
			public string A { get; set; }
			public string B { get; set; }
			public string u { get; set; }
			public string S { get; set; }

			// optional parameters, missing in RFC5054 test vector
			public string K { get; set; }
			public string M1 { get; set; }
			public string M2 { get; set; }

			/// <summary>
			/// Creates the hasher.
			/// </summary>
			private HashAlgorithm CreateHasher()
			{
				var hasher = SrpHash.CreateHasher(H);
				if (hasher == null)
				{
					HashAlgorithm blake2b(int bits) =>
						new Blake2BHasher(new Blake2BConfig { OutputSizeInBits = bits })
							.AsHashAlgorithm();

					switch (H.ToLowerInvariant())
					{
						case "blake2s":
							return null;

						case "blake2b-224":
							return blake2b(224);

						case "blake2b-256":
							return blake2b(256);

						case "blake2b-384":
							return blake2b(384);

						case "blake2b-512":
							return blake2b(512);
					}
				}

				return hasher;
			}

			/// <summary>
			/// Creates the <see cref="SrpParameters"/> for the current test vector.
			/// </summary>
			public SrpParameters CreateParameters()
			{
				// skip test vectors with the unsupported hash format
				var hasher = CreateHasher();
				if (hasher == null)
				{
					return null;
				}

				// convert size in bits to padded length in chars
				var paddedLength = Size / 4;
				return new SrpParameters(hasher, N, g, paddedLength);
			}
		}
	}
}

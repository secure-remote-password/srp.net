using System;
using System.Security.Cryptography;

namespace Zyan.SecureRemotePassword.Tests
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

			private SrpParameters CreateParameters<T>() where T : HashAlgorithm
			{
				// convert size in bits to chars
				var paddedLengthInChars = Size / 4;

				return SrpParameters.Create<T>(N, g, paddedLengthInChars);
			}

			/// <summary>
			/// Creates the <see cref="SrpParameters"/> for the current test vector.
			/// </summary>
			public SrpParameters CreateParameters()
			{
				switch (H.ToLowerInvariant())
				{
					case "sha1":
						return CreateParameters<SHA1>();

					case "sha256":
						return CreateParameters<SHA256>();

					case "sha384":
						return CreateParameters<SHA384>();

					case "sha512":
						return CreateParameters<SHA512>();

					default:
						throw new InvalidOperationException($"Unknown hash format: {H}");
				}
			}
		}
	}
}

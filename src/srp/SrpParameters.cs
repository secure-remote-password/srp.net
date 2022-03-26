using System;
using System.Security.Cryptography;

namespace SecureRemotePassword
{
	/// <summary>
	/// SRP-6a protocol parameters.
	/// </summary>
	public class SrpParameters
	{
		/// <summary>
		/// Hash function signature.
		/// Computes the hash of the specified <see cref="string"/> or <see cref="SrpInteger"/> values.
		/// </summary>
		/// <param name="values">The values.</param>
		public delegate SrpInteger SrpHashFunction(params object[] values);

		/// <summary>
		/// Initializes a new instance of the <see cref="SrpParameters"/> class.
		/// </summary>
		/// <param name="hashAlgorithmFactory">The hashing algorithm factory.</param>
		/// <param name="largeSafePrime">Large safe prime number N (hexadecimal).</param>
		/// <param name="generator">The generator value modulo N (hexadecimal).</param>
		/// <param name="paddedLength">The hexadecimal length of N and g.</param>
		/// <param name="revision">Revision of SRP protocol, defaults to 6a if not provided.</param>
		public SrpParameters(Func<HashAlgorithm> hashAlgorithmFactory = null, string largeSafePrime = null, string generator = null, int? paddedLength = null, SrpRevision? revision = null)
		{
			Prime = SrpInteger.FromHex(largeSafePrime ?? SrpConstants.SafePrime2048);
			Generator = SrpInteger.FromHex(generator ?? SrpConstants.Generator2048);
			PaddedLength = paddedLength ?? Prime.HexLength.Value;
			Hasher = hashAlgorithmFactory != null ? new SrpHash(hashAlgorithmFactory) : new SrpHash<SHA256>();
			Pad = i => i.Pad(PaddedLength);
			Revision = revision ?? SrpRevision.SixA;
		}

		/// <summary>
		/// Creates the SRP-6a parameters using the specified hash function.
		/// </summary>
		/// <typeparam name="T"><see cref="HashAlgorithm"/> implementation.</typeparam>
		/// <param name="largeSafePrime">Large safe prime number N (hexadecimal).</param>
		/// <param name="generator">The generator value modulo N (hexadecimal).</param>
		/// <param name="paddedLength">The hexadecimal length of N and g.</param>
		/// <param name="revision">Revision of SRP protocol, defaults to 6a if not provided.</param>
		public static SrpParameters Create<T>(string largeSafePrime = null, string generator = null, int? paddedLength = null, SrpRevision? revision = null)
			where T : HashAlgorithm
		{
			var result = new SrpParameters
			{
				Hasher = new SrpHash<T>(),
			};

			if (largeSafePrime != null)
			{
				result.Prime = SrpInteger.FromHex(largeSafePrime);
				result.PaddedLength = result.Prime.HexLength.Value;
			}

			if (generator != null)
			{
				result.Generator = SrpInteger.FromHex(generator);
			}

			if (paddedLength.HasValue)
			{
				result.PaddedLength = paddedLength.Value;
			}

			if (revision.HasValue)
			{
				result.Revision = revision.Value;
			}

			return result;
		}

		/// <summary>
		/// Creates the SRP-6a parameters using the specified hash function and 1024-bit group.
		/// </summary>
		/// <typeparam name="T"><see cref="HashAlgorithm"/> implementation.</typeparam>
		public static SrpParameters Create1024<T>()
			where T : HashAlgorithm => Create<T>(SrpConstants.SafePrime1024, SrpConstants.Generator1024);

		/// <summary>
		/// Creates the SRP-6a parameters using the specified hash function and 1536-bit group.
		/// </summary>
		/// <typeparam name="T"><see cref="HashAlgorithm"/> implementation.</typeparam>
		public static SrpParameters Create1536<T>()
			where T : HashAlgorithm => Create<T>(SrpConstants.SafePrime1536, SrpConstants.Generator1536);

		/// <summary>
		/// Creates the SRP-6a parameters using the specified hash function and 2048-bit group.
		/// </summary>
		/// <typeparam name="T"><see cref="HashAlgorithm"/> implementation.</typeparam>
		public static SrpParameters Create2048<T>()
			where T : HashAlgorithm => Create<T>(SrpConstants.SafePrime2048, SrpConstants.Generator2048);

		/// <summary>
		/// Creates the SRP-6a parameters using the specified hash function and 3072-bit group.
		/// </summary>
		/// <typeparam name="T"><see cref="HashAlgorithm"/> implementation.</typeparam>
		public static SrpParameters Create3072<T>()
			where T : HashAlgorithm => Create<T>(SrpConstants.SafePrime3072, SrpConstants.Generator3072);

		/// <summary>
		/// Creates the SRP-6a parameters using the specified hash function and 4096-bit group.
		/// </summary>
		/// <typeparam name="T"><see cref="HashAlgorithm"/> implementation.</typeparam>
		public static SrpParameters Create4096<T>()
			where T : HashAlgorithm => Create<T>(SrpConstants.SafePrime4096, SrpConstants.Generator4096);

		/// <summary>
		/// Creates the SRP-6a parameters using the specified hash function and 6144-bit group.
		/// </summary>
		/// <typeparam name="T"><see cref="HashAlgorithm"/> implementation.</typeparam>
		public static SrpParameters Create6144<T>()
			where T : HashAlgorithm => Create<T>(SrpConstants.SafePrime6144, SrpConstants.Generator6144);

		/// <summary>
		/// Creates the SRP-6a parameters using the specified hash function and 8192-bit group.
		/// </summary>
		/// <typeparam name="T"><see cref="HashAlgorithm"/> implementation.</typeparam>
		public static SrpParameters Create8192<T>()
			where T : HashAlgorithm => Create<T>(SrpConstants.SafePrime8192, SrpConstants.Generator8192);

		/// <summary>
		/// Gets or sets the length of the padded N and g values.
		/// </summary>
		public int PaddedLength { get; set; }

		/// <summary>
		/// Gets or sets the length of the padded N and g values.
		/// </summary>
		public SrpRevision Revision { get; set; }

		/// <summary>
		/// Gets or sets the large safe prime number (N = 2q+1, where q is prime).
		/// </summary>
		public SrpInteger Prime { get; set; }

		/// <summary>
		/// Gets or sets the generator modulo N.
		/// </summary>
		public SrpInteger Generator { get; set; }

		/// <summary>
		/// Gets or sets the SRP hasher.
		/// </summary>
		public ISrpHash Hasher { get; set; }

		/// <summary>
		/// Gets the hashing function.
		/// </summary>
		public SrpHashFunction Hash => Hasher.ComputeHash;

		/// <summary>
		/// Gets the function to pad the specified integer value.
		/// </summary>
		public Func<SrpInteger, SrpInteger> Pad { get; }

		/// <summary>
		/// Gets the hash size in bytes.
		/// </summary>
		public int HashSizeBytes => Hasher.HashSizeBytes;

		/// <summary>
		/// Gets the multiplier parameter: k = H(N, g) in SRP-6a (k = 3 for legacy SRP-6).
		/// </summary>
		public SrpInteger Multiplier
		{
			get
			{
				switch (Revision)
				{
					case SrpRevision.Three:
						return new SrpInteger("01");
					case SrpRevision.Six:
						return new SrpInteger("03");
					default:
						return Hash(Prime, Pad(Generator));
				}
			}
		}

		/// <inheritdoc/>
		public override string ToString() => $"SrpParameters.Create<{Hasher.AlgorithmName}>(\"{Prime.ToHex()}\", \"{Generator.ToHex()}\")";
	}
}

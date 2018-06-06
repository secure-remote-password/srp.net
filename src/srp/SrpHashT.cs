using System.Security.Cryptography;

namespace SecureRemotePassword
{
	/// <summary>
	/// Hashing algorithms for the SRP-6a protocol.
	/// </summary>
	/// <typeparam name="T">Hash algorithm type.</typeparam>
	public class SrpHash<T> : SrpHash
		where T : HashAlgorithm
	{
		/// <summary>
		/// Initializes a new instance of the <see cref="SrpHash{T}"/> class.
		/// </summary>
		public SrpHash()
			: base(CreateHasher())
		{
		}

		/// <summary>
		/// Creates the hasher of the given type <typeparamref name="T"/>.
		/// </summary>
		public static T CreateHasher() => (T)CreateHasher(typeof(T).Name);
	}
}

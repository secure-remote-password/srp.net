namespace SecureRemotePassword
{
	/// <summary>
	/// Interface for the hash functions used by SRP-6a protocol.
	/// </summary>
	public interface ISrpHash
	{
		/// <summary>
		/// Computes the hash of the specified <see cref="string"/> or <see cref="SrpInteger"/> values.
		/// </summary>
		/// <param name="values">The values.</param>
		SrpInteger ComputeHash(params object[] values);

		/// <summary>
		/// Gets the hash size in bytes.
		/// </summary>
		int HashSizeBytes { get; }

		/// <summary>
		/// Gets the name of the algorithm.
		/// </summary>
		string AlgorithmName { get; }
	}
}

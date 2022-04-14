namespace SecureRemotePassword
{
	/// <summary>
	/// Client-side code of the SRP-6a protocol.
	/// </summary>
	public interface ISrpClient
	{
		/// <summary>
		/// Generates the random salt of the same size as a used hash.
		/// </summary>
    /// <param name="saltLength">
		/// An optional, custom salt length specifying the number of bytes. If it is unset,
		/// the `HashSizeBytes` of the hash function from the `Parameters` will be used.
		//// </param>
		string GenerateSalt(int? saltLength = null);

		/// <summary>
		/// Derives the private key from the given salt, user name and password.
		/// </summary>
		/// <param name="salt">The salt.</param>
		/// <param name="userName">The name of the user.</param>
		/// <param name="password">The password.</param>
		string DerivePrivateKey(string salt, string userName, string password);

		/// <summary>
		/// Derives the verifier from the private key.
		/// </summary>
		/// <param name="privateKey">The private key.</param>
		string DeriveVerifier(string privateKey);

		/// <summary>
		/// Generates the ephemeral value.
		/// </summary>
		SrpEphemeral GenerateEphemeral();

		/// <summary>
		/// Derives the client session.
		/// </summary>
		/// <param name="clientSecretEphemeral">The client secret ephemeral.</param>
		/// <param name="serverPublicEphemeral">The server public ephemeral.</param>
		/// <param name="salt">The salt.</param>
		/// <param name="username">The username.</param>
		/// <param name="privateKey">The private key.</param>
		/// <returns>Session key and proof.</returns>
		SrpSession DeriveSession(string clientSecretEphemeral, string serverPublicEphemeral, string salt, string username, string privateKey);

		/// <summary>
		/// Verifies the session using the server-provided session proof.
		/// </summary>
		/// <param name="clientPublicEphemeral">The client public ephemeral.</param>
		/// <param name="clientSession">The client session.</param>
		/// <param name="serverSessionProof">The server session proof.</param>
		void VerifySession(string clientPublicEphemeral, SrpSession clientSession, string serverSessionProof);
	}
}
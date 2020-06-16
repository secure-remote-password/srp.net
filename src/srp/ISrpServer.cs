namespace SecureRemotePassword
{
	/// <summary>
	/// Server-side code of the SRP-6a protocol.
	/// </summary>
	public interface ISrpServer
	{
		/// <summary>
		/// Generates the ephemeral value from the given verifier.
		/// </summary>
		/// <param name="verifier">Verifier.</param>
		SrpEphemeral GenerateEphemeral(string verifier);

		/// <summary>
		/// Derives the server session.
		/// </summary>
		/// <param name="serverSecretEphemeral">The server secret ephemeral.</param>
		/// <param name="clientPublicEphemeral">The client public ephemeral.</param>
		/// <param name="salt">The salt.</param>
		/// <param name="username">The username.</param>
		/// <param name="verifier">The verifier.</param>
		/// <param name="clientSessionProof">The client session proof value.</param>
		/// <returns>Session key and proof.</returns>
		SrpSession DeriveSession(string serverSecretEphemeral, string clientPublicEphemeral, string salt, string username, string verifier, string clientSessionProof);
	}
}
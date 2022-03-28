namespace SecureRemotePassword
{
	/// <summary>
	/// SRP protocol revisions.
	/// </summary>
	public enum SrpRevision
	{
		/// <summary>
		/// SRP-3 protocol.
		/// </summary>
		Three = 1,

		/// <summary>
		/// SRP-6 protocol.
		/// </summary>
		Six = 2,

		/// <summary>
		/// SRP-6a protocol, the default.
		/// </summary>
		SixA = 3,
	}
}
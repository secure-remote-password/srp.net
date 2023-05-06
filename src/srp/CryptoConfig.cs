using System;
using System.Collections.Generic;

namespace SecureRemotePassword
{
	/// <summary>
	/// An alternative cryptographic configuration for .netstandard1.6 and browser runtimes.
	/// </summary>
	public static class CryptoConfig
	{
		private static readonly IDictionary<string, Type> CryptoRegistry = new Dictionary<string, Type>();

		/// <summary>
		/// Creates a new instance of the specified cryptographic object.
		/// </summary>
		/// <param name="name">The simple name of the cryptographic object of which to create an instance.</param>
		/// <returns>A new instance of the specified cryptographic object.</returns>
		public static object CreateFromName(string name)
		{
			if (!CryptoRegistry.TryGetValue(name, out Type type))
			{
				return default(System.Security.Cryptography.HashAlgorithm);
			}

			return Activator.CreateInstance(type);
		}

		/// <summary>
		/// Adds a set of names to algorithm mappings to be used for the current application domain.
		/// </summary>
		/// <param name="algorithm">The algorithm to map to.</param>
		/// <param name="names">An array of names to map to the algorithm.</param>
		public static void AddAlgorithm(Type algorithm, params string[] names)
		{
			foreach (string name in names)
			{
				CryptoRegistry[name] = algorithm;
			}
		}
	}
}

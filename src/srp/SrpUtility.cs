using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SecureRemotePassword
{
	/// <summary>
	/// Utility methods, extension methods, etc.
	/// </summary>
	public static class SrpUtility
	{
		/// <summary>
		/// Checks if the given hexadecimal string is a valid padded SRP integer.
		/// </summary>
		/// <param name="hexString">Integer value represented as hexadecimal string.</param>
		/// <param name="requiredLength">Required length of the hexadecimal string.</param>
		/// <returns>True, if the value is valid.</returns>
		public static bool IsValidInteger(string hexString, int requiredLength)
		{
			if (string.IsNullOrEmpty(hexString) || hexString.Length != requiredLength)
			{
				return false;
			}

			try
			{
				var tmp = new SrpInteger(hexString);
				return true;
			}
			catch
			{
				return false;
			}
		}

		/// <summary>
		/// Checks if the given salt value is a valid padded hexadecimal string.
		/// </summary>
		/// <param name="parameters">SRP parameters.</param>
		/// <param name="salt">Hexadecimal salt string.</param>
		/// <returns>True, if the salt value is valid.</returns>
		public static bool IsValidSalt(this SrpParameters parameters, string salt) => IsValidInteger(salt, parameters.HashSizeBytes * 2);

		/// <summary>
		/// Checks if the given verifier value is a valid padded hexadecimal string.
		/// </summary>
		/// <param name="parameters">SRP parameters.</param>
		/// <param name="verifier">Password verifier.</param>
		/// <returns>True, if the verifier value is valid.</returns>
		public static bool IsValidVerifier(this SrpParameters parameters, string verifier) => IsValidInteger(verifier, parameters.PaddedLength);
	}
}

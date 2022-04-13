﻿using System.Security;

namespace SecureRemotePassword
{
	/// <summary>
	/// Server-side code of the SRP-6a protocol.
	/// </summary>
	public class SrpServer : ISrpServer
	{
		/// <summary>
		/// Initializes a new instance of the <see cref="SrpServer"/> class.
		/// </summary>
		/// <param name="parameters">The parameters of the SRP-6a protocol.</param>
		public SrpServer(SrpParameters parameters = null)
		{
			Parameters = parameters ?? new SrpParameters();
		}

		/// <summary>
		/// Gets or sets the protocol parameters.
		/// </summary>
		internal SrpParameters Parameters { get; set; }

		/// <summary>
		/// Generates the ephemeral value from the given verifier.
		/// </summary>
		/// <param name="verifier">Verifier.</param>
		public SrpEphemeral GenerateEphemeral(string verifier)
		{
			// B = kv + g^b (b = random number)
			var b = SrpInteger.RandomInteger(Parameters.HashSizeBytes);
			var B = ComputeB(verifier, b);

			return new SrpEphemeral
			{
				Secret = b.ToHex(),
				Public = B.ToHex(),
			};
		}

		/// <summary>
		/// Generates the public ephemeral value from the given verifier and the secret.
		/// </summary>
		/// <param name="verifier">Verifier.</param>
		/// <param name="b">Secret server ephemeral.</param>
		internal SrpInteger ComputeB(string verifier, SrpInteger b)
		{
			// N — A large safe prime (N = 2q+1, where q is prime)
			// g — A generator modulo N
			// k — Multiplier parameter (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
			var N = Parameters.Prime;
			var g = Parameters.Generator;
			var k = Parameters.Multiplier;

			// v — Password verifier
			var v = SrpInteger.FromHex(verifier);

			// B = kv + g^b (b = random number)
			return ((k * v) + g.ModPow(b, N)) % N;
		}

		/// <summary>
		/// Computes S, the premaster-secret.
		/// </summary>
		/// <param name="A">Client public ephemeral value.</param>
		/// <param name="b">Server secret ephemeral value.</param>
		/// <param name="u">The computed value of u.</param>
		/// <param name="v">The verifier.</param>
		internal SrpInteger ComputeS(SrpInteger A, SrpInteger b, SrpInteger u, SrpInteger v)
		{
			// N — A large safe prime (N = 2q+1, where q is prime)
			var N = Parameters.Prime;

			// S = (Av^u) ^ b (computes session key)
			return (A * v.ModPow(u, N)).ModPow(b, N);
		}

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
		public SrpSession DeriveSession(string serverSecretEphemeral, string clientPublicEphemeral, string salt, string username, string verifier, string clientSessionProof)
		{
			// N — A large safe prime (N = 2q+1, where q is prime)
			// g — A generator modulo N
			// k — Multiplier parameter (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
			// H — One-way hash function
			// PAD — Pad the number to have the same number of bytes as N
			var N = Parameters.Prime;
			var g = Parameters.Generator;
			var k = Parameters.Multiplier;
			var H = Parameters.Hash;
			var PAD = Parameters.Pad;

			// b — Secret ephemeral values
			// A — Public ephemeral values
			// s — User's salt
			// p — Cleartext Password
			// I — Username
			// v — Password verifier
			var b = SrpInteger.FromHex(serverSecretEphemeral);
			var A = SrpInteger.FromHex(clientPublicEphemeral);
			var s = SrpInteger.FromHex(salt);
			var I = username + string.Empty;
			var v = SrpInteger.FromHex(verifier);

			var B = ComputeB(verifier, b);

			// A % N > 0
			if (A % N == 0)
			{
				// fixme: .code, .statusCode, etc.
				throw new SecurityException("The client sent an invalid public ephemeral");
			}

			// u = H(PAD(A), PAD(B))
			var u = H(PAD(A), PAD(B));

			// S = (Av^u) ^ b (computes session key)
			var S = ComputeS(A, b, u, v);

			// K = H(S)
			var K = H(S);

			// M = H(H(N) xor H(g), H(I), s, A, B, K)
			var M = H(H(N) ^ H(g), H(I), s, A, B, K);

			// validate client session proof
			var expected = M;
			var actual = SrpInteger.FromHex(clientSessionProof);
			if (actual != expected)
			{
				// fixme: .code, .statusCode, etc.
				throw new SecurityException("Client provided session proof is invalid");
			}

			// P = H(A, M, K)
			var P = H(A, M, K);

			return new SrpSession
			{
				Key = K.ToHex(),
				Proof = P.ToHex(),
			};
		}
	}
}

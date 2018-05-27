using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using Newtonsoft.Json;
using NUnit.Framework;

namespace Zyan.SecureRemotePassword.Tests
{
	using TestClass = TestFixtureAttribute;
	using TestMethod = TestAttribute;

	/// <summary>
	/// Test class for SRP-6a protocol implementation.
	///</summary>
	[TestClass]
	public class SrpTestVectors
	{
		[TestMethod]
		public void VerifyTestVector()
		{
			var json = new WebClient().DownloadString("https://raw.githubusercontent.com/secure-remote-password/test-vectors/master/rfc5054.json");
			var testVectors = JsonConvert.DeserializeObject<TestVectorSet>(json);
			foreach (var tv in testVectors.TestVectors)
			{
				VerifyTestVector(tv);
			}
		}

		private void VerifyTestVector(TestVectorSet.TestVector testVector)
		{
			// prepare parameters
			var parameters = testVector.CreateParameters();
			var N = parameters.N;
			var g = parameters.G;
			var H = parameters.H;

			// validate the multiplier parameter
			var k = parameters.K;
			var kx = SrpInteger.FromHex(testVector.k);
			Assert.AreEqual(kx, k);

			// prepare user name, password and salt
			var I = testVector.I;
			var P = testVector.P;
			var s = SrpInteger.FromHex(testVector.s).ToHex();
			var client = new SrpClient(parameters);
			var server = new SrpServer(parameters);

			// validate the private key
			var x = SrpInteger.FromHex(client.DerivePrivateKey(s, I, P));
			var xx = SrpInteger.FromHex(testVector.x);
			Assert.AreEqual(xx, x);

			// validate the verifier
			var v = SrpInteger.FromHex(client.DeriveVerifier(x));
			var vx = SrpInteger.FromHex(testVector.v);
			Assert.AreEqual(vx, v);

			// client ephemeral
			var a = SrpInteger.FromHex(testVector.a);
			var A = client.ComputeA(a);
			var Ax = SrpInteger.FromHex(testVector.A);
			Assert.AreEqual(Ax, A);
			var clientEphemeral = new SrpEphemeral { Public = A, Secret = a };

			// server ephemeral
			var b = SrpInteger.FromHex(testVector.b);
			var B = server.ComputeB(v, b);
			var Bx = SrpInteger.FromHex(testVector.B);
			Assert.AreEqual(Bx, B);
			var serverEphemeral = new SrpEphemeral { Public = B, Secret = a };

			// validate u
			var u = client.ComputeU(A, B);
			var ux = SrpInteger.FromHex(testVector.u);
			Assert.AreEqual(ux, u);

			// premaster secret — client version
			var S = client.ComputeS(a, B, u, x);
			var Sx = SrpInteger.FromHex(testVector.S);
			Assert.AreEqual(Sx, S);

			// premaster secret — server version
			S = server.ComputeS(A, b, u, v);
			Assert.AreEqual(Sx, S);

			// client session
			var clientSession = client.DeriveSession(a, B, s, I, x);
			if (testVector.M1 != null)
			{
				Assert.AreEqual(testVector.M1, clientSession.Proof);
			}

			// server session
			var serverSession = server.DeriveSession(b, A, s, I, v, clientSession.Proof);
			Assert.AreEqual(clientSession.Key, serverSession.Key);
			if (testVector.M2 != null)
			{
				Assert.AreEqual(testVector.M2, serverSession.Proof);
			}

			// verify server session
			client.VerifySession(A, clientSession, serverSession.Proof);
			if (testVector.K != null)
			{
				Assert.AreEqual(testVector.K, serverSession.Key);
			}
		}
	}
}

﻿using System;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
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
	public class SrpAuthenticationTests
	{
		public class TestVectorSet
		{
			public string Comments { get; set; }
			public string Url { get; set; }
			public TestVector[] TestVectors { get; set; }

			public class TestVector
			{
				public string H { get; set; }
				public int Size { get; set; }
				public string N { get; set; }
				public string g { get; set; }
				public string I { get; set; }
				public string P { get; set; }
				public string s { get; set; }
				public string k { get; set; }
				public string x { get; set; }
				public string v { get; set; }
				public string a { get; set; }
				public string b { get; set; }
				public string A { get; set; }
				public string B { get; set; }
				public string u { get; set; }
				public string S { get; set; }
			}
		}

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
			var N = SrpInteger.FromHex(testVector.N);
			var g = SrpInteger.FromHex(testVector.g);
			var p = SrpParameters.Create<SHA1>(N, g);
			var H = p.H;
			var k = p.K;
			var kx = SrpInteger.FromHex(testVector.k);
			Assert.AreEqual(kx, k);

			// prepare user name, password and salt
			var I = testVector.I;
			var P = testVector.P;
			var s = SrpInteger.FromHex(testVector.s).ToHex();
			var client = new SrpClient(p);
			var server = new SrpServer(p);

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

			// u
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
			Assert.AreEqual("017eefa1cefc5c2e626e21598987f31e0f1b11bb", clientSession.Key);
			Assert.AreEqual("3f3bc67169ea71302599cf1b0f5d408b7b65d347", clientSession.Proof);

			// server session
			var serverSession = server.DeriveSession(b, A, s, I, v, clientSession.Proof);
			Assert.AreEqual("017eefa1cefc5c2e626e21598987f31e0f1b11bb", serverSession.Key);
			Assert.AreEqual("9cab3c575a11de37d3ac1421a9f009236a48eb55", serverSession.Proof);

			// verify server session
			client.VerifySession(A, clientSession, serverSession.Proof);
		}

		[TestMethod]
		public void SrpTestVectorsFromRfc5054()
		{
			// https://www.ietf.org/rfc/rfc5054.txt
			var N = SrpInteger.FromHex(@"EEAF0AB9 ADB38DD6 9C33F80A FA8FC5E8 60726187 75FF3C0B 9EA2314C
				9C256576 D674DF74 96EA81D3 383B4813 D692C6E0 E0D5D8E2 50B98BE4
				8E495C1D 6089DAD1 5DC7D7B4 6154D6B6 CE8EF4AD 69B15D49 82559B29
				7BCF1885 C529F566 660E57EC 68EDBC3C 05726CC0 2FD4CBF4 976EAA9A
				FD5138FE 8376435B 9FC61D2F C0EB06E3");
			var g = SrpInteger.FromHex("02");
			var p = SrpParameters.Create<SHA1>(N, g);
			var H = p.H;
			var k = p.K;
			var kx = SrpInteger.FromHex(@"7556AA04 5AEF2CDD 07ABAF0F 665C3E81 8913186F");
			Assert.AreEqual(kx, k);

			// prepare known parameters
			var I = "alice";
			var P = "password123";
			var s = SrpInteger.FromHex(@"BEB25379 D1A8581E B5A72767 3A2441EE").ToHex();
			var client = new SrpClient(p);
			var server = new SrpServer(p);

			// validate the private key
			var x = SrpInteger.FromHex(client.DerivePrivateKey(s, I, P));
			var xx = SrpInteger.FromHex(@"94B7555A ABE9127C C58CCF49 93DB6CF8 4D16C124");
			Assert.AreEqual(xx, x);

			// validate the verifier
			var v = SrpInteger.FromHex(client.DeriveVerifier(x));
			var vx = SrpInteger.FromHex(@"
				7E273DE8 696FFC4F 4E337D05 B4B375BE B0DDE156 9E8FA00A 9886D812
				9BADA1F1 822223CA 1A605B53 0E379BA4 729FDC59 F105B478 7E5186F5
				C671085A 1447B52A 48CF1970 B4FB6F84 00BBF4CE BFBB1681 52E08AB5
				EA53D15C 1AFF87B2 B9DA6E04 E058AD51 CC72BFC9 033B564E 26480D78
				E955A5E2 9E7AB245 DB2BE315 E2099AFB");
			Assert.AreEqual(vx, v);

			// client ephemeral
			var a = SrpInteger.FromHex("60975527 035CF2AD 1989806F 0407210B C81EDC04 E2762A56 AFD529DD DA2D4393");
			var A = client.ComputeA(a);
			var Ax = SrpInteger.FromHex(@"
				61D5E490 F6F1B795 47B0704C 436F523D D0E560F0 C64115BB 72557EC4
				4352E890 3211C046 92272D8B 2D1A5358 A2CF1B6E 0BFCF99F 921530EC
				8E393561 79EAE45E 42BA92AE ACED8251 71E1E8B9 AF6D9C03 E1327F44
				BE087EF0 6530E69F 66615261 EEF54073 CA11CF58 58F0EDFD FE15EFEA
				B349EF5D 76988A36 72FAC47B 0769447B");
			Assert.AreEqual(Ax, A);
			var clientEphemeral = new SrpEphemeral { Public = A, Secret = a };

			// server ephemeral
			var b = SrpInteger.FromHex("E487CB59 D31AC550 471E81F0 0F6928E0 1DDA08E9 74A004F4 9E61F5D1 05284D20");
			var B = server.ComputeB(v, b);
			var Bx = SrpInteger.FromHex(@"
				BD0C6151 2C692C0C B6D041FA 01BB152D 4916A1E7 7AF46AE1 05393011
				BAF38964 DC46A067 0DD125B9 5A981652 236F99D9 B681CBF8 7837EC99
				6C6DA044 53728610 D0C6DDB5 8B318885 D7D82C7F 8DEB75CE 7BD4FBAA
				37089E6F 9C6059F3 88838E7A 00030B33 1EB76840 910440B1 B27AAEAE
				EB4012B7 D7665238 A8E3FB00 4B117B58");
			Assert.AreEqual(Bx, B);
			var serverEphemeral = new SrpEphemeral { Public = B, Secret = a };

			// u
			var u = client.ComputeU(A, B);
			var ux = SrpInteger.FromHex("CE38B959 3487DA98 554ED47D 70A7AE5F 462EF019");
			Assert.AreEqual(ux, u);

			// premaster secret — client version
			var S = client.ComputeS(a, B, u, x);
			var Sx = SrpInteger.FromHex(@"
				B0DC82BA BCF30674 AE450C02 87745E79 90A3381F 63B387AA F271A10D
				233861E3 59B48220 F7C4693C 9AE12B0A 6F67809F 0876E2D0 13800D6C
				41BB59B6 D5979B5C 00A172B4 A2A5903A 0BDCAF8A 709585EB 2AFAFA8F
				3499B200 210DCC1F 10EB3394 3CD67FC8 8A2F39A4 BE5BEC4E C0A3212D
				C346D7E4 74B29EDE 8A469FFE CA686E5A");
			Assert.AreEqual(Sx, S);

			// premaster secret — server version
			S = server.ComputeS(A, b, u, v);
			Assert.AreEqual(Sx, S);

			// client session
			var clientSession = client.DeriveSession(a, B, s, I, x);
			Assert.AreEqual("017eefa1cefc5c2e626e21598987f31e0f1b11bb", clientSession.Key);
			Assert.AreEqual("3f3bc67169ea71302599cf1b0f5d408b7b65d347", clientSession.Proof);

			// server session
			var serverSession = server.DeriveSession(b, A, s, I, v, clientSession.Proof);
			Assert.AreEqual("017eefa1cefc5c2e626e21598987f31e0f1b11bb", serverSession.Key);
			Assert.AreEqual("9cab3c575a11de37d3ac1421a9f009236a48eb55", serverSession.Proof);

			// verify server session
			client.VerifySession(A, clientSession, serverSession.Proof);
		}

		[TestMethod]
		public void SrpShouldAuthenticateAUser()
		{
			// default parameters, taken from https://github.com/LinusU/secure-remote-password/blob/master/test.js
			SrpAuthentication("linus@folkdatorn.se", "$uper$ecure");

			// sha512, 512-bit prime number
			var parameters = SrpParameters.Create<SHA512>("D4C7F8A2B32C11B8FBA9581EC4BA4F1B04215642EF7355E37C0FC0443EF756EA2C6B8EEB755A1C723027663CAA265EF785B8FF6A9B35227A52D86633DBDFCA43", "03");
			SrpAuthentication("yallie@yandex.ru", "h4ck3r$", parameters);

			// md5, 1024-bit prime number from wikipedia (generated using "openssl dhparam -text 1024")
			parameters = SrpParameters.Create<SHA384>("00c037c37588b4329887e61c2da3324b1ba4b81a63f9748fed2d8a410c2fc21b1232f0d3bfa024276cfd88448197aae486a63bfca7b8bf7754dfb327c7201f6fd17fd7fd74158bd31ce772c9f5f8ab584548a99a759b5a2c0532162b7b6218e8f142bce2c30d7784689a483e095e701618437913a8c39c3dd0d4ca3c500b885fe3", "07");
			SrpAuthentication("bozo", "h4ck3r", parameters);

			// sha1 hash function, default N and g values for all standard groups
			SrpAuthenticationUsingStandardParameters<SHA1>("hello", "world");
		}

		// [Test, Explicit]
		public void SrpStressTest()
		{
			// 100 iterations take ~10 minutes on my machine
			for (var i = 0; i < 100; i++)
			{
				SrpShouldAuthenticateAUser();
			}
		}

		// [Test, Explicit]
		public void SrpUsingStandardParameters()
		{
			// takes ~42 seconds on my machine
			SrpAuthenticationUsingStandardParameters<SHA1>("user", "password");
			SrpAuthenticationUsingStandardParameters<SHA256>("LongUser", "stronger-password");
			SrpAuthenticationUsingStandardParameters<SHA384>("root", "$hacker$");
			SrpAuthenticationUsingStandardParameters<SHA512>("Administrator", "123456");
			SrpAuthenticationUsingStandardParameters<MD5>("not-safe", "dont-use");
		}

		private void SrpAuthenticationUsingStandardParameters<T>(string username, string password) where T : HashAlgorithm
		{
			// test all standard groups using the same hashing algorithm
			SrpAuthentication(username, password, SrpParameters.Create1024<T>());
			SrpAuthentication(username, password, SrpParameters.Create1536<T>());
			SrpAuthentication(username, password, SrpParameters.Create2048<T>());
			SrpAuthentication(username, password, SrpParameters.Create3072<T>());
			SrpAuthentication(username, password, SrpParameters.Create4096<T>());
			SrpAuthentication(username, password, SrpParameters.Create6144<T>());
			SrpAuthentication(username, password, SrpParameters.Create8192<T>());
		}

		private void SrpAuthentication(string username, string password, SrpParameters parameters = null)
		{
			// use default parameters if not specified: sha256, 2048-bit prime number
			var client = new SrpClient(parameters);
			var server = new SrpServer(parameters);

			// sign up
			var salt = client.GenerateSalt();
			var privateKey = client.DerivePrivateKey(salt, username, password);
			var verifier = client.DeriveVerifier(privateKey);

			// authenticate
			var clientEphemeral = client.GenerateEphemeral();
			var serverEphemeral = server.GenerateEphemeral(verifier);
			var clientSession = client.DeriveSession(clientEphemeral.Secret, serverEphemeral.Public, salt, username, privateKey);

			try
			{
				var serverSession = server.DeriveSession(serverEphemeral.Secret, clientEphemeral.Public, salt, username, verifier, clientSession.Proof);
				client.VerifySession(clientEphemeral.Public, clientSession, serverSession.Proof);

				// make sure both the client and the server have the same session key
				Assert.AreEqual(clientSession.Key, serverSession.Key);
			}
			catch
			{
				// generate the regression test code
				Console.WriteLine("// regression test:");
				Console.WriteLine($"var parameters = {parameters?.ToString() ?? "new SrpParameters()"};");
				Console.WriteLine($"var serverEphemeral = new SrpEphemeral");
				Console.WriteLine($"{{");
				Console.WriteLine($"	Secret = \"{serverEphemeral.Secret}\",");
				Console.WriteLine($"	Public = \"{serverEphemeral.Public}\",");
				Console.WriteLine($"}};");
				Console.WriteLine();
				Console.WriteLine($"var clientEphemeral = new SrpEphemeral");
				Console.WriteLine($"{{");
				Console.WriteLine($"	Secret = \"{clientEphemeral.Secret}\",");
				Console.WriteLine($"	Public = \"{clientEphemeral.Public}\",");
				Console.WriteLine($"}};");
				Console.WriteLine();
				Console.WriteLine($"var salt = \"{salt}\";");
				Console.WriteLine($"var username = \"{username}\";");
				Console.WriteLine($"var privateKey = \"{privateKey}\";");
				Console.WriteLine($"var verifier = \"{verifier}\";");
				Console.WriteLine($"var clientSessionProof = \"{clientSession.Proof}\";");
				Console.WriteLine($"var serverSessionKey = \"{clientSession.Key}\";");
				Console.WriteLine($"var serverSessionProof = \"????\";");
				Console.WriteLine();
				Console.WriteLine($"var clientSession = new SrpClient(parameters).DeriveSession(clientEphemeral.Secret, serverEphemeral.Public, salt, username, privateKey);");
				Console.WriteLine($"Assert.IsNotNull(clientSession);");
				Console.WriteLine($"Assert.AreEqual(serverSessionKey, clientSession.Key);");
				Console.WriteLine($"Assert.AreEqual(clientSessionProof, clientSession.Proof);");
				Console.WriteLine();
				Console.WriteLine($"var serverSession = new SrpServer(parameters).DeriveSession(serverEphemeral.Secret, clientEphemeral.Public, salt, username, verifier, clientSessionProof);");
				Console.WriteLine($"Assert.IsNotNull(serverSession);");
				Console.WriteLine($"Assert.AreEqual(serverSessionKey, serverSession.Key);");
				Console.WriteLine($"Assert.AreEqual(serverSessionProof, serverSession.Proof);");
				throw;
			}
		}
	}
}
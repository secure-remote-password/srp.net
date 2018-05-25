using System;
using System.Linq;
using System.Security.Cryptography;
using NUnit.Framework;

namespace Zyan.SecureRemotePassword.Tests
{
	using TestClass = TestFixtureAttribute;
	using TestMethod = TestAttribute;

	/// <summary>
	/// <see cref="SrpClient"/> tests.
	///</summary>
	[TestClass]
	public class SrpClientTests
	{
		[TestMethod]
		public void SrpClientGenerateSaltReturnsRandomInteger()
		{
			var salt = new SrpClient().GenerateSalt();
			Assert.IsNotNull(salt);
			Assert.AreNotEqual(string.Empty, salt);
			Assert.AreEqual(new SrpParameters().HashSizeBytes * 2, salt.Length);
		}

		[TestMethod]
		public void SrpClientDerivesThePrivateKeyAndVerifier()
		{
			// validate intermediate steps
			var userName = "hacker@example.com";
			var password = "secret";
			var H = new SrpHash<SHA256>().HashFunction;
			var step1 = H($"{userName}:{password}");
			Assert.AreEqual(SrpInteger.FromHex("ed3250071433e544b62b5dd0341564825a697357b5379f07aabca795a4e0a109"), step1);

			// step1.1
			var salt = "34ada39bbabfa6e663f1aad3d7814121";
			var s = SrpInteger.FromHex(salt);
			var step11 = H(s);
			Assert.AreEqual(SrpInteger.FromHex("a5acfc1292e1b8e171b7c9a0f7b5bcd9bbcd4a3485c18d9d4fcf4480e8573442"), step11);

			// step1.2
			var step12 = H(step1);
			Assert.AreEqual(SrpInteger.FromHex("446d597ddf0e65ca0395926665e70f10a2b0f8194f633243e71359028895be6f"), step12);

			// step2
			var step2 = H(s, step1);
			Assert.AreEqual(SrpInteger.FromHex("e2db59181003e48e326292b3b307a1173a5f1fd12c6ffde55f7289503065fd6c"), step2);

			// private key derivation is deterministic for the same s, I, p
			var privateKey = new SrpClient().DerivePrivateKey(salt, userName, password);
			Assert.AreEqual("e2db59181003e48e326292b3b307a1173a5f1fd12c6ffde55f7289503065fd6c", privateKey);

			// verifier
			var verifier = new SrpClient().DeriveVerifier(privateKey);
			Assert.AreEqual("622dad56d6c282a949f9d2702941a9866b7dd277af92a6e538b2d7cca42583275a2f4b64bd61369a24b23170223faf212e2f3bdddc529204c61055687c4162aa2cd0fd41ced0186406b8a6dda4802fa941c54f5115ca69953a8e265210349a4cb89dda3febc96c86df08a87823235ff6c87a170cc1618f38ec493e758e2cac4c04db3dcdac8656458296dbcc3599fc1f66cde1e62e477dd1696c65dbeb413d8ed832adc7304e68566b46a7849126eea62c95d5561306f76fe1f8a77a3bd85db85e6b0262064d665890ff46170f96ce403a9b485abe387e91ca85e3522d6276e2fff41754d57a71dee6da62aea614725da100631efd7442cf68a294001d8134e9", verifier);
		}

		[TestMethod]
		public void SrpClientGeneratesEphemeralValue()
		{
			var ephemeral = new SrpClient().GenerateEphemeral();
			Assert.IsNotNull(ephemeral.Public);
			Assert.AreNotEqual(string.Empty, ephemeral.Public);

			Assert.IsNotNull(ephemeral.Secret);
			Assert.AreNotEqual(string.Empty, ephemeral.Secret);

			Assert.AreNotEqual(ephemeral.Secret, ephemeral.Public);
			Assert.IsTrue(ephemeral.Secret.Length < ephemeral.Public.Length);
		}

		[TestMethod]
		public void SrpClientDeriveSession()
		{
			var clientEphemeralSecret = "27b282fc8fbf8d8a5a075ff4992406ec730bc80eea2f9b89a75bb95f1272265e";
			var serverEphemeralPublic = "084153f1c6374fbf166f99b870b771fbd4ce3d3455671d5ee974eae65a06d1791b263af47c7fc2b4288267b943f8c30d3c049f0627a60badb78be3708a76b7ab0d1a64235cf00e7376001e3bddaccfc90148752062e36d70a81a56d3b4446f258beb255d17bd1b3aa05bb6012ca306ab1342dcc558c66daa19d1169b7cefb6005fcd92fbc4d593f3e4fec3e356b214c89fe26508c49b11b9efa04ecf6f05a748a50464252909eca2e04c9623d0997273b28499b1ea8c42d5a022609e2a89f6906e13dd3c9142a92575424311448fdf588524a64488fb8d2fcd1a5f2b2c059515fe0c83fd499b7b3fb2fe46f42fa7fc8d72cc0c04a5c9b22ebceddebf8fac4d8e";
			var salt = "d420d13b7e510e9457fb59d03819c6475fe53f680b4abb963ef9f6d4f6ddb04e";
			var username = "bozo";
			var privateKey = "f8af13ffc45b3c64a826e3a133b8a74d0484e47625c049b7f635dd233cbda124";
			var clientSessionKey = "52121d4c5d029b91bd856fe373bdf7cd81c7c48727eb8d765959518b9eda20a7";
			var clientSessionProof = "96340088aec5717eb66b88e3a47c70865756970f48876ab4c8ca6ea359a70e2d";

			var clientSession = new SrpClient().DeriveSession(clientEphemeralSecret, serverEphemeralPublic, salt, username, privateKey);
			Assert.IsNotNull(clientSession);
			Assert.AreEqual(clientSessionKey, clientSession.Key);
			Assert.AreEqual(clientSessionProof, clientSession.Proof);
		}

		[TestMethod]
		public void SrpClientDeriveSessionRegressionTest()
		{
			var clientEphemeralSecret = "72dac3f6f7ade13135e234d9d3c4899453418c929af72c4171ffdc920fcf2535";
			var serverEphemeralPublic = "1139bdcab77770878d8cb72536a4368f315897e36cdcbfe603971f70be6190500b064d3202fa4a57bb8aa25fb2fba871fa66fb59183e17f8513ec2746e6193143f3c439512d243b2c0b92cbf671a2ed5712d2ef6f190840e7e1bf6b2480c837fc7f3b8f6e4b27f25b7af96a0197a21c175c0e067164151c151f7c68190fc8b7e10b45055e4bc18a4abf07e6f9a02d3be916b2783c474d7babef10867abf12370455b65749ed35dcd376addf3dad8a156a49a306b13041e3a4795654384faec21a19c40c429e5629b92e8925fb7f7a62d925cb99a15c06b41d7c50d1b7c38a05dea2ed5a14c5657de29f2864b1535f6eedd6ff6746a5b4d1521e101481a342e4f";
			var salt = "532ec0e523a7b19db660f00eb00e91f033697f0ab58a542c99be8e9a08f48d6e";
			var username = "linus@folkdatorn.se";
			var privateKey = "79c7aadce96da2387b01a48ce5b9e910eb3f9e1ac0f8574b314c3f0fe8106f08";
			var clientSessionKey = "39be93f466aeea2de0a498600c546969eaeebbf015690bd6cefe624ddaf5c383";
			var clientSessionProof = "2410ed11831f58d7522f088f089e3d68fa2eaf4f0510913764f50f0e31e8c471";

			var clientSession = new SrpClient().DeriveSession(clientEphemeralSecret, serverEphemeralPublic, salt, username, privateKey);
			Assert.IsNotNull(clientSession);
			Assert.AreEqual(clientSessionKey, clientSession.Key);
			Assert.AreEqual(clientSessionProof, clientSession.Proof);
		}

		[TestMethod]
		public void SrpClientVerifiesSession()
		{
			var clientEphemeralPublic = "30fca5854c2391faa219fd863487c31f2591f5ba9988ce5129319906929ff2d23bc4e24c3f36f6ed12034111881ca705b033edfb782a1714e0f4d892f17c7d8432a1089c311c3170848bba0a0f64930d3f097c670b08384f1641a73833edaf9d1493744e655043df0d68f0c18a1571cc1c07c41ad817b57c262f48dde991d413628c0f3fa1de55afcf2d87e994c7f6e25c07cf1a803d41f555158997cd8703da68a48e54598b5b4947cc661d5c0138a5ecaa55996d5d6b566578f9de3b1ca1e128ff223c290595252497835646b9f8c0e330f4d6a3e61f31ff3eb8e305f563cb112ca90942e770f94cd02396041ab4c47e0c58675ded8bb0026640f9723b4d67";
			var clientSessionKey = "0bb4c696fd6f240fa0b268f3ce267044b05d620ac5f9871d21e4f89a3b0ac841";
			var clientSessionProof = "50a240e5b5f4d0db633e147d92a32aa0c9451e5d0508bded623b40200d237eef";
			var serverSessionProof = "a06d7fe3d45542f993c39b145ea3a0e3f5d6943373af35af355bb82692d692e8";
			var clientSession = new SrpSession
			{
				Key = clientSessionKey,
				Proof = clientSessionProof,
			};

			new SrpClient().VerifySession(clientEphemeralPublic, clientSession, serverSessionProof);
		}
	}
}

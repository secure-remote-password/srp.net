using System;
using System.Linq;
using System.Security.Cryptography;
using NUnit.Framework;

namespace Zyan.SecureRemotePassword.Tests
{
	using TestClass = TestFixtureAttribute;
	using TestMethod = TestAttribute;

	/// <summary>
	/// <see cref="SrpServer"/> tests.
	///</summary>
	[TestClass]
	public class SrpServerTests
	{
		[TestMethod]
		public void SrpServerGeneratesEphemeralValue()
		{
			var verifier = "622dad56d6c282a949f9d2702941a9866b7dd277af92a6e538b2d7cca42583275a2f4b64bd61369a24b23170223faf212e2f3bdddc529204c61055687c4162aa2cd0fd41ced0186406b8a6dda4802fa941c54f5115ca69953a8e265210349a4cb89dda3febc96c86df08a87823235ff6c87a170cc1618f38ec493e758e2cac4c04db3dcdac8656458296dbcc3599fc1f66cde1e62e477dd1696c65dbeb413d8ed832adc7304e68566b46a7849126eea62c95d5561306f76fe1f8a77a3bd85db85e6b0262064d665890ff46170f96ce403a9b485abe387e91ca85e3522d6276e2fff41754d57a71dee6da62aea614725da100631efd7442cf68a294001d8134e9";
			var ephemeral = new SrpServer().GenerateEphemeral(verifier);
			Assert.IsNotNull(ephemeral.Public);
			Assert.AreNotEqual(string.Empty, ephemeral.Public);

			Assert.IsNotNull(ephemeral.Secret);
			Assert.AreNotEqual(string.Empty, ephemeral.Secret);

			Assert.AreNotEqual(ephemeral.Secret, ephemeral.Public);
			Assert.IsTrue(ephemeral.Secret.Length < ephemeral.Public.Length);
		}

		[TestMethod]
		public void SrpServerDeriveSession()
		{
			var serverSecretEphemeral = "e252dc34cc300c5f330ae3c684bf1b1657f5b1ca694bbfbba14829bb16e5638c";
			var clientPublicEphemeral = "278f74f97e2dcdf886769ce31c87513a4a73548762a29b2db0188757fdccf066393ed79305d946e80b6e5d963771d62475566cb2ce0883076c8846d8f961d9396ffcba54447879772b4b8a43de258662e52407bb7f0f6397a8402173f69e4a306aed850b9df89fc78ddbc72d76aa6b0e99555e8b08a21b4d91c6cd86cee4c2117a54a0a58ae0a7f6f0c8699cf0709e9ac7ba009c2e304b3e8559d76d3b3a27c016f2647a3f4ba3f94494a4a61d799d9fda67000331976f8e1b6f5b68504cadfd9a48fa5dc73ef39b7e7ad07338a7fc7bd82777bd7ad2a7b7abcbbcbfa50e0e949b2a5726fe30361298b3981e620fb57f0c58684b5b24ad317f18b288474b10d8";
			var salt = "d420d13b7e510e9457fb59d03819c6475fe53f680b4abb963ef9f6d4f6ddb04e";
			var username = "bozo";
			var verifier = "a9f253f5da8b0ec3ea2fdf01ae497799ff2fb3b4b2c2c488b01c9beeeed543a9de3c7014d05b4014e0986dda96c9f416d90c858a7483740845f0f6cd5a6eef1b140d1b46bb37f5bcfbb28127bf84f9b7f5c0d5cc4329cb7b166ff45375becdfe941664167903fb0fc9c035ee5b3cb5411a34b91e2f9b0dcc5310bf1b6c514ac63a15eb811bb652a65f96e105079942a5c7d21724910c1c2a2615ea1ceeddcc879c05658e6efd75db15250300080680875d4e31054dc508d446db31e2683724c785e7651fdf26faea054479ce95ea2443e6464ba1f53b62e7eaa8e21075a082a7ed6d937be65e835bacaa37d45651baf202601506e6246a2a183e178acc50bbd5";
			var clientSessionProof = "63f0ae40f93cce889c08dc143e2535d8b0797920cdd29484e77aec010827692a";
			var serverSessionKey = "7de5394ade704c03b2ac22011b6b66fba7280dc7ce8a9c07d28af762bc5f07cc";
			var serverSessionProof = "75b9ed3883ecc9bc01b6eeebd953b94179ed0e8816810f7bcc140786929289b0";

			var serverSession = new SrpServer().DeriveSession(serverSecretEphemeral, clientPublicEphemeral, salt, username, verifier, clientSessionProof);
			Assert.IsNotNull(serverSession);
			Assert.AreEqual(serverSessionKey, serverSession.Key);
			Assert.AreEqual(serverSessionProof, serverSession.Proof);
		}

		[TestMethod]
		public void SrpServerDeriveSessionRegressionTest1()
		{
			var serverSecretEphemeral = "10586d81ccecdce05f7a6ad2ed205b7f5615f84463fdcf584bfec2f288fad5f5";
			var clientPublicEphemeral = "5bff094e878aa7aefb777fe78067a75d459223e58d2d41ea810017fee3e8b0fdd7085d94ce0db7935dcb81e78d14c7e8a3dcacad4c2d6aa29c23724fab4303131ef8e9f3ed13ccd2414be43e851abf6713060699d94137fda38b59e524dbc2caebc7e3cd388e14abed4e3e9e6e25744b708a4c6ee79a84009b81b1a2e69ba0c926856b0e1858597239ad230aa0b95070968833f357613d9dd69bd30a1450af284adea261eb383cf9c3ae1e992ed8382527e8d680c20b54ad46e24c55998a784fd55f4c37a64562cd8beee0f9f3ee607d7bf4199e05c37129364ab0daf9c4768070a54c5ed125184a56d659d05f8b6b66ede56da1f82f48ee3d272370edd876ff";
			var salt = "4ea524accbfee7a2ba67301422b7c8ba4ce205a68bb8bfc36e32fab005c9f4f4";
			var username = "linus@folkdatorn.se";
			var verifier = "2052387840d2a36b5da0a0b74d1b4c5f3216003a00977681b2bad3b4b6005fcee73fcc644106018bcd090afc50455cbde18194b1ef34be4a44418624cd6a0b974cd7a890c9115bbe0f538806c2016b4db5b9dd8bd5f7e2819720c2e4a42479a06297eee9d8acb9326b49a9a16358b7fdd75ce20e7b03993f13f17747a5ea4c02b3b116632bcd34f1da265704a43d074845373b6fc528a858abb07c4ab162a8f30847628f19bc26149d43ecf7570c10463b2a3e886665cb3af7d186a209a4b8d9b85f6ba9c23852311856011e642633fde3bfd48cf43c2f54070b3340408d4f615e536f4bf1656b794d5bee861bb28f16c55e36025ebf3421db0f51682e03e2ea";
			var clientSessionProof = "6842a3726f5b3452983f5eb20cbf244d67a8269d558cb4d11dab6cfbe9908097";
			var serverSessionKey = "389c0b233952136feaeb68816b6a759d31deb80e8a86696969acf939df9f0688";
			var serverSessionProof = "2420ad80c3eec1d6568fb9112198b20d4b576f4457a3cb1a10df85ecf670c466";

			var serverSession = new SrpServer().DeriveSession(serverSecretEphemeral, clientPublicEphemeral, salt, username, verifier, clientSessionProof);
			Assert.IsNotNull(serverSession);
			Assert.AreEqual(serverSessionKey, serverSession.Key);
			Assert.AreEqual(serverSessionProof, serverSession.Proof);
		}

		[TestMethod]
		public void SrpServerDeriveSessionRegressionTest2()
		{
			// regression test:
			var parameters = new SrpParameters();
			var clientEphemeral = new SrpEphemeral
			{
				Secret = "64e1124e73967bb4806cf5e3f151c574d0012147255e10fca02e9b4bafc8f4ba",
				Public = "07be00c7e6aa8198eddc42cc2f251901f3bc05795fefd5f40f90f0a6bfe66743954ef18ece62d229095a704197be18c0d1ca3a280381c8a53b42173df36867c29c564e8c974cf4ff4718547d27bd9c08eb9a909fb984e8e23a109eaf4f57a337c9cbe1609e35b9fddbc9f847825b1c37167cb3f10b3b284a7370323818571e6369e91b4ac6f6eedcdbc1c7d8d57b2020d43be7fec3df14a120c76d27ebabc8d93cdc555362a4c7c08a1052e67647e9f3f879846389672e7a5d6e1ff93940d4196bef451e8d6a3b410a5062ac29cee3783e9a5aeac9724ad1375a2189c3b5a8dbf671dfad990132d2e5b73eb5a2e3d2034b6b908210f5fe61272b2cf4d1e3a4aa",
			};

			var serverEphemeral = new SrpEphemeral
			{
				Secret = "54f5f01dc134a3decef47e5e74feb20ce60716965c1908aa422ec701e5c2ce23",
				Public = "47b1e293dff41447e74d33b6a13cfd3dc77e17580a6d724c633d106827dcba9578d222ea6931dfb37ba282998df04dae849eafc57e4bdbf8478f0fd312b4393af8d6512f6013ab4199b831673ce99f14240ef3202803bb4ced05cb046c42a108b2342fdd3e30f8ba7b8f154243b6873a30c467d368888a5a95ed7abaad10ba0bd093717c1479e46e8e15b20809bc7e2f3bc316d09c0b6a3289852ac4d441be50d3ce1ec76ded2f44c643e8fbfa762a62f3311e3425c7f6730d7b35f9037dc07d6165968ece3b4885b5d5cb264a50595cf989622b2fe156a0d98101e5f14f808a3595da761885188f50230fcddc4dd34ec38de5f64a44fdcd1f535f5f83f900d7",
			};

			var salt = "31c3af4879262b1ee85295480b14800672cbb59870e7ae1980a07ee56eaa25fc";
			var username = "hello";
			var privateKey = "d3f37035827919d8803d246d0a81dcf0118e84f85e45c4c06f2c362262422118";
			var verifier = "1786105be4cde9793d4896047cd178260ded3a0623491d18b0e942469107012f0a8d67d40c41d5b4863233ee5cd6b765bf3bffd56d0b429445be5af163303d42ae5ced9ff29e3cd275eeba482d3dad3bac3d6f2cf2113c6be5c50dfd2e3a2a9a1bbf2d829d4a5538c36e94197dfce12e990d030a124ee77ebb843c416701d85f0e00f1001a93051aef27d6e7c7120d00f08c52e4b1ea99b050c6d4080d59c0080af439f9291d07e384f13d121c1374d71f0d168e6fbfab9408974bf652844c7ac07b77b5dbc3cb53cb89de9d7fdcaf33f21e1e73c16bdc487732b2773aa34da0777b1d057a8aa3fc3a0679661956fa2ee01f69bcc1535d381feaaa973e7d802c";
			var clientSessionProof = "ddc8c78aafe9c471086b3d20a4e4eb2401de2fcaa48081fea5357114dc508a23";
			var serverSessionKey = "bd0079ddefc205d65da9241ba416c44a131440c723e20de6e3bdb5bd662c9de0";
			var serverSessionProof = "01a62474121b11347f84d422088b469b949d9a376f89b87b8080f17931846ef5";

			var clientSession = new SrpClient(parameters).DeriveSession(clientEphemeral.Secret, serverEphemeral.Public, salt, username, privateKey);
			Assert.IsNotNull(clientSession);
			Assert.AreEqual(serverSessionKey, clientSession.Key);
			Assert.AreEqual(clientSessionProof, clientSession.Proof);

			var serverSession = new SrpServer(parameters).DeriveSession(serverEphemeral.Secret, clientEphemeral.Public, salt, username, verifier, clientSessionProof);
			Assert.IsNotNull(serverSession);
			Assert.AreEqual(serverSessionKey, serverSession.Key);
			Assert.AreEqual(serverSessionProof, serverSession.Proof);
		}
	}
}

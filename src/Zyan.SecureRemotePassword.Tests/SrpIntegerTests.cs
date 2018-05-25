using System;
using System.Linq;
using System.Security.Cryptography;
using NUnit.Framework;

namespace Zyan.SecureRemotePassword.Tests
{
	using TestClass = TestFixtureAttribute;
	using TestMethod = TestAttribute;

	/// <summary>
	/// <see cref="SrpInteger"/> tests.
	///</summary>
	[TestClass]
	public class SrpIntegerTests
	{
		[TestMethod]
		public void SrpIntegerToString()
		{
			var si = new SrpInteger("2");
			Assert.AreEqual("<SrpInteger: 2>", si.ToString());

			// 512-bit prime number
			si = new SrpInteger("D4C7F8A2B32C11B8FBA9581EC4BA4F1B04215642EF7355E37C0FC0443EF756EA2C6B8EEB755A1C723027663CAA265EF785B8FF6A9B35227A52D86633DBDFCA43");
			Assert.AreEqual("<SrpInteger: 0d4c7f8a2b32c11b...>", si.ToString());
		}

		[TestMethod]
		public void SrpIntegerFromHexToHex()
		{
			var si = SrpInteger.FromHex("02");
			Assert.AreEqual("02", si.ToHex());

			// 512-bit prime number
			si = SrpInteger.FromHex("D4C7F8A2B32C11B8FBA9581EC4BA4F1B04215642EF7355E37C0FC0443EF756EA2C6B8EEB755A1C723027663CAA265EF785B8FF6A9B35227A52D86633DBDFCA43");
			Assert.AreEqual("d4c7f8a2b32c11b8fba9581ec4ba4f1b04215642ef7355e37c0fc0443ef756ea2c6b8eeb755a1c723027663caa265ef785b8ff6a9b35227a52d86633dbdfca43", si.ToHex());

			// should keep padding when going back and forth
			Assert.AreEqual("a", SrpInteger.FromHex("a").ToHex());
			Assert.AreEqual("0a", SrpInteger.FromHex("0a").ToHex());
			Assert.AreEqual("00a", SrpInteger.FromHex("00a").ToHex());
			Assert.AreEqual("000a", SrpInteger.FromHex("000a").ToHex());
			Assert.AreEqual("0000a", SrpInteger.FromHex("0000a").ToHex());
			Assert.AreEqual("00000a", SrpInteger.FromHex("00000a").ToHex());
		}

		[TestMethod]
		public void SrpIntegerNormalizedLength()
		{
			var hex = SrpInteger.FromHex(@"
				7E273DE8 696FFC4F 4E337D05 B4B375BE B0DDE156 9E8FA00A 9886D812
				9BADA1F1 822223CA 1A605B53 0E379BA4 729FDC59 F105B478 7E5186F5
				C671085A 1447B52A 48CF1970 B4FB6F84 00BBF4CE BFBB1681 52E08AB5
				EA53D15C 1AFF87B2 B9DA6E04 E058AD51 CC72BFC9 033B564E 26480D78
				E955A5E2 9E7AB245 DB2BE315 E2099AFB").ToHex();

			Assert.IsTrue(hex.StartsWith("7e27") && hex.EndsWith("9afb"));
			Assert.AreEqual(256, hex.Length);
		}

		[TestMethod]
		public void SrpIntegerNegativeNumbers()
		{
			var srp = SrpInteger.FromHex("-f34");
			Assert.AreEqual("-f34", srp.ToHex());

			srp = 0x19 - SrpInteger.FromHex("face");
			Assert.AreEqual("-fab5", srp.ToHex());
		}

		[TestMethod]
		public void SrpIntegerAdd()
		{
			var result = SrpInteger.FromHex("353") + SrpInteger.FromHex("181");
			Assert.AreEqual("4d4", result.ToHex());
		}

		[TestMethod]
		public void SrpIntegerSubtract()
		{
			var result = SrpInteger.FromHex("5340") - SrpInteger.FromHex("5181");
			Assert.AreEqual("01bf", result.ToHex());
		}

		[TestMethod]
		public void SrpIntegerMultiply()
		{
			var result = SrpInteger.FromHex("CAFE") * SrpInteger.FromHex("babe");
			Assert.AreEqual("94133484", result.ToHex());
		}

		[TestMethod]
		public void SrpIntegerDivide()
		{
			var result = SrpInteger.FromHex("faced") / SrpInteger.FromHex("BABE");
			Assert.AreEqual("00015", result.ToHex());
		}

		[TestMethod]
		public void SrpIntegerModulo()
		{
			var result = SrpInteger.FromHex("10") % SrpInteger.FromHex("9");
			Assert.AreEqual("07", result.ToHex());
		}

		[TestMethod]
		public void SrpIntegerXor()
		{
			var left = SrpInteger.FromHex("32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909ba7696cf606ef40c04afe1ac0aa8148dd066592ded9f8774b529c7ea125d298e8883f5e9305f4b44f915cb2bd05af51373fd9b4af511039fa2d96f83414aaaf261bda2e97b170fb5cce2a53e675c154c0d9681596934777e2275b381ce2e40582afe67650b13e72287ff2270abcf73bb028932836fbdecfecee0a3b894473c1bbeb6b4913a536ce4f9b13f1efff71ea313c8661dd9a4ce");
			var right = SrpInteger.FromHex("71946f9bbb2aeadec111841a81abc300ecaa01bd8069d5cc91005e9fe4aad6e04d513e96d99de2569bc5e50eeeca709b50a8a987f4264edb6896fb537d0a716132ddc938fb0f836480e06ed0fcd6e9759f40462f9cf57f4564186a2c1778f1543efa270bda5e933421cbe88a4a52222190f471e9bd15f652b653b7071aec59a2705081ffe72651d08f822c9ed6d76e48b63ab15d0208573a7eef027");
			var xor = SrpInteger.FromHex("32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba3624730b208d83b237176b5a41e13d1a2c0080f55d6fb05e4fd9a6e8aff84a9eec74ec0e3115dd0808c011baa15b2c29edad06d6c319976fc7c7eb6a8727e79906c96397dd14594a17511e2ba018c3267935877b5c2c1750f28b2d5bf55faa6c2218c30e58f17542717ad6f8622dd0069a4886d20d3d657a80a869c8f6025399f914f23e5ccd3a999c271a50994c7db959c5c0b73334d15ba3754e9");

			var result = left ^ right;
			Assert.AreEqual(xor, result);
		}

		[TestMethod]
		public void SrpIntegetModPowCompatibleWithJsbn()
		{
			// jsbn results:
			//  5 ^ 3 % 1000 =  <SRPInteger 7d>  = 125
			// -5 ^ 3 % 1000 =  <SRPInteger f83> = 0x1000-0x7d
			// 5 ^ 33 % 1000 =  <SRPInteger 2bd> = 701
			//-5 ^ 33 % 1000 =  <SRPInteger d43> = 0x1000-0x2bd,
			// 5 ^ 90 % 1000 =  <SRPInteger dc1>
			//-5 ^ 90 % 1000 =  <SRPInteger dc1>

			var p5 = SrpInteger.FromHex("5");
			var n5 = SrpInteger.FromHex("-5");
			var x3 = SrpInteger.FromHex("3");
			var x33 = SrpInteger.FromHex("33");
			var x90 = SrpInteger.FromHex("90");
			var m = SrpInteger.FromHex("1000");

			var result = p5.ModPow(x3, m);
			Assert.AreEqual("007d", result.ToHex());

			result = p5.ModPow(x33, m);
			Assert.AreEqual("02bd", result.ToHex());

			result = p5.ModPow(x90, m);
			Assert.AreEqual("0dc1", result.ToHex());

			result = n5.ModPow(x3, m);
			Assert.AreEqual("0f83", result.ToHex());

			result = n5.ModPow(x33, m);
			Assert.AreEqual("0d43", result.ToHex());

			result = n5.ModPow(x90, m);
			Assert.AreEqual("0dc1", result.ToHex());
		}

		[TestMethod]
		public void SrpIntegerModPowRegressionTest()
		{
			var p = new SrpParameters();
			var g = p.G;
			var N = p.N;

			var a = SrpInteger.FromHex("64e1124e73967bb4806cf5e3f151c574d0012147255e10fca02e9b4bafc8f4ba");
			var A = g.ModPow(a, N);

			Assert.AreEqual("07be00c7e6aa8198eddc42cc2f251901f3bc05795fefd5f40f90f0a6bfe66743954ef18ece62d229095a704197be18c0d1ca3a280381c8a53b42173df36867c29c564e8c974cf4ff4718547d27bd9c08eb9a909fb984e8e23a109eaf4f57a337c9cbe1609e35b9fddbc9f847825b1c37167cb3f10b3b284a7370323818571e6369e91b4ac6f6eedcdbc1c7d8d57b2020d43be7fec3df14a120c76d27ebabc8d93cdc555362a4c7c08a1052e67647e9f3f879846389672e7a5d6e1ff93940d4196bef451e8d6a3b410a5062ac29cee3783e9a5aeac9724ad1375a2189c3b5a8dbf671dfad990132d2e5b73eb5a2e3d2034b6b908210f5fe61272b2cf4d1e3a4aa", A.ToHex());
		}

		[TestMethod]
		public void SrpIntegerEqualityChecks()
		{
			Assert.AreEqual(SrpInteger.FromHex("0"), SrpInteger.Zero);
			Assert.IsTrue(SrpInteger.FromHex("0") == SrpInteger.Zero);
			Assert.IsTrue(0 == SrpInteger.Zero);
			Assert.IsTrue(SrpInteger.Zero == 0);
			Assert.IsTrue(0L == SrpInteger.Zero);
			Assert.IsTrue(SrpInteger.Zero == 0L);

			Assert.AreNotEqual(SrpInteger.FromHex("1"), SrpInteger.Zero);
			Assert.IsTrue(SrpInteger.FromHex("1") != SrpInteger.Zero);
			Assert.IsTrue(1 != SrpInteger.Zero);
			Assert.IsTrue(SrpInteger.Zero != 1);
			Assert.IsTrue(1L != SrpInteger.Zero);
			Assert.IsTrue(SrpInteger.Zero != 1L);
		}

		[TestMethod]
		public void SrpIntegerImplicitStringConversion()
		{
			var si = SrpInteger.FromHex("02");
			string sistr = si;
			Assert.AreEqual(sistr, "02");

			si = SrpInteger.FromHex("000000000000");
			sistr = si;
			Assert.AreEqual(sistr, "000000000000");
		}

		[TestMethod]
		public void SrpIntegerToByteArrayConversion()
		{
			var si = SrpInteger.FromHex("02");
			var arr = new byte[] { 0x02 };
			Assert.IsTrue(Enumerable.SequenceEqual(arr, si.ToByteArray()));

			si = SrpInteger.FromHex("01F2C3A4B506");
			arr = new byte[] { 0x01, 0xF2, 0xC3, 0xA4, 0xB5, 0x06 };
			Assert.IsTrue(Enumerable.SequenceEqual(arr, si.ToByteArray()));

			si = SrpInteger.FromHex("ed3250071433e544b62b5dd0341564825a697357b5379f07aabca795a4e0a109");
			arr = new byte[] { 0xed, 0x32, 0x50, 0x07, 0x14, 0x33, 0xe5, 0x44, 0xb6, 0x2b, 0x5d, 0xd0, 0x34, 0x15, 0x64, 0x82, 0x5a, 0x69, 0x73, 0x57, 0xb5, 0x37, 0x9f, 0x07, 0xaa, 0xbc, 0xa7, 0x95, 0xa4, 0xe0, 0xa1, 0x09 };
			Assert.IsTrue(Enumerable.SequenceEqual(arr, si.ToByteArray()));

			si = new SrpInteger("B0", 10);
			arr = new byte[] { 0, 0, 0, 0, 0xb0 };
			Assert.IsTrue(Enumerable.SequenceEqual(arr, si.ToByteArray()));
		}

		[TestMethod]
		public void RandomIntegerReturnsAnIntegerOfTheGivenSize()
		{
			var rnd = SrpInteger.RandomInteger(1);
			Assert.AreEqual(2, rnd.ToHex().Length);
			Assert.AreNotEqual("00", rnd.ToHex());

			rnd = SrpInteger.RandomInteger(8);
			Assert.AreEqual(16, rnd.ToHex().Length);
			Assert.AreNotEqual("0000000000000000", rnd.ToHex());
		}
	}
}

<img src="https://raw.githubusercontent.com/secure-remote-password/srp.net/master/images/srp.net.png" width="128" height="128" />

# Secure Remote Password for .NET

[![Appveyor](https://img.shields.io/appveyor/ci/yallie/srp-net.svg)](https://ci.appveyor.com/project/yallie/srp-net)
[![Coverage](https://img.shields.io/codecov/c/github/secure-remote-password/srp.net.svg)](https://codecov.io/gh/secure-remote-password/srp.net)
[![Tests](https://img.shields.io/appveyor/tests/yallie/srp-net.svg)](https://ci.appveyor.com/project/yallie/srp-net/build/tests)
[![NuGet](https://img.shields.io/nuget/v/srp.svg)](https://www.nuget.org/packages/srp)

A modern [SRP-6a](http://srp.stanford.edu) implementation for .NET Standard 2.0 and .NET Framework 3.5+.  
Based on and is compatible with [secure-remote-password](https://npmjs.com/package/secure-remote-password) npm package by [Linus Unnebäck](https://github.com/LinusU/secure-remote-password).

## Installation

```sh
dotnet add package srp
```

## Usage

TODO

## Authentication at a glance


```c#
var client = new SrpClient();
var server = new SrpServer();

// sign up
var salt = client.GenerateSalt();
var privateKey = client.DerivePrivateKey(salt, username, password);
var verifier = client.DeriveVerifier(privateKey);

// authenticate
var clientEphemeral = client.GenerateEphemeral();
var serverEphemeral = server.GenerateEphemeral(verifier);
var clientSession = client.DeriveSession(clientEphemeral.Secret, serverEphemeral.Public, salt, username, privateKey);
var serverSession = server.DeriveSession(serverEphemeral.Secret, clientEphemeral.Public, salt, username, verifier, clientSession.Proof);
client.VerifySession(clientEphemeral.Public, clientSession, serverSession.Proof);

// both the client and the server have the same session key
Assert.AreEqual(clientSession.Key, serverSession.Key);
```

## References

* [Secure Remote Password protocol](http://srp.stanford.edu/), [documentation](http://srp.stanford.edu/doc.html), [wikipedia](http://en.wikipedia.org/wiki/Secure_remote_password_protocol)
* [RFC2945](http://www.ietf.org/rfc/rfc2945.txt) — The SRP Authentication and Key Exchange System
* [RFC5054](http://www.ietf.org/rfc/rfc5054.txt) — Using the Secure Remote Password (SRP) Protocol for TLS Authentication

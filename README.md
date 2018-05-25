# Secure Remote Password for .NET

[![Appveyor](https://img.shields.io/appveyor/ci/yallie/dotnet-srp.svg)](https://ci.appveyor.com/project/yallie/dotnet-srp)
[![Coverage](https://img.shields.io/codecov/c/github/secure-remote-password/dotnet-srp.svg)](https://codecov.io/gh/secure-remote-password/dotnet-srp)
[![Tests](https://img.shields.io/appveyor/tests/yallie/dotnet-srp.svg)](https://ci.appveyor.com/project/yallie/dotnet-srp/build/tests)

A modern [SRP-6a](http://srp.stanford.edu) implementation for .NET Standard 2.0 and .NET Framework 3.5+.  
Based on and is compatible with [secure-remote-password](https://npmjs.com/package/secure-remote-password) npm package by [Linus Unnebäck](https://github.com/LinusU/secure-remote-password).

## Installation

```sh
dotnet add package Zyan.SecureRemotePassword
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

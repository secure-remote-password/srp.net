<img src="https://raw.githubusercontent.com/secure-remote-password/srp.net/master/images/srp.net.png" width="128" height="128" />

# Secure Remote Password for .NET

[![Appveyor](https://img.shields.io/appveyor/ci/yallie/srp-net.svg)](https://ci.appveyor.com/project/yallie/srp-net)
[![Coverage](https://img.shields.io/codecov/c/github/secure-remote-password/srp.net.svg)](https://codecov.io/gh/secure-remote-password/srp.net)
[![Tests](https://img.shields.io/appveyor/tests/yallie/srp-net.svg)](https://ci.appveyor.com/project/yallie/srp-net/build/tests)
[![NuGet](https://img.shields.io/nuget/v/srp.svg)](https://www.nuget.org/packages/srp)

A modern [SRP-6a](http://srp.stanford.edu) implementation for .NET Standard 1.6+ and .NET Framework 3.5+.  
Based on and is compatible with [secure-remote-password](https://npmjs.com/package/secure-remote-password) npm package by [Linus Unnebäck](https://github.com/LinusU/secure-remote-password) (see [Compatibility](#user-content-compatibility-with-other-implementations)).

## Installation

```sh
dotnet add package srp
```

## Usage

### Signing up

To create an account, a client provides the following three values:

* Identifier (username or email)
* Salt
* Verifier

The salt and verifier are calculated as follows:

```c#
using SecureRemotePassword;

// a user enters his name and password
var userName = "alice";
var password = "password123";

var client = new SrpClient();
var salt = client.GenerateSalt();
var privateKey = client.DerivePrivateKey(salt, userName, password);
var verifier = client.DeriveVerifier(privateKey);

// send userName, salt and verifier to server
```

### Logging in

Authentication involves several steps:

#### 1. Client → Server: I, A

The client generates an ephemeral secret/public value pair and sends the 
public value and user name to server:

```c#
using SecureRemotePassword;

// a user enters his name
var userName = "alice";

var client = new SrpClient();
var clientEphemeral = client.GenerateEphemeral(verifier);

// send userName and clientEphemeral.Public to server
```

#### 2. Server → Client: s, B

The server retrieves `salt` and `verifier` from the database using the 
client-provided `userName`. Then it generates its own ephemeral secret/public
value pair:

```c#
using SecureRemotePassword;

// retrieved from the database
var salt = "beb25379...";
var verifier = "7e273de8...";

var server = new SrpServer();
var serverEphemeral = server.GenerateEphemeral();

// store serverEphemeral.Secret for later use
// send salt and serverEphemeral.Public to the client
```

#### 3. Client → Server: M1

The client derives the shared session key and a proof of it to provide to the server:

```c#
using SecureRemotePassword;

// a user enters his password
var password = "password123";

var client = new SrpClient();
var privateKey = client.DerivePrivateKey(salt, userName, password);
var clientSession = client.DeriveSession(clientEphemeral.Secret,
    serverPublicEphemeral, salt, userName, privateKey);

// send clientSession.Proof to the server
```

#### 4. Server → Client: M2

The server derives the shared session key and verifies that the client has the
same key using the provided proof value:

```c#
using SecureRemotePassword;

// get the serverEphemeral.Secret stored in step 2
var serverSecretEphemeral = "e487cb59...";

var server = new SrpServer();
var serverSession = server.DeriveSession(serverSecretEphemeral,
    clientPublicEphemeral, salt, userName, verifier, clientSessionProof);

// send serverSession.Proof to the client
```

#### 5. Client verifies M2

Finally, the client verifies that the server has derived the same session key
using the server's proof value:

```c#
using SecureRemotePassword;

var client = new SrpClient();
client.VerifySession(clientEphemeral.Public, clientSession, serverSessionProof);
```

## Authentication at a glance


```c#
using SecureRemotePassword;

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

## Custom protocol parameters

This SRP-6a implementation uses `sha256` hash function and 2048-bit group values
by default. Any class derived from `HashAlgorithm` can be used as `H`. 
Customizing the parameters is easy:

```c#
using System.Security.Cryptography;
using SecureRemotePassword;

// use predefined 4096-bit group with SHA512 hash function
var customParams = SrpParameters.Create4096<SHA512>();
```

`SrpParameters` has helper methods for all predefined groups from RFC5054:
`Create1024<SHA1>()`, etc.

It's also possible to specify custom values of `N` and `g`:

```c#
var N = "D4C7F8A2B32C11B8FBA9581EC4BA...";
var customParams = SrpParameters.Create<SHA1>(N, "02");
```

Custom SRP parameters are then passed to `SrpClient` and `SrpServer` constructors.
Make sure to use the same parameters on both sides:

```c#
var client = new SrpClient(customParams);
var server = new SrpServer(customParams);
```

## Compatibility with other implementations

`srp.net` is designed to be compatible with other implementations hosted
in [secure-remote-password](https://github.com/secure-remote-password/) organization.

At the time of writing, the [secure-remote-password](https://npmjs.com/package/secure-remote-password) npm package is incompatible with this implementation because it does not pad values according to RFC5054. 

* If you have control over both client and server, it is recommended to upgrade both to [this version](https://github.com/LinusU/secure-remote-password/pull/13), as outlined [here](https://github.com/secure-remote-password/srp.net/issues/7#issuecomment-561353784).
* If you are forced to maintain compatibility with an existing server, you can disable padding by  initializing the client with `new SrpClient(new SrpParameters { PaddedLength = 0 })`. This is _not recommended_, as the resulting behavior is incompatible with libraries that follow the standard.

Other compatible libraries are listed [here](https://github.com/secure-remote-password/implementations/blob/master/README.md).

## References

* [Secure Remote Password protocol](http://srp.stanford.edu/), [documentation](http://srp.stanford.edu/doc.html), [wikipedia](http://en.wikipedia.org/wiki/Secure_remote_password_protocol)
* [RFC2945](http://www.ietf.org/rfc/rfc2945.txt) — The SRP Authentication and Key Exchange System
* [RFC5054](http://www.ietf.org/rfc/rfc5054.txt) — Using the Secure Remote Password (SRP) Protocol for TLS Authentication

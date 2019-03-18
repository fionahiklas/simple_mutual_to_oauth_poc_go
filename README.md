## Overview

Simple proof of concept for mutual auth to OAuth2 microservice


## Quickstart

Run the application with the following command

```
bin/simple_mutual_to_oauth_poc 127.0.0.1:9443 crypto/server/pki/private/matooa-server.key crypto/certauth/pki/issue
d/matooa-server.crt crypto/certauth/pki/ca.crt
```

Test with Curl

```
curl -vvv -k \
--cacert crypto/certauth/pki/ca.crt \
--key crypto/client/pki/private/matooa-client.key \
--cert crypto/certauth/pki/issued/matooa-client.crt \
 https://localhost:9443/hb
```

## Setup

### Crypto

There are quite a few keys and certificates needed to test the app, these are
all stored under subdirectories of `crypto`.  For each we're using
[Easy-RSA](https://github.com/OpenVPN/easy-rsa.git) and this needs initialising

```
easyrsa init-pki
```

Use `password` for all passphrases to make life easier in terms of testing

#### Certification Authority

Create this with the following command

```
easyrsa build-ca
```

The CA has a CN of `matooa-ca`

#### Server Key and Certificate

Create the key and signing request

```
easyrsa gen-req matooa-server
```

Under the Certification Authority directory run the following commands to
import and sign the request

```
easyrsa import-req ../server/pki/reqs/matooa-server.req matooa-server
easyrsa sign-req server matooa-server
```

To allow the application to read the key (without needing a passphrase) remove
the password with the following command (under the server directory)

```
mv matooa-server.key matooa-server-enc.key
openssl rsa -in matooa-server-enc.key -out matooa-server.key
```


#### Client Key and Certificate

Create the key and signing request under the client directory

```
easyrsa gen-req matooa-client
```

Under the Certification Authority directory run the following commands to
import and sign the request

```
easyrsa import-req ../client/pki/reqs/matooa-client.req client-server
easyrsa sign-req client matooa-client
```

To allow the application to read the key (without needing a passphrase) remove
the password with the following command (under the server directory)

```
mv matooa-client.key matooa-client-enc.key
openssl rsa -in matooa-client-enc.key -out matooa-client.key
```


### Compiling and Running

#### Compiling

Set the `GOPATH` environment

```
export GOPATH=$PWD
```

It's expected that you will be in the directory where the git repo was cloned.

Compile (and grab dependencies) with the following

```
go get simple_mutual_to_oauth_poc
```


## References

### OAuth2

* [Server to server flows](https://developers.google.com/identity/protocols/OAuth2ServiceAccount)

### Go Mutual Auth

* [Example code](https://github.com/wolfeidau/golang-massl/blob/master/cmd/massl-https/server.go)


### Go OAuth2

* [Library and Example](https://github.com/golang/oauth2)
* [Example](https://tutorialedge.net/golang/go-oauth2-tutorial/)

# RSA

Simple RSA implementation with OAEP. This was made to further my own 
understanding and keep my skills practiced, and must not be used in 
production. There are much better maintained libraries for that.

All the ciphers and such are based on a heirarchy of interfaces, so that 
theoretically any code that used a cipher or hash could be changed to use 
another with minimal modification.

There's also:

* A basic (and half-completed) ASN.1 parser.

* A fully-functioning implementation of SHA1 and SHA 2 (with no unit test)

* An implementation of ECDH for curve25519 (using the KeyAgreement interface)


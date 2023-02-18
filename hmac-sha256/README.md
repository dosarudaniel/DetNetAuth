# HMAC-SHA256

We have used the Ilia Levin implementation of sha256 to create our own
HMAC-SHA256 algorithm used for computing the DetNetAuth header.

This is an implementation of the HMAC SHA-256 secure hash algorithm defined in
[FIPS 198-1](https://csrc.nist.gov/publications/detail/fips/180/4/final)

It is not a byte-oriented implementation. Still, it may complement
a portable byte-oriented C version of AES-256 at
[www.literatecode.com/aes256](http://www.literatecode.com/aes256)


## Compile

This implementation supports `clang` (recommended) and `GCC` C compilers.
Other compilers may also work with some minor code tweaking. Apologies for
not caring about the seamless support of the MSVC compiler any longer.
Check the legacy section below if you still need that.

Use `make` or `sh sha256.c -c -o sha256.o` to compile into an object file
that you may link with your project later.

Use `make test` or `sh sha256.c -DSHA256_SELF_TEST__` to compile an
executable binary that will perform a few known answer tests for SHA-256.


## BASIC TEST

HMAC("abc", "123") = 8f16771f9f8851b26f4d46fa17de93e2711c7e51337cb8a608af81e1c1b6ae

## PERFORMANCE TEST

`make performance_test` can be used to benchmark our HMAC implementation for different 
input sizes. 
# DetNetAuth

## HMAC-SHA256

We have used the Ilia Levin implementation of sha256 to create our own
HMAC-SHA256 algorithm used for computing the DetNetAuth header.

This repo contains under hmac-sha256 directory an implementation of the 
HMAC SHA-256 secure hash algorithm defined in [FIPS 198-1](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.198-1.pdf)

### Compile

This implementation supports `clang` (recommended).
Other compilers may also work with some minor code tweaking. 

`cd hmac-sha256`

Use `make` or `sh hmac-sha256.c -c -o hmac-sha256.o` to compile into an object file
that you may link with your project later.


### BASIC TEST

Use `make basic_test` or `sh hmac-sha256.c -DSHA256_SELF_TEST__` to compile an
executable binary that will perform a basic test for HMAC-256.

`HMAC("abc", "123") = 8f16771f9f8851b26f4d46fa17de93e2711c7e51337cb8a608af81e1c1b6ae`

### PERFORMANCE TEST

Use `make performance_test` or `sh hmac-sha256.c -DSHA256_PERF_TEST__` to compile an
executable binary that can be used to benchmark our HMAC implementation for different
input sizes (packet vs headers only)



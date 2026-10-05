# Pinned Noise implementation

`vendor/snow` is the source archive for `mcginty/snow` tag `v0.10.0`, fetched
from `https://github.com/mcginty/snow/archive/refs/tags/v0.10.0.tar.gz`.

Archive SHA-256: `77b5ee00eecb67122f53badca58e94febe22d316c4e6e193c6f2b5f13e52e206`.

The upstream package is dual licensed Apache-2.0 OR MIT. Its upstream
`LICENSE-APACHE` and `LICENSE-MIT` files are retained in the vendor tree.

This fork is limited to zeroization support needed by the Prodigy opaque C ABI.
It is intentionally built with only Snow's default resolver components required
for `Noise_NNpsk0_25519_ChaChaPoly_SHA256`: getrandom, curve25519-dalek,
ChaCha20-Poly1305, SHA-256, and `risky-raw-split`.

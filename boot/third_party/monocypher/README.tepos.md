# Monocypher (vendored)

Monocypher 4.0.3, unmodified, from https://monocypher.org/download/:

    monocypher-4.0.3.tar.gz
    sha512 40904ada5c7ee4f7741733e38b69a30a4b0561cbffba5ffe7c2dce16136d540251ec0d9056ff606510d3b5b708fb8a40db7e0870d4a0b2dc17ba2bfb880f8965

Files: `src/monocypher.{c,h}` and `src/optional/monocypher-ed25519.{c,h}`
(Ed25519 as in RFC 8032, with SHA-512), plus `LICENCE.md` (BSD-2-Clause or
CC0-1.0, our choice) and `AUTHORS.md`.

tepOS uses it for Ed25519 signatures and XChaCha20-Poly1305 sealing instead
of implementing curve arithmetic itself: it is small, freestanding (only
<stddef.h> and <stdint.h>), and audited. To update, replace these files from a
newer release, check its published hash, and record it here.

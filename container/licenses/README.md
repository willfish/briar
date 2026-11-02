# Runtime dependency notices

These unmodified texts accompany libraries statically linked into the container
executable. Review them with dependency updates; they do not change Briar's
AGPL-3.0-only license or its file-specific notices.

| File | Source |
|---|---|
| `musl-COPYRIGHT` | [musl 1.2.6](https://git.musl-libc.org/cgit/musl/plain/COPYRIGHT?h=v1.2.6) |
| `json-c-COPYING` | [json-c 0.18](https://github.com/json-c/json-c/blob/json-c-0.18-20240915/COPYING) |
| `OpenSSL-LICENSE.txt` | [OpenSSL 3.5.9](https://github.com/openssl/openssl/blob/openssl-3.5.9/LICENSE.txt) |
| `gcc-COPYING3`, `gcc-COPYING.RUNTIME` | [GCC 15.2.0 runtime exception and GPL](https://github.com/gcc-mirror/gcc/tree/releases/gcc-15.2.0) |
| `zlib-LICENSE` | [zlib 1.3.2](https://github.com/madler/zlib/blob/v1.3.2/LICENSE) |

The Dockerfile also copies PCRE2's installed `LICENCE.md` and the copyright texts
from its checksum-verified curl and libxml2 source archives into the image.
Briar's own `LICENSE`, `NOTICE` and `LICENSES` directory are included separately.

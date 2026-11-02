# SPDX-License-Identifier: AGPL-3.0-only
FROM alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a AS dependencies
RUN apk add --no-cache build-base pkgconf \
    pcre2-dev pcre2-static pcre2-doc json-c-dev \
    openssl-dev openssl-libs-static zlib-dev zlib-static
ARG BUILD_JOBS=4
# The executable has no CLI verification. Avoid curl's optional IDN, public
# suffix, HTTP/2 and extra compression dependencies, not Briar's detectors.
# Source checksum: Alpine aports main/curl, curl 8.23.0-r0.
RUN wget -q https://curl.se/download/curl-8.23.0.tar.xz \
    && echo '69cf0feafdc79fbad007cf2fc977b777ce6ccb05d01afd17b5a42f8bedbfcc342fc3a48193faa7f3eafe6800cd7d07948916e8733db1b9de60287ed06219b840  curl-8.23.0.tar.xz' | sha512sum -c - \
    && tar -xf curl-8.23.0.tar.xz && cd curl-8.23.0 \
    && CFLAGS='-Os -ffunction-sections -fdata-sections' ./configure \
        --disable-shared --enable-static --disable-docs --disable-curl \
        --with-openssl --with-zlib --without-libpsl --without-libidn2 \
        --without-brotli --without-zstd --without-nghttp2 --without-nghttp3 \
        --without-ngtcp2 --without-libssh2 --disable-ldap --disable-ldaps \
    && make -j"$BUILD_JOBS" && make install \
    && mkdir -p /out/licenses/dependencies \
    && cp COPYING /out/licenses/dependencies/curl-COPYING
# Briar uses libxml2's declared-encoding API, absent from Alpine's 2.13 package.
RUN wget -q https://download.gnome.org/sources/libxml2/2.15/libxml2-2.15.3.tar.xz \
    && echo '78262a6e7ac170d6528ebfe2efccdf220191a5af6a6cd61ea4a9a9a5042c7a07  libxml2-2.15.3.tar.xz' | sha256sum -c - \
    && tar -xf libxml2-2.15.3.tar.xz && cd libxml2-2.15.3 \
    && CFLAGS='-Os -ffunction-sections -fdata-sections' ./configure \
        --disable-shared --enable-static --without-python \
    && make -j"$BUILD_JOBS" && make install \
    && cp Copyright /out/licenses/dependencies/libxml2-Copyright \
    && cp /usr/share/doc/pcre2-*/LICENCE.md /out/licenses/dependencies/pcre2-LICENCE.md

FROM dependencies AS build
ARG BUILD_JOBS=4
WORKDIR /build
COPY Makefile ./
COPY include/ include/
COPY src/ src/
RUN make -j"$BUILD_JOBS" build/briar \
    CFLAGS='-Os -ffunction-sections -fdata-sections -flto' \
    LDFLAGS='-static -s -Wl,--gc-sections,-z,pack-relative-relocs' \
    PKG_CONFIG='pkg-config --static' \
    && cp build/briar /out/briar
COPY LICENSE NOTICE /out/licenses/
COPY LICENSES/ /out/licenses/third-party/
COPY container/licenses/ /out/licenses/dependencies/
# Decimal MB, including notices. Fail rather than silently grow past the budget.
RUN test "$(du -sb /out | cut -f1)" -lt 10000000

FROM scratch
LABEL org.opencontainers.image.source="https://github.com/willfish/briar" \
      org.opencontainers.image.licenses="AGPL-3.0-only"
COPY --from=build /out/ /
WORKDIR /src
USER 65532:65532
ENTRYPOINT ["/briar", "pre-commit"]
CMD ["--"]

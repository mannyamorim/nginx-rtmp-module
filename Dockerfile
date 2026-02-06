FROM nginx:1.28.2-alpine as builder
COPY . /modules/rtmp
ENV module=rtmp

RUN set -ex \
    && apk update \
    && apk add linux-headers openssl-dev pcre2-dev zlib-dev openssl abuild \
               musl-dev libxslt libxml2-utils make gcc unzip git xz g++ \
               coreutils \
    # allow abuild as a root user \
    && printf "#!/bin/sh\\nSETFATTR=true /usr/bin/abuild -F \"\$@\"\\n" > /usr/local/bin/abuild \
    && chmod +x /usr/local/bin/abuild \
    && git clone --depth 1 --branch ${NGINX_VERSION}-${PKG_RELEASE} https://github.com/nginx/pkg-oss/ \
    && cd pkg-oss \
    && mkdir /tmp/packages \
    && echo "Building $module from user-supplied sources" \
    && /pkg-oss/build_module.sh -v $NGINX_VERSION -f -y -o /tmp/packages -n $module /modules/$module

FROM nginx:1.28.2-alpine
COPY --from=builder /tmp/packages /tmp/packages
ENV module=rtmp
RUN set -ex \
    && apk add --no-cache --allow-untrusted /tmp/packages/nginx-module-${module}-${NGINX_VERSION}*.apk

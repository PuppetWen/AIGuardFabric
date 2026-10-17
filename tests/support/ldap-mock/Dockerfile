FROM rust:1.97-slim-bookworm
RUN sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources \
    && apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends slapd ldap-utils \
    && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /usr/local/bin/agf-ldap-mock
RUN chmod 755 /usr/local/bin/agf-ldap-mock
EXPOSE 636
ENTRYPOINT ["/usr/local/bin/agf-ldap-mock"]

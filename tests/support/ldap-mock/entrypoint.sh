#!/bin/sh
set -eu
test -n "${AGF_TEST_LDAP_ADMIN_PASSWORD:-}"
test -n "${AGF_TEST_LDAP_USER_PASSWORD:-}"
printf 'slapd slapd/no_configuration boolean false\nslapd slapd/domain string example.test\nslapd shared/organization string AGF Test\nslapd slapd/password1 password %s\nslapd slapd/password2 password %s\nslapd slapd/backend select MDB\nslapd slapd/purge_database boolean true\nslapd slapd/move_old_database boolean true\n' \
  "$AGF_TEST_LDAP_ADMIN_PASSWORD" "$AGF_TEST_LDAP_ADMIN_PASSWORD" | debconf-set-selections
DEBIAN_FRONTEND=noninteractive dpkg-reconfigure slapd
mkdir -p /etc/ldap/ssl
openssl req -x509 -newkey rsa:2048 -nodes -keyout /etc/ldap/ssl/ca.key \
  -out /etc/ldap/ssl/ca.crt -days 2 -subj '/CN=AGF LDAP Test CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -keyout /etc/ldap/ssl/server.key \
  -out /etc/ldap/ssl/server.csr -subj '/CN=localhost' >/dev/null 2>&1
cat >/etc/ldap/ssl/server.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF
openssl x509 -req -in /etc/ldap/ssl/server.csr -CA /etc/ldap/ssl/ca.crt \
  -CAkey /etc/ldap/ssl/ca.key -CAcreateserial -out /etc/ldap/ssl/server.crt \
  -days 2 -sha256 -extfile /etc/ldap/ssl/server.ext >/dev/null 2>&1
chown -R openldap:openldap /etc/ldap/ssl
chmod 600 /etc/ldap/ssl/ca.key /etc/ldap/ssl/server.key
slapd -h 'ldap:/// ldaps:/// ldapi:///' -d 0 &
server_pid=$!
trap 'kill "$server_pid" 2>/dev/null || true' EXIT INT TERM
attempt=0
until ldapwhoami -x -H ldap://127.0.0.1 -D 'cn=admin,dc=example,dc=test' \
  -w "$AGF_TEST_LDAP_ADMIN_PASSWORD" >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  test "$attempt" -lt 40 || exit 1
  sleep 1
done
cat >/tmp/tls.ldif <<'EOF'
dn: cn=config
changetype: modify
add: olcTLSCACertificateFile
olcTLSCACertificateFile: /etc/ldap/ssl/ca.crt
-
add: olcTLSCertificateFile
olcTLSCertificateFile: /etc/ldap/ssl/server.crt
-
add: olcTLSCertificateKeyFile
olcTLSCertificateKeyFile: /etc/ldap/ssl/server.key
EOF
ldapmodify -Y EXTERNAL -H ldapi:/// -f /tmp/tls.ldif
cat >/tmp/users.ldif <<EOF
dn: ou=People,dc=example,dc=test
objectClass: organizationalUnit
ou: People

dn: uid=alice,ou=People,dc=example,dc=test
objectClass: inetOrgPerson
uid: alice
cn: Alice Example
sn: Example
mail: alice@example.test
userPassword: ${AGF_TEST_LDAP_USER_PASSWORD}
EOF
ldapadd -x -H ldap://127.0.0.1 -D 'cn=admin,dc=example,dc=test' \
  -w "$AGF_TEST_LDAP_ADMIN_PASSWORD" -f /tmp/users.ldif
cp /etc/ldap/ssl/ca.crt /tmp/agf-test-ldap-ca.pem
echo 'AGF LDAP mock ready'
wait "$server_pid"

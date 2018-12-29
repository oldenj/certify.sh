# certify.sh
Small wrapper for https://github.com/diafygi/acme-tiny, supposed to be compact, robust and easy to use.

This script issues new Letsencrypt certificates with a single command.
It supports account creation, the Letsencrypt staging environment,
renewal of all existing certificates and subject alternative names (SAN) to cover multiple subdomains with a single certificate.

# Requirements
The script uses **curl** to fetch the Letsencrypt intermediary certificate.

There has to be a webserver ready to serve the challenge files.

The script also requires an OpenSSL configuration file to generate the certificate signing requests.

PKI_DIR/openssl.cnf
```
[ req ]
# Options for the `req` tool (`man req`).
default_bits        = 2048
distinguished_name  = req_distinguished_name
string_mask         = utf8only

# SHA-1 is deprecated, so use SHA-2 instead.
default_md          = sha256

# Extension to add when the -x509 option is used.
x509_extensions     = v3_ca

[ req_distinguished_name ]
# See <https://en.wikipedia.org/wiki/Certificate_signing_request>.
countryName                     =
stateOrProvinceName             =
localityName                    =
0.organizationName              =
organizationalUnitName          =
commonName                      =
emailAddress                    =

# Optionally, specify some defaults.
countryName_default             =
stateOrProvinceName_default     =
localityName_default            =
0.organizationName_default      =
organizationalUnitName_default  =
emailAddress_default            =

[ v3_ca ]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer:always
basicConstraints = critical, CA:true
```

# Usage
```
certify issue [-s/--staging] [-a/--acme-dir CA directory URL] [-p/--pki-dir PKI directory] [-d/--domains <SAN1>,<SAN2>,...] <domain>
```

```
certify renew [-s/--staging] [-a/--acme-dir CA directory URL] [-p/--pki-dir PKI directory]
```

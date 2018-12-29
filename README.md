# certify.sh
Wrapper for https://github.com/diafygi/acme-tiny, supposed to be compact, robust and easy to use.

This script issues new Letsencrypt certificates with a single command.
It supports account creation, the Letsencrypt staging environment,
renewal of all existing certificates and subject alternative names (SAN) to cover multiple subdomains with a single certificate.

# Usage
certify issue [-s/--staging] [-a/--acme-dir CA directory URL] [-p/--pki-dir PKI directory] [-d/--domains <SAN1>,<SAN2>,...] <domain>
certify renew [-s/--staging] [-a/--acme-dir CA directory URL] [-p/--pki-dir PKI directory]

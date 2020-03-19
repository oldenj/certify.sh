#!/bin/bash

# CLI options defaults
ISSUE=false
RENEW=false
STAGING=false
DOMAIN=""
ALT_DOMAINS=()
PKI_DIR="/var/lib/certify/"
ACME_DIR="/srv/http/acme-challenge/.well-known/acme-challenge/"

# Default Parameters
DIRECTORY="https://acme-v02.api.letsencrypt.org/directory"
DIRECTORY_STAGING="https://acme-staging-v02.api.letsencrypt.org/directory"
ACCOUNT_KEY="${PKI_DIR}/accounts/live.key"
ACCOUNT_KEY_STAGING="${PKI_DIR}/accounts/staging.key"
SSL_CONF="/var/lib/certify/openssl.cnf"
ACME_TINY="acme-tiny --quiet"

# Colors for logging
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NO_COLOR='\033[0m'

_exiterr() {
	echo -e "[${RED}ERR${NO_COLOR}] ${1}" >&2
	echo -e "${RED}Terminating${NO_COLOR}" >&2
	exit 1
}

_logerr() {
	echo -e "[${RED}ERR${NO_COLOR}] ${1}" >&2
}

_logwarn() {
	echo -e "[${YELLOW}WARN${NO_COLOR}] ${1}" >&2
}

_logok() {
	echo -e "[${GREEN}OK${NO_COLOR}] ${1}" >&1
}

_log() {
	echo -e "${1}" >&1
}

_usage() {
	echo -e "Usage: $0  [-s/--staging] [-a/--acme-dir Directory hosting challenge files] [-p/--pki-dir PKI directory] [-d/--domains <SAN1>,<SAN2>,...] <domain>"
}

function get_opts() {
	OPTIND=1
	OPTERR=0

	while getopts "sd:a:p:h" opt; do
		case "$opt" in
			s)
				STAGING=true
				;;
			d)
				tmp=$(echo "$OPTARG" | sed -r 's/[,]+/ /g')
				read -r -a ALT_DOMAINS <<< $tmp
				;;
			a)
				ACME_DIR=$OPTARG
				;;
			p)
				PKI_DIR=$OPTARG
				;;
			h)
				_usage
				;;
		esac
	done

	shift $((OPTIND-1))

	# handle non-option arguments
	if [[ $# -lt 1 ]]; then
		_usage
		exit 1
	fi

	while [[ $# -gt 0 ]]; do
		case "$1" in
			"issue"|"renew")
				MODE=$1
				if [ $MODE == "renew" ]; then
					shift
				fi
				shift
				;;
			*)
				DOMAIN=$1
				shift
				;;
		esac
	done
}

# Parameter 1: domain name
# Parameter 2: subject alt names
function gen_csr() {
	if [ -z $1 ]; then
		_logerr "Empty name (CN)!"
		return 1
	fi
	if $STAGING; then
		work_dir="${PKI_DIR}/staging/${1}"
		domain_key="${work_dir}/key.pem"
		csr="${PKI_DIR}/csr/${1}.csr.staging"
	else
		work_dir="${PKI_DIR}/live/${1}"
		domain_key="${work_dir}/key.pem"
		csr="${PKI_DIR}/csr/${1}.csr"
	fi

	# generate the SAN extension string
	cn=$1
	san="[SAN]\nsubjectAltName=DNS:${1}"
	shift
	for dom in "$@"; do
		san="${san},DNS:${dom}"
	done

	# generate domain private key if not existing
	if [ ! -f $domain_key ]; then
		mkdir -p $work_dir
		key_tmp="$(openssl genrsa 4096)"
		if [ $? -ne 0 ]; then
			err "Failed to generate private key for ${cn}! Purging ${work_dir}."
			rm -rf $work_dir
			return 1
		fi
		echo "$key_tmp" > $domain_key
		chmod 400 $domain_key
		_logok "Generated key for ${cn}."
	fi

	# generate csr
	req_tmp="$(openssl req -new -sha256 -key $domain_key -subj "/CN=${cn}" -reqexts SAN -config <(cat ${SSL_CONF} <(printf ${san})))"
	if [ $? -ne 0 ]; then
		_logerr "Failed to generate csr for ${cn}! Purging ${csr}."
		return 1
	fi
	mkdir -p $(dirname $csr)
	echo "$req_tmp" > $csr
	_logok "Generated csr for ${cn}."
}

# Parameters: Domains (CN) to be signed
function sign() {
	for dom in "$@"; do
		# STAGING
		if $STAGING; then
			work_dir="${PKI_DIR}/staging/${dom}"
			csr="${PKI_DIR}/csr/${dom}.csr.staging"
			cert="${work_dir}/cert.pem"

			mkdir -p $work_dir
			_log "Signing request (staging) for ${dom}".
			cert_data="$(${ACME_TINY} --directory-url "$DIRECTORY_STAGING" --account-key "$ACCOUNT_KEY_STAGING" --csr "$csr" --acme-dir "$ACME_DIR")"
			if [ $? -ne 0 ] || [ -z "${cert_data}" ]; then
				_logerr "ACME failed for ${dom}!"
				rm -f $csr
				continue
			fi
			echo "$cert_data" > $cert
			_logok "ACME completed (staging). Received signed certificate for ${dom}."
		# LIVE
		else
			work_dir="${PKI_DIR}/live/${dom}"
			csr="${PKI_DIR}/csr/${dom}.csr"
			cert="${work_dir}/cert.pem"
			chain="${work_dir}/chain.pem"
			fullchain="${work_dir}/fullchain.pem"

			mkdir -p $work_dir
			_log "Signing request for ${dom}".
			cert_data="$(${ACME_TINY} --account-key "$ACCOUNT_KEY" --csr "$csr" --acme-dir "$ACME_DIR")"
			if [ $? -ne 0 ] || [ -z "${cert_data}" ]; then
				_logerr "ACME failed for ${dom}!"
				if [ "$MODE" == "issue" ]; then
					_logwarn "Cleaning up CSR for ${dom}!"
					rm -f $csr
				fi
				continue
			fi
			echo "$cert_data" > $cert
			_logok "ACME completed. Received signed certificate for ${dom}."
		fi
	done
}

function check_environment() {
	if [ ! -f ${SSL_CONF} ]; then
		_logerr "No SSL config found at ${SSL_CONF}."
		return 1
	fi
	if ! $STAGING && [ ! -f ${ACCOUNT_KEY} ]; then
		_logwarn "No account key found at ${ACCOUNT_KEY}."
		mkdir -p $(dirname ${ACCOUNT_KEY})
		key_tmp="$(openssl genrsa 4096)"
		if [ $? -ne 0 ] || [ -z "${key_tmp}" ]; then
			_logerr "Failed to generate account key!"
			continue
		fi
		echo "$key_tmp" > ${ACCOUNT_KEY}
		_logok "Generated new account key."
	elif $STAGING && [ ! -f ${ACCOUNT_KEY_STAGING} ]; then
		_logwarn "No account key found at ${ACCOUNT_KEY_STAGING}."
		mkdir -p $(dirname ${ACCOUNT_KEY_STAGING})
		key_tmp="$(openssl genrsa 4096)"
		if [ $? -ne 0 ] || [ -z "${key_tmp}" ]; then
			_logerr "Failed to generate account key (staging)!"
			continue
		fi
		echo "$key_tmp" > ${ACCOUNT_KEY_STAGING}
		_logok "Generated new account key (staging)."
	fi
}

get_opts $@
check_environment || _exiterr "Missing environment files."
if [ "$MODE" == "issue" ]; then
	gen_csr ${DOMAIN} ${ALT_DOMAINS[@]} || _exiterr "Failed to generate csr."
	sign ${DOMAIN[0]} true || _exiterr "Failed to obtain signed certificate."
elif [ "$MODE" == "renew" ]; then
	csr_l=()
	for csr in ${PKI_DIR}/csr/*.csr; do
		if [ ! -e $csr ]; then
			continue
		fi

		name="$(basename "$csr")"
		name="${name%.csr}"
		csr_l=(${csr_l[@]} $name)
	done
	if [ -z ${csr_l[0]} ]; then
		_logwarn "No signing requests found for renewal."
		exit 0
	fi
	sign ${csr_l[@]} || _logwarn "Failed to renew some or all certificates."
else
	_logwarn "No mode specified."
	_usage
fi
exit 0

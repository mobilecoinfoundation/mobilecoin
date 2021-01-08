#!/bin/bash

set -x
set -u
set -e

BASEDIR=$(dirname $0)

function init_ca_dir() {
	dirname="$1"
	mkdir -p "${dirname}"
	mkdir -p "${dirname}/certs"
	mkdir -p "${dirname}/newcerts"
	mkdir -p "${dirname}/private"
	mkdir -p "${dirname}/crl"

	chmod 700 "${dirname}/private"
	touch "${dirname}/index.txt"
	echo '1000' > "${dirname}/serial"
	echo '1000' > "${dirname}/crlnumber"
}

init_ca_dir "${BASEDIR}/root"


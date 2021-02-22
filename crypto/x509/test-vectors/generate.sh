#!/bin/bash

set -x
set -e
set -u

OPENSSL="${OPENSSL_BIN:-$(which openssl)}"

# Some variables we'll use later
FIFTYYEARS="$(expr 365 \* 50 + 50 / 4)"
BASEDIR="$(dirname $0)"

OPENSSL_CNF="${BASEDIR}/openssl.cnf"

OUTPUT_BASE_DIR="${OUT_DIR}/openssl"
OK_ROOT_DIR="${OUTPUT_BASE_DIR}/ok_root"
OK_PENULTIMATE_DIR="${OUTPUT_BASE_DIR}/ok_penultimate"
OK_INTERMEDIATE1_DIR="${OUTPUT_BASE_DIR}/ok_intermediate1"
OK_INTERMEDIATE2_DIR="${OUTPUT_BASE_DIR}/ok_intermediate2"
OK_INTERMEDIATE3_DIR="${OUTPUT_BASE_DIR}/ok_intermediate3"
OK_INTERMEDIATE4_DIR="${OUTPUT_BASE_DIR}/ok_intermediate4"
OK_INTERMEDIATE5_DIR="${OUTPUT_BASE_DIR}/ok_intermediate5"
OK_INTERMEDIATE6_DIR="${OUTPUT_BASE_DIR}/ok_intermediate6"
OK_INTERMEDIATE7_DIR="${OUTPUT_BASE_DIR}/ok_intermediate7"
OK_PENULTIMATE8_DIR="${OUTPUT_BASE_DIR}/ok_penultimate8"


# Initialize a directory to contain a certificate authority
function init_ca_dir() {
	DIRNAME="$1"
	mkdir -p "${DIRNAME}"
	mkdir -p "${DIRNAME}/certs"
	mkdir -p "${DIRNAME}/crl"
	mkdir -p "${DIRNAME}/newcerts"
	mkdir -p "${DIRNAME}/private"
	mkdir -p "${DIRNAME}/req"

	chmod 700 "${DIRNAME}/private"
	touch "${DIRNAME}/index.txt"
	echo '1000' > "${DIRNAME}/serial"
	echo '1000' > "${DIRNAME}/crlnumber"
}


# Create an intermediate CA
function make_intermediate_ca() {
	ID=$1
	PARENT="ok_root"
	if [[ 1 -lt $ID ]]; then
		PARENT="ok_intermediate$(expr $ID - 1)"
	fi

	DIR="OK_INTERMEDIATE${ID}_DIR"

	"${OPENSSL}" genpkey \
		-algorithm rsa \
		-pkeyopt rsa_keygen_bits:2048 \
		-outform PEM \
		-out "${!DIR}/private/ca.key"

	"${OPENSSL}" req \
		-config "$OPENSSL_CNF" \
		-subj "/C=US/ST=California/L=San Francisco/O=TESTING ONLY/OU=TESTING/CN=Test Intermediate Authority ${ID}" \
		-key "${!DIR}/private/ca.key" \
		-new \
		-sha256 \
		-extensions v3_intermediate_ca \
		-out "${!DIR}/req/ca.csr"

	"${OPENSSL}" ca \
		-batch \
		-config "$OPENSSL_CNF" \
		-name "${PARENT}" \
		-extensions v3_intermediate_ca \
		-days $FIFTYYEARS \
		-md sha256 \
		-in "${!DIR}/req/ca.csr" \
		-notext \
		-out "${!DIR}/certs/ca.crt"
}

# Clean any existing directories
rm -rf "${OUTPUT_BASE_DIR}"


# Setup the directories
init_ca_dir "${OK_ROOT_DIR}"
init_ca_dir "${OK_PENULTIMATE_DIR}"
init_ca_dir "${OK_INTERMEDIATE1_DIR}"
init_ca_dir "${OK_INTERMEDIATE2_DIR}"
init_ca_dir "${OK_INTERMEDIATE3_DIR}"
init_ca_dir "${OK_INTERMEDIATE4_DIR}"
init_ca_dir "${OK_INTERMEDIATE5_DIR}"
init_ca_dir "${OK_INTERMEDIATE6_DIR}"
init_ca_dir "${OK_INTERMEDIATE7_DIR}"
init_ca_dir "${OK_PENULTIMATE8_DIR}"

# Generate a random password we will use later (not currently used)
# PASSWD_FILE="${OUTPUT_BASE_DIR}/password.txt"
# cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1 > "$PASSWD_FILE"


# Root CA
"${OPENSSL}" genpkey \
	-algorithm rsa \
	-pkeyopt rsa_keygen_bits:4096 \
	-outform PEM \
	-out "${OK_ROOT_DIR}/private/ca.key"

"${OPENSSL}" req \
	-config "$OPENSSL_CNF" \
	-subj "/C=US/ST=California/L=San Francisco/O=TESTING ONLY/OU=TESTING/CN=Test Root Authority" \
	-key "${OK_ROOT_DIR}/private/ca.key" \
	-new \
	-x509 \
	-days $FIFTYYEARS \
	-sha256 \
	-extensions v3_ca \
	-out "${OK_ROOT_DIR}/certs/ca.crt"


# Penultimate Authority
"${OPENSSL}" genpkey \
	-algorithm rsa \
	-pkeyopt rsa_keygen_bits:2048 \
	-outform PEM \
	-out "${OK_PENULTIMATE_DIR}/private/ca.key"

"${OPENSSL}" req \
	-config "$OPENSSL_CNF" \
	-subj "/C=US/ST=California/L=San Francisco/O=TESTING ONLY/OU=TESTING/CN=Test Penultimate Authority 1" \
	-key "${OK_PENULTIMATE_DIR}/private/ca.key" \
	-new \
	-sha256 \
	-extensions v3_penultimate_ca \
	-out "${OK_PENULTIMATE_DIR}/req/ca.csr"

"${OPENSSL}" ca \
	-batch \
	-config "$OPENSSL_CNF" \
	-name ok_root \
	-extensions v3_penultimate_ca \
	-days $FIFTYYEARS \
	-md sha256 \
	-in "${OK_PENULTIMATE_DIR}/req/ca.csr" \
	-notext \
	-out "${OK_PENULTIMATE_DIR}/certs/ca.crt"


# Leaf Certificate
"${OPENSSL}" genpkey \
	-algorithm ed25519 \
	-outform PEM \
	-out "${OK_PENULTIMATE_DIR}/private/leaf.key"

"${OPENSSL}" req \
	-config "$OPENSSL_CNF" \
	-subj "/C=US/ST=California/L=San Francisco/O=TESTING ONLY/OU=TESTING/CN=Test Leaf Certificate 1" \
	-key "${OK_PENULTIMATE_DIR}/private/leaf.key" \
	-new \
	-sha256 \
	-extensions leaf_cert \
	-out "${OK_PENULTIMATE_DIR}/req/leaf.csr"

"${OPENSSL}" ca \
	-batch \
	-config "$OPENSSL_CNF" \
	-name ok_penultimate \
	-extensions leaf_cert \
	-days $FIFTYYEARS \
	-md sha256 \
	-in "${OK_PENULTIMATE_DIR}/req/leaf.csr" \
	-notext \
	-out "${OK_PENULTIMATE_DIR}/certs/leaf.crt"


# ok_rsa_head()
cp "${OK_ROOT_DIR}/certs/ca.crt" "${OUTPUT_BASE_DIR}/ok_rsa_head.pem"


# ok_rsa_chain_25519_leaf()
cat "${OK_PENULTIMATE_DIR}/certs/leaf.crt" > "${OUTPUT_BASE_DIR}/ok_rsa_chain_25519_leaf.pem"
cat "${OK_PENULTIMATE_DIR}/certs/ca.crt" >> "${OUTPUT_BASE_DIR}/ok_rsa_chain_25519_leaf.pem"
cat "${OK_ROOT_DIR}/certs/ca.crt" >> "${OUTPUT_BASE_DIR}/ok_rsa_chain_25519_leaf.pem"

cat "${OK_PENULTIMATE_DIR}/private/leaf.key" > "${OUTPUT_BASE_DIR}/ok_rsa_chain_25519_leaf.key"


# ok_rsa_out_of_order()
cat "${OK_ROOT_DIR}/certs/ca.crt" > "${OUTPUT_BASE_DIR}/ok_rsa_out_of_order.pem"
cat "${OK_PENULTIMATE_DIR}/certs/ca.crt" >> "${OUTPUT_BASE_DIR}/ok_rsa_out_of_order.pem"
cat "${OK_PENULTIMATE_DIR}/certs/leaf.crt" >> "${OUTPUT_BASE_DIR}/ok_rsa_out_of_order.pem"

cat "${OK_PENULTIMATE_DIR}/private/leaf.key" > "${OUTPUT_BASE_DIR}/ok_rsa_out_of_order.key"


# Generate intermediate CAs
make_intermediate_ca 1
make_intermediate_ca 2
make_intermediate_ca 3
make_intermediate_ca 4
make_intermediate_ca 5
make_intermediate_ca 6
make_intermediate_ca 7


# Depth-10 Penultimate Authority
"${OPENSSL}" genpkey \
	-algorithm rsa \
	-pkeyopt rsa_keygen_bits:2048 \
	-outform PEM \
	-out "${OK_PENULTIMATE8_DIR}/private/ca.key"

"${OPENSSL}" req \
	-config "$OPENSSL_CNF" \
	-subj "/C=US/ST=California/L=San Francisco/O=TESTING ONLY/OU=TESTING/CN=Test Penultimate Authority 8" \
	-key "${OK_PENULTIMATE8_DIR}/private/ca.key" \
	-new \
	-sha256 \
	-extensions v3_penultimate_ca \
	-out "${OK_PENULTIMATE8_DIR}/req/ca.csr"

"${OPENSSL}" ca \
	-batch \
	-config "$OPENSSL_CNF" \
	-name ok_intermediate7 \
	-extensions v3_penultimate_ca \
	-days $FIFTYYEARS \
	-md sha256 \
	-in "${OK_PENULTIMATE8_DIR}/req/ca.csr" \
	-notext \
	-out "${OK_PENULTIMATE8_DIR}/certs/ca.crt"


# Depth 10 Leaf Certificate
"${OPENSSL}" genpkey \
	-algorithm ed25519 \
	-outform PEM \
	-out "${OK_PENULTIMATE8_DIR}/private/leaf.key"

"${OPENSSL}" req \
	-config "$OPENSSL_CNF" \
	-subj "/C=US/ST=California/L=San Francisco/O=TESTING ONLY/OU=TESTING/CN=Test Leaf Certificate 9" \
	-key "${OK_PENULTIMATE8_DIR}/private/leaf.key" \
	-new \
	-sha256 \
	-extensions leaf_cert \
	-out "${OK_PENULTIMATE8_DIR}/req/leaf.csr"

"${OPENSSL}" ca \
	-batch \
	-config "$OPENSSL_CNF" \
	-name ok_penultimate8 \
	-extensions leaf_cert \
	-days $FIFTYYEARS \
	-md sha256 \
	-in "${OK_PENULTIMATE8_DIR}/req/leaf.csr" \
	-notext \
	-out "${OK_PENULTIMATE8_DIR}/certs/leaf.crt"


# ok_rsa_chain_depth_10()
cat "${OK_PENULTIMATE8_DIR}/certs/leaf.crt" > "${OUTPUT_BASE_DIR}/ok_rsa_chain_depth_10.pem"
cat "${OK_PENULTIMATE8_DIR}/certs/ca.crt" >> "${OUTPUT_BASE_DIR}/ok_rsa_chain_depth_10.pem"
cat "${OK_INTERMEDIATE7_DIR}/certs/ca.crt" >> "${OUTPUT_BASE_DIR}/ok_rsa_chain_depth_10.pem"
cat "${OK_INTERMEDIATE6_DIR}/certs/ca.crt" >> "${OUTPUT_BASE_DIR}/ok_rsa_chain_depth_10.pem"
cat "${OK_INTERMEDIATE5_DIR}/certs/ca.crt" >> "${OUTPUT_BASE_DIR}/ok_rsa_chain_depth_10.pem"
cat "${OK_INTERMEDIATE4_DIR}/certs/ca.crt" >> "${OUTPUT_BASE_DIR}/ok_rsa_chain_depth_10.pem"
cat "${OK_INTERMEDIATE3_DIR}/certs/ca.crt" >> "${OUTPUT_BASE_DIR}/ok_rsa_chain_depth_10.pem"
cat "${OK_INTERMEDIATE2_DIR}/certs/ca.crt" >> "${OUTPUT_BASE_DIR}/ok_rsa_chain_depth_10.pem"
cat "${OK_INTERMEDIATE1_DIR}/certs/ca.crt" >> "${OUTPUT_BASE_DIR}/ok_rsa_chain_depth_10.pem"
cat "${OK_ROOT_DIR}/certs/ca.crt" >> "${OUTPUT_BASE_DIR}/ok_rsa_chain_depth_10.pem"

cat "${OK_PENULTIMATE8_DIR}/private/leaf.key" > "${OUTPUT_BASE_DIR}/ok_rsa_chain_depth_10.key"


# fail_missing_head()
cat "${OK_PENULTIMATE_DIR}/certs/leaf.crt" > "${OUTPUT_BASE_DIR}/fail_missing_head.pem"
cat "${OK_PENULTIMATE_DIR}/certs/ca.crt" >> "${OUTPUT_BASE_DIR}/fail_missing_head.pem"

cat "${OK_PENULTIMATE_DIR}/private/leaf.key" > "${OUTPUT_BASE_DIR}/fail_missing_head.key"


# fail_missing_link()
cat "${OK_PENULTIMATE_DIR}/certs/leaf.crt" > "${OUTPUT_BASE_DIR}/fail_missing_link.pem"
cat "${OK_ROOT_DIR}/certs/ca.crt" >> "${OUTPUT_BASE_DIR}/fail_missing_link.pem"

cat "${OK_PENULTIMATE_DIR}/private/leaf.key" > "${OUTPUT_BASE_DIR}/fail_missing_link.key"


# Expired Leaf (valid Jan 1, 2021 @ 00:00:00 - Jan 1, 2021 @ 00:00:01)
"${OPENSSL}" genpkey \
	-algorithm ed25519 \
	-outform PEM \
	-out "${OK_PENULTIMATE_DIR}/private/expired.key"

"${OPENSSL}" req \
	-config "$OPENSSL_CNF" \
	-subj "/C=US/ST=California/L=San Francisco/O=TESTING ONLY/OU=TESTING/CN=Test Expired Leaf Certificate" \
	-key "${OK_PENULTIMATE_DIR}/private/expired.key" \
	-new \
	-sha256 \
	-extensions leaf_cert \
	-out "${OK_PENULTIMATE_DIR}/req/expired.csr"

"${OPENSSL}" ca \
	-batch \
	-config "$OPENSSL_CNF" \
	-name ok_penultimate \
	-extensions leaf_cert \
	-startdate 20010101000000Z \
	-enddate 20100101000001Z \
	-md sha256 \
	-in "${OK_PENULTIMATE_DIR}/req/expired.csr" \
	-notext \
	-out "${OK_PENULTIMATE_DIR}/certs/expired.crt"


# fail_leaf_expired()
cat "${OK_PENULTIMATE_DIR}/certs/expired.crt" > "${OUTPUT_BASE_DIR}/fail_leaf_expired.pem"
cat "${OK_PENULTIMATE_DIR}/certs/ca.crt" >> "${OUTPUT_BASE_DIR}/fail_leaf_expired.pem"
cat "${OK_ROOT_DIR}/certs/ca.crt" >> "${OUTPUT_BASE_DIR}/fail_leaf_expired.pem"

cat "${OK_PENULTIMATE_DIR}/private/leaf.key" > "${OUTPUT_BASE_DIR}/fail_leaf_expired.key"


# Leaf Too Soon (valid Jan 1, 2070 @ 00:00:00 - Jan 1, 2070 @ 00:00:01)
"${OPENSSL}" genpkey \
	-algorithm ed25519 \
	-outform PEM \
	-out "${OK_PENULTIMATE_DIR}/private/too_soon.key"

"${OPENSSL}" req \
	-config "$OPENSSL_CNF" \
	-subj "/C=US/ST=California/L=San Francisco/O=TESTING ONLY/OU=TESTING/CN=Test Too Soon Leaf Certificate" \
	-key "${OK_PENULTIMATE_DIR}/private/too_soon.key" \
	-new \
	-sha256 \
	-extensions leaf_cert \
	-out "${OK_PENULTIMATE_DIR}/req/too_soon.csr"

"${OPENSSL}" ca \
	-batch \
	-config "$OPENSSL_CNF" \
	-name ok_penultimate \
	-extensions leaf_cert \
	-startdate 20590101000000Z \
	-enddate 20770101000001Z \
	-md sha256 \
	-in "${OK_PENULTIMATE_DIR}/req/too_soon.csr" \
	-notext \
	-out "${OK_PENULTIMATE_DIR}/certs/too_soon.crt"


# fail_leaf_too_soon()
cat "${OK_PENULTIMATE_DIR}/certs/too_soon.crt" > "${OUTPUT_BASE_DIR}/fail_leaf_too_soon.pem"
cat "${OK_PENULTIMATE_DIR}/certs/ca.crt" >> "${OUTPUT_BASE_DIR}/fail_leaf_too_soon.pem"
cat "${OK_ROOT_DIR}/certs/ca.crt" >> "${OUTPUT_BASE_DIR}/fail_leaf_too_soon.pem"

cat "${OK_PENULTIMATE_DIR}/private/too_soon.key" > "${OUTPUT_BASE_DIR}/fail_leaf_too_soon.key"


# ok_rsa_tree()
cat "${OK_PENULTIMATE_DIR}/certs/leaf.crt" > "${OUTPUT_BASE_DIR}/ok_rsa_tree.pem"
cat "${OK_INTERMEDIATE1_DIR}/certs/ca.crt" >> "${OUTPUT_BASE_DIR}/ok_rsa_tree.pem"
cat "${OK_INTERMEDIATE2_DIR}/certs/ca.crt" >> "${OUTPUT_BASE_DIR}/ok_rsa_tree.pem"
cat "${OK_PENULTIMATE_DIR}/certs/ca.crt" >> "${OUTPUT_BASE_DIR}/ok_rsa_tree.pem"
cat "${OK_ROOT_DIR}/certs/ca.crt" >> "${OUTPUT_BASE_DIR}/ok_rsa_tree.pem"

cat "${OK_PENULTIMATE_DIR}/private/leaf.key" > "${OUTPUT_BASE_DIR}/ok_rsa_tree.key"

# ok_self_signed_1()
"${OPENSSL}" req \
    -x509 \
    -newkey rsa:4096 \
    -keyout "${OUTPUT_BASE_DIR}/ok_self_signed_1.key" \
    -out "${OUTPUT_BASE_DIR}/ok_self_signed_1.pem" \
    -days 3650 \
    -subj "/C=US/ST=Neverland/L=California/O=Company Name/OU=Org/CN=www.server1.com" \
    -nodes

# ok_self_signed_2()
"${OPENSSL}" req \
    -x509 \
    -newkey rsa:4096 \
    -keyout "${OUTPUT_BASE_DIR}/ok_self_signed_2.key" \
    -out "${OUTPUT_BASE_DIR}/ok_self_signed_2.pem" \
    -days 3650 \
    -subj "/C=US/ST=Neverland/L=California/O=Company Name/OU=Org/CN=www.server2.com" \
    -nodes

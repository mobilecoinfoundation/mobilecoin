#!/bin/bash
# Copyright (c) 2018-2022 The MobileCoin Foundation
#


pri_pem=$(openssl genpkey -algorithm ED25519)
pri_der=$(echo -n "${pri_pem}" | openssl pkey -outform DER | openssl base64)
pub=$(echo -n "${pri_pem}" | openssl pkey -pubout | grep -v "^-----" | sed 's/+/-/g; s/\//_/g')

echo "private: ${pri_der}"
echo "public: ${pub}"

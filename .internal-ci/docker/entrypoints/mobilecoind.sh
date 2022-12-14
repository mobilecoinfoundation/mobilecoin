#!/bin/bash

set -eo pipefail

if [ -n "$INITIAL_KEYS_SEED" ]
then
	generate_origin_data.sh
fi

exec "$@"

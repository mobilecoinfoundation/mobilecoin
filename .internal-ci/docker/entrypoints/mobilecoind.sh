#!/bin/bash
# Copyright (c) 2018-2022 The MobileCoin Foundation
#
# Entrypoint script to set up testing environment in bootstrap(toolbox) container.

if [ -n "$INITIAL_KEYS_SEED" ]
then
	generate_origin_data.sh
fi

exec "$@"

#!/bin/bash
# Copyright (c) 2018-2022 The MobileCoin Foundation
#

export TMPDIR=".tmp"

error_exit()
{
  msg="${1}"

  echo "${msg}" 1>&2
  exit 1
}

is_set()
{
  var_name="${1}"

  if [ -z "${!var_name}" ]; then
    error_exit "${var_name} is not set."
  fi
}

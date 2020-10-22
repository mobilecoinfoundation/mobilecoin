#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2018-2020 MobileCoin Inc.

# Python wrappers for fetching IAS reports from the gRPC service `Fog Report Service`
# This is intended as a diagnostic.
# It DOES NOT do IAS validation, and that will be difficult in python.
# So it is dubious to use this in connection to creating new transactions.

import grpc

from .report_pb2 import *
from .report_pb2_grpc import *

# Fetch all available reports from the report server
#
# Arguments:
# * url - the url of the fog report server
# * ssl - bool indicating whether or not to use ssl when connecting
#
# Returns:
# * The python representation of the ReportResponse from the report server
def fetch_fog_reports(url, ssl):
    if ssl:
        credentials = grpc.ssl_channel_credentials()
        channel = grpc.secure_channel(daemon, credentials)
    else:
        channel = grpc.insecure_channel(daemon)
    stub = ReportAPIStub(channel)

    request = ReportRequest()
    return stub.GetReports(request)

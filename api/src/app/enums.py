#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
* SPDX-License-Identifier: MIT-0
*
* Permission is hereby granted, free of charge, to any person obtaining a copy of this
* software and associated documentation files (the "Software"), to deal in the Software
* without restriction, including without limitation the rights to use, copy, modify,
* merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
* permit persons to whom the Software is furnished to do so.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
* INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
* PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
* HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
* OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
* SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""

from enum import IntEnum


class EncodingVersion(IntEnum):
    # Written on every new vault record as `_v` (`ATTR_VERSION`). The
    # value is no longer load-bearing on read — the API discriminates
    # between legacy hex strings and binary attributes by the
    # DynamoDB type — but it is preserved as a forward-looking marker
    # in case a future on-disk format ever needs a discriminator.
    # `HEX = 1` (legacy `encap_hex#ct_hex` strings) is intentionally
    # absent: existing v=1 records still decode via
    # `utils.decode_v1_field`, but no new code paths construct one.
    BINARY = 2  # encap || ciphertext stored as a DynamoDB Binary attribute

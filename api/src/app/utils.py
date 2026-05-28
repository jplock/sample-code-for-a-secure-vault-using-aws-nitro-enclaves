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

import datetime
import json
import time
from typing import Any, Union
import uuid

from aws_lambda_powertools.event_handler import Response, content_types
from aws_lambda_powertools.shared.json_encoder import Encoder
from boto3.dynamodb.types import Binary
from pksuid import PKSUID

from app import constants

__all__ = [
    "json_dumps",
    "generate_id",
    "error_response",
    "now_micros",
    "build_key",
    "hpke_encap_key_size",
    "decode_v1_field",
    "decode_v2_field",
]

# Per-KEM encapsulated-key sizes (RFC 9180 §7.1, "Nenc"). The 10-byte
# HPKE suite identifier has the layout `"HPKE" + uint16 KEM_ID + uint16
# KDF_ID + uint16 AEAD_ID` (big-endian), so bytes 4-5 carry the KEM ID
# we look up here.
_KEM_ENCAP_SIZES = {
    0x0010: 65,   # DHKEM(P-256, HKDF-SHA256)
    0x0011: 97,   # DHKEM(P-384, HKDF-SHA384)
    0x0012: 133,  # DHKEM(P-521, HKDF-SHA512)
}


class CustomEncoder(Encoder):
    """
    JSONEncoder subclass that knows how to encode date/time, decimal types, and
    UUIDs.
    """

    def default(self, obj):
        # See "Date Time String Format" in the ECMA-262 specification.
        if isinstance(obj, datetime.datetime):
            return obj.replace(microsecond=0).isoformat().replace("+00:00", "Z")
        elif isinstance(obj, datetime.date):
            return obj.isoformat()
        elif isinstance(obj, uuid.UUID):
            return str(obj)
        else:
            return super().default(obj)


def json_dumps(obj: Any) -> str:
    """
    Compact JSON encoder
    """
    return json.dumps(obj, indent=None, separators=(",", ":"), sort_keys=True, cls=CustomEncoder)


def generate_id(prefix: str) -> str:
    """
    Return a unique ID
    """

    id = PKSUID(prefix)
    return str(id)


def error_response(status_code: int, message: str) -> Response:
    """
    Return an error response
    """

    data = {"statusCode": status_code, "message": message}

    return Response(
        status_code=status_code,
        content_type=content_types.APPLICATION_JSON,
        body=json_dumps(data),
    )


def now_micros() -> int:
    """
    Return the current time in microseconds
    """
    return time.time_ns() // 1000


def build_key(*args: str) -> str:
    """
    Build a key from a list of arguments
    """
    return constants.KEY_SEPARATOR.join(args)


def hpke_encap_key_size(suite_id: bytes) -> int:
    """Return the encapsulated-key length for the HPKE suite encoded in
    `suite_id` (10 raw bytes per RFC 9180). Raises ValueError for an
    unknown KEM ID — silently misreading the wire would corrupt the
    encap/ciphertext split for that record."""
    if len(suite_id) != 10:
        raise ValueError(f"suite_id must be 10 bytes, got {len(suite_id)}")
    kem_id = int.from_bytes(suite_id[4:6], "big")
    size = _KEM_ENCAP_SIZES.get(kem_id)
    if size is None:
        raise ValueError(f"unsupported HPKE KEM ID: 0x{kem_id:04x}")
    return size


def decode_v1_field(value: str) -> tuple[bytes, bytes]:
    """Split a legacy `_v == 1` (hex) per-field value `encap_hex#ct_hex`
    into raw `(encapped_key, ciphertext)` bytes."""
    encap_hex, sep, ct_hex = value.partition("#")
    if not sep:
        raise ValueError("v1 field is missing the '#' separator")
    return bytes.fromhex(encap_hex), bytes.fromhex(ct_hex)


def decode_v2_field(value: Union[bytes, Binary], encap_size: int) -> tuple[bytes, bytes]:
    """Split a `_v == 2` (binary) per-field value `encap || ciphertext`
    into raw `(encapped_key, ciphertext)` bytes, using `encap_size`
    derived from the record's HPKE suite via `hpke_encap_key_size`."""
    data = bytes(value)
    if len(data) < encap_size:
        raise ValueError(
            f"v2 field too short: {len(data)} bytes, need at least {encap_size}"
        )
    return data[:encap_size], data[encap_size:]

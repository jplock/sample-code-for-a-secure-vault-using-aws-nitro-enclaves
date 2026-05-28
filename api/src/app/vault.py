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

import os
from typing import Optional, Dict, Any, List

from aws_lambda_powertools import Logger, Tracer
from boto3.dynamodb.types import Binary
import cbor2
import requests
from requests.exceptions import HTTPError

from app import constants, utils, exceptions, encryptors
from app.resources import TransactionWriter

# MIME type for CBOR payloads (RFC 8949). Parent's `/decrypt` handler
# branches on these headers — sending CBOR + asking for CBOR is the
# new fast path; JSON stays available for backward compat.
_CBOR_CONTENT_TYPE = "application/cbor"

__all__ = [
    "create_vault",
    "get_vault",
    "delete_vault",
    "update_vault",
    "decrypt_vault",
]


tracer = Tracer()
logger = Logger(child=True)

VAULT_URL = os.getenv(constants.ENV_VAULT_URL)
if not VAULT_URL:
    logger.warning(f"{constants.ENV_VAULT_URL} environment variable not set")

AWS_REGION = os.getenv(constants.ENV_AWS_REGION)
if not AWS_REGION:
    logger.warning(f"{constants.ENV_AWS_REGION} environment variable not set")


@tracer.capture_method(capture_response=False)
def create_vault(txn: TransactionWriter, data: Optional[Dict[str, Any]] = None) -> str:

    vault_id = utils.generate_id("v")
    session = txn.dynamodb.session

    encryptor = encryptors.HpkeAdapter(session)
    key_pair = encryptor.generate_data_key_pair_without_plaintext(vault_id)

    now = utils.now_micros()

    item = {
        constants.ATTR_PK: utils.build_key("VAULT", vault_id),
        constants.ATTR_SK: constants.DEFAULT_VERSION,
        constants.ATTR_ID: vault_id,
        constants.ATTR_VERSION: constants.DEFAULT_ENCODING,
        constants.ATTR_HPKE_SUITE_ID: encryptor.get_suite_id(),
        constants.ATTR_SECRET_KEY: key_pair.encrypted_private_key,
        constants.ATTR_PUBLIC_KEY: key_pair.public_key,
        constants.ATTR_CREATED_AT: now,
        constants.ATTR_MODIFIED_AT: now,
    }

    if data:
        data = encryptor.encrypt_values(key_pair.public_key, data, vault_id)
        item |= data  # merge data dictionary into item dictionary

    txn.put_item(item, unique=True)

    log = {
        constants.ATTR_PK: utils.build_key("LOG", vault_id),
        constants.ATTR_SK: str(now),
        constants.ATTR_EVENT: "CreateVault",
        constants.ATTR_ID: vault_id,
        constants.ATTR_CREATED_AT: now,
    }

    txn.put_item(log)

    return vault_id


@tracer.capture_method(capture_response=False)
def get_vault(txn: TransactionWriter, vault_id: str, attributes: Optional[List[str]] = None) -> Dict[str, Any]:

    key = {
        constants.ATTR_PK: utils.build_key("VAULT", vault_id),
        constants.ATTR_SK: constants.DEFAULT_VERSION,
    }

    dynamodb = txn.dynamodb

    logger.debug("Getting vault from DynamoDB", key=key, attributes=attributes)
    item = dynamodb.get_item(key, attributes)

    return item


@tracer.capture_method(capture_response=False)
def delete_vault(
    txn: TransactionWriter,
    vault_id: str,
    fields: Optional[List[str]] = None,
    delete_all: Optional[bool] = None,
) -> None:

    key = {
        constants.ATTR_PK: utils.build_key("VAULT", vault_id),
        constants.ATTR_SK: constants.DEFAULT_VERSION,
    }

    now = utils.now_micros()

    if delete_all:
        logger.debug("Deleting vault from DynamoDB", key=key)

        txn.delete_item(key)

        log = {
            constants.ATTR_PK: utils.build_key("LOG", vault_id),
            constants.ATTR_SK: str(now),
            constants.ATTR_EVENT: "DeleteVault",
            constants.ATTR_ID: vault_id,
            constants.ATTR_CREATED_AT: now,
        }

        txn.put_item(log)

    elif fields:
        logger.debug(
            "Removing attributes from vault in DynamoDB",
            key=key,
            remove_attributes=fields,
        )

        item = {
            constants.ATTR_MODIFIED_AT: now,
        }

        txn.update_item(key, update_item=item, remove_attributes=fields)

        log = {
            constants.ATTR_PK: utils.build_key("LOG", vault_id),
            constants.ATTR_SK: str(now),
            constants.ATTR_EVENT: "UpdateVault",
            constants.ATTR_FIELDS: fields,
            constants.ATTR_REASON: "RemoveFields",
            constants.ATTR_ID: vault_id,
            constants.ATTR_CREATED_AT: now,
        }

        txn.put_item(log)


@tracer.capture_method(capture_response=False)
def update_vault(txn: TransactionWriter, vault_id: str, data: Optional[Dict[str, Any]] = None) -> None:
    if not data:
        return None

    key = {
        constants.ATTR_PK: utils.build_key("VAULT", vault_id),
        constants.ATTR_SK: constants.DEFAULT_VERSION,
    }

    dynamodb = txn.dynamodb
    attributes = [constants.ATTR_PUBLIC_KEY]

    logger.debug("Getting vault from DynamoDB", key=key, attributes=attributes)
    item = dynamodb.get_item(key, attributes)

    public_key: Optional[Binary] = item.get(constants.ATTR_PUBLIC_KEY)
    if not public_key:
        logger.error("Public key not found in vault", key=key)
        raise exceptions.InternalServerError("Public key not found in vault")

    encryptor = encryptors.HpkeAdapter(dynamodb.session)
    data = encryptor.encrypt_values(bytes(public_key), data, vault_id)

    now = utils.now_micros()
    data[constants.ATTR_MODIFIED_AT] = now

    txn.update_item(key, update_item=data)

    log = {
        constants.ATTR_PK: utils.build_key("LOG", vault_id),
        constants.ATTR_SK: str(now),
        constants.ATTR_EVENT: "UpdateVault",
        constants.ATTR_ID: vault_id,
        constants.ATTR_CREATED_AT: now,
    }

    txn.put_item(log)

    return None


@tracer.capture_method(capture_response=False)
def decrypt_vault(
    txn: TransactionWriter,
    vault_id: str,
    fields: List[str],
    expressions: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:

    key = {
        constants.ATTR_PK: utils.build_key("VAULT", vault_id),
        constants.ATTR_SK: constants.DEFAULT_VERSION,
    }

    dynamodb = txn.dynamodb
    attributes = [
        constants.ATTR_ID,
        constants.ATTR_VERSION,
        constants.ATTR_HPKE_SUITE_ID,
        constants.ATTR_SECRET_KEY,
    ] + fields

    logger.debug("Getting vault from DynamoDB", key=key, attributes=attributes)
    item = dynamodb.get_item(key, attributes)

    encrypted_secret_key: Optional[Binary] = item.get(constants.ATTR_SECRET_KEY)
    if not encrypted_secret_key:
        logger.error("Secret key not found in vault", key=key)
        raise exceptions.InternalServerError("Secret key not found in vault")

    hpke_suite_id: Optional[Binary] = item.get(constants.ATTR_HPKE_SUITE_ID)
    if not hpke_suite_id:
        logger.error("Encryption suite not found in vault", key=key)
        raise exceptions.InternalServerError("Encryption suite not found in vault")

    encoding_version: Optional[int] = item.get(constants.ATTR_VERSION)

    # Normalize every per-field value to a typed `{encapped_key,
    # ciphertext}` pair of raw bytes regardless of how it was stored in
    # DynamoDB. v=1 records (legacy hex) carry `encap_hex#ct_hex`
    # strings; v=2 records (current binary default) carry `encap ||
    # ciphertext` concatenated bytes, split using the suite's
    # encapsulated-key length. The parent receives the same typed shape
    # either way, so the `encoding` selector is gone from the wire.
    suite_id_bytes = bytes(hpke_suite_id)
    encap_size = utils.hpke_encap_key_size(suite_id_bytes)

    payload_fields: Dict[str, Dict[str, bytes]] = {}
    for field in fields:
        value: Optional[str | Binary] = item.get(field)
        if value is None:
            continue
        if isinstance(value, Binary):
            encap, ciphertext = utils.decode_v2_field(value, encap_size)
        else:
            encap, ciphertext = utils.decode_v1_field(value)
        payload_fields[field] = {"encapped_key": encap, "ciphertext": ciphertext}

    payload: Dict[str, Any] = {
        "vault_id": vault_id,
        "region": AWS_REGION,
        "fields": payload_fields,
        "suite_id": suite_id_bytes,
        "encrypted_private_key": bytes(encrypted_secret_key),
    }
    if expressions:
        payload["expressions"] = expressions

    url = f"{VAULT_URL}/decrypt"

    logger.debug(
        "Sending decrypt request to vault",
        url=url,
        vault_id=vault_id,
        field_count=len(payload_fields),
        encoding_version=encoding_version,
    )
    body = cbor2.dumps(payload)
    r = requests.post(
        url,
        data=body,
        headers={
            "Content-Type": _CBOR_CONTENT_TYPE,
            "Accept": _CBOR_CONTENT_TYPE,
        },
        timeout=constants.VAULT_TIMEOUT_SECS,
        allow_redirects=False,
    )
    try:
        r.raise_for_status()
    except HTTPError:
        logger.exception(
            "Invalid response received from vault",
            status_code=r.status_code,
            body=r.text,
        )
        raise exceptions.InternalServerError()

    # Parent normally responds CBOR (matching Accept), but error
    # responses come back as JSON regardless. We branch on the response
    # Content-Type rather than guessing per status code.
    response_ct = r.headers.get("content-type", "").lower()
    if response_ct.startswith(_CBOR_CONTENT_TYPE):
        data = cbor2.loads(r.content)
    else:
        data = r.json()

    return data

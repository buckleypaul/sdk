#!/usr/bin/env python3
#
# Copyright (c) 2025 Hubble Network, Inc.
#
# SPDX-License-Identifier: Apache-2.0

"""
Generate test vectors for BLE advertisement encryption testing.

This script generates a C header file containing test vectors that can be
used to validate the hubble_ble_advertise_get() function against the Python
reference implementation.

Usage:
    python3 generate_ble_test_vectors.py > tests/zephyr/unit/ble-advertise/src/test_vectors.h
"""

from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from Crypto.Protocol.KDF import SP800_108_Counter

HUBBLE_AES_KEY_SIZE = 32
HUBBLE_AES_NONCE_SIZE = 12
HUBBLE_DEVICE_ID_SIZE = 4
HUBBLE_AES_TAG_SIZE = 4
HUBBLE_BLE_UUID = 0xFCA6
TIMER_COUNTER_FREQUENCY = 86400000  # Daily


def generate_kdf_key(key: bytes, key_size: int, label: str, context: int) -> bytes:
    """Generate a derived key using SP800-108 Counter mode KDF."""
    label_bytes = label.encode()
    context_bytes = str(context).encode()

    return SP800_108_Counter(
        key,
        key_size,
        lambda session_key, data: CMAC.new(session_key, data, AES).digest(),
        label=label_bytes,
        context=context_bytes,
    )


def get_device_id(master_key: bytes, time_counter: int) -> bytes:
    """Derive the device ID from the master key and time counter."""
    device_key = generate_kdf_key(master_key, HUBBLE_AES_KEY_SIZE, "DeviceKey", time_counter)
    device_id = generate_kdf_key(device_key, HUBBLE_DEVICE_ID_SIZE, "DeviceID", 0)
    # Return raw bytes - C code uses memcpy directly without byte order conversion
    return device_id


def get_nonce(master_key: bytes, time_counter: int, seq_no: int) -> bytes:
    """Derive the nonce from master key, time counter, and sequence number."""
    nonce_key = generate_kdf_key(master_key, HUBBLE_AES_KEY_SIZE, "NonceKey", time_counter)
    return generate_kdf_key(nonce_key, HUBBLE_AES_NONCE_SIZE, "Nonce", seq_no)


def get_encryption_key(master_key: bytes, time_counter: int, seq_no: int) -> bytes:
    """Derive the encryption key from master key, time counter, and sequence number."""
    encryption_key_base = generate_kdf_key(
        master_key, HUBBLE_AES_KEY_SIZE, "EncryptionKey", time_counter
    )
    return generate_kdf_key(encryption_key_base, HUBBLE_AES_KEY_SIZE, "Key", seq_no)


def get_auth_tag(key: bytes, ciphertext: bytes) -> bytes:
    """Compute the CMAC authentication tag (truncated to 4 bytes)."""
    computed_cmac = CMAC.new(key, ciphertext, AES).digest()
    return computed_cmac[:HUBBLE_AES_TAG_SIZE]


def aes_encrypt(key: bytes, nonce: bytes, data: bytes) -> tuple[bytes, bytes]:
    """Encrypt data using AES-CTR and compute auth tag."""
    ciphertext = AES.new(key, AES.MODE_CTR, nonce=nonce).encrypt(data)
    tag = get_auth_tag(key, ciphertext)
    return ciphertext, tag


def generate_ble_adv(
    master_key: bytes, time_counter: int, seq_no: int, payload: bytes
) -> bytes:
    """Generate the complete BLE advertisement data."""
    device_id = get_device_id(master_key, time_counter)
    nonce = get_nonce(master_key, time_counter, seq_no)
    enc_key = get_encryption_key(master_key, time_counter, seq_no)
    ciphertext, auth_tag = aes_encrypt(enc_key, nonce, payload)

    # Build the advertisement packet
    result = bytearray()

    # Service UUID (little-endian)
    result.append(HUBBLE_BLE_UUID & 0xFF)
    result.append((HUBBLE_BLE_UUID >> 8) & 0xFF)

    # Address: protocol version (6 bits) + seq_no (10 bits) + device_id (32 bits)
    protocol_version = 0b000000
    addr_byte0 = (protocol_version << 2) | ((seq_no >> 8) & 0x03)
    addr_byte1 = seq_no & 0xFF
    result.append(addr_byte0)
    result.append(addr_byte1)

    # Device ID (4 bytes, raw from KDF - C uses memcpy directly)
    result.extend(device_id)

    # Auth tag (4 bytes)
    result.extend(auth_tag)

    # Encrypted payload
    result.extend(ciphertext)

    return bytes(result)


def format_bytes_c(data: bytes, indent: str = "\t\t") -> str:
    """Format bytes as a C array initializer."""
    if len(data) == 0:
        return ""
    hex_values = [f"0x{b:02x}" for b in data]
    # Group in lines of 8 values
    lines = []
    for i in range(0, len(hex_values), 8):
        chunk = hex_values[i : i + 8]
        lines.append(indent + ", ".join(chunk))
    return ",\n".join(lines)


def main():
    # Test keys
    test_keys = [
        # Key from existing tests (zRWlq8BgtnKIph5E6ZW6d9FAvUZWS4jeQcFaknOwzoU=)
        bytes(
            [
                0xCD, 0x15, 0xA5, 0xAB, 0xC0, 0x60, 0xB6, 0x72,
                0x88, 0xA6, 0x1E, 0x44, 0xE9, 0x95, 0xBA, 0x77,
                0xD1, 0x40, 0xBD, 0x46, 0x56, 0x4B, 0x88, 0xDE,
                0x41, 0xC1, 0x5A, 0x92, 0x73, 0xB0, 0xCE, 0x85,
            ]
        ),
        # All zeros key
        bytes([0x00] * 32),
        # All 0xFF key
        bytes([0xFF] * 32),
        # Sequential key
        bytes(list(range(32))),
    ]

    # Test payloads
    test_payloads = [
        b"",  # Empty payload
        bytes([0xDE, 0xAD, 0xBE, 0xEF]),  # 4 bytes
        b"Hello",  # 5 bytes text
        bytes([0x00] * 13),  # Max length, all zeros
        bytes([0xFF] * 13),  # Max length, all 0xFF
        bytes(list(range(13))),  # Max length, sequential
        b"Hello World!",  # 12 bytes text (near max)
    ]

    # Test sequence numbers
    test_seq_nos = [0, 1, 100, 512, 1023]

    # Test time counters (utc_time / 86400000)
    # Note: time_counter=0 means utc_time=0, but hubble_init rejects utc_time=0
    # So we start from 1
    test_time_counters = [1, 2, 20, 1000]

    print(
        """\
/*
 * Copyright (c) 2025 Hubble Network, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * AUTO-GENERATED FILE - DO NOT EDIT
 * Generated by: tools/generate_ble_test_vectors.py
 */

#ifndef TEST_VECTORS_H
#define TEST_VECTORS_H

#include <stdint.h>
#include <stddef.h>

#define TEST_VECTOR_MAX_PAYLOAD_LEN 13
#define TEST_VECTOR_MAX_OUTPUT_LEN  25  /* 2 + 6 + 4 + 13 */

struct test_vector {
\tuint8_t key[32];
\tuint64_t utc_time;
\tuint16_t seq_no;
\tuint8_t payload[TEST_VECTOR_MAX_PAYLOAD_LEN];
\tsize_t payload_len;
\tuint8_t expected_output[TEST_VECTOR_MAX_OUTPUT_LEN];
\tsize_t expected_output_len;
};
"""
    )

    vectors = []

    # Generate comprehensive test vectors
    vector_id = 0

    # Primary key with various payloads and parameters
    for key_idx, key in enumerate(test_keys):
        for payload in test_payloads:
            for seq_no in test_seq_nos:
                for time_counter in test_time_counters:
                    utc_time = time_counter * TIMER_COUNTER_FREQUENCY
                    output = generate_ble_adv(key, time_counter, seq_no, payload)

                    vectors.append(
                        {
                            "key": key,
                            "utc_time": utc_time,
                            "seq_no": seq_no,
                            "payload": payload,
                            "output": output,
                        }
                    )
                    vector_id += 1

                    # Only generate full matrix for first key to keep size reasonable
                    if key_idx > 0:
                        break
                if key_idx > 0:
                    break
            if key_idx > 0 and len(payload) > 4:
                break

    print(f"static const struct test_vector test_vectors[] = {{")

    for i, v in enumerate(vectors):
        key_str = format_bytes_c(v["key"], "\t\t\t")
        payload_str = format_bytes_c(v["payload"], "\t\t\t") if v["payload"] else ""
        output_str = format_bytes_c(v["output"], "\t\t\t")

        print(f"\t/* Vector {i} */")
        print("\t{")
        print(f"\t\t.key = {{")
        print(f"{key_str}")
        print(f"\t\t}},")
        print(f"\t\t.utc_time = {v['utc_time']}ULL,")
        print(f"\t\t.seq_no = {v['seq_no']},")
        if payload_str:
            print(f"\t\t.payload = {{")
            print(f"{payload_str}")
            print(f"\t\t}},")
        else:
            print(f"\t\t.payload = {{}},")
        print(f"\t\t.payload_len = {len(v['payload'])},")
        print(f"\t\t.expected_output = {{")
        print(f"{output_str}")
        print(f"\t\t}},")
        print(f"\t\t.expected_output_len = {len(v['output'])},")
        print("\t},")

    print("};")
    print()
    print(f"#define TEST_VECTOR_COUNT {len(vectors)}")
    print()
    print("#endif /* TEST_VECTORS_H */")


if __name__ == "__main__":
    main()

/*
 * Copyright (c) 2025 Hubble Network, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <hubble/hubble.h>
#include <hubble/port/sys.h>
#include <hubble/port/crypto.h>

#include <zephyr/sys/util.h>
#include <zephyr/types.h>
#include <zephyr/ztest.h>

#include "test_decrypt.h"
#include "test_vectors.h"

#define TEST_ADV_BUFFER_SZ 32
#define TIMER_COUNTER_FREQUENCY 86400000ULL

/* Test sequence counter override */
static uint16_t test_seq_override;

uint16_t hubble_sequence_counter_get(void)
{
	return test_seq_override;
}

/* Test keys */
static const uint8_t test_key_primary[CONFIG_HUBBLE_KEY_SIZE] = {
	0xcd, 0x15, 0xa5, 0xab, 0xc0, 0x60, 0xb6, 0x72,
	0x88, 0xa6, 0x1e, 0x44, 0xe9, 0x95, 0xba, 0x77,
	0xd1, 0x40, 0xbd, 0x46, 0x56, 0x4b, 0x88, 0xde,
	0x41, 0xc1, 0x5a, 0x92, 0x73, 0xb0, 0xce, 0x85
};

static const uint8_t test_key_zeros[CONFIG_HUBBLE_KEY_SIZE] = {0};

static const uint8_t test_key_ones[CONFIG_HUBBLE_KEY_SIZE] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

static const uint8_t test_key_sequential[CONFIG_HUBBLE_KEY_SIZE] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

/*===========================================================================*/
/* Test Suite: ble_vector_test - Python cross-validation                     */
/*===========================================================================*/

ZTEST(ble_vector_test, test_against_python_vectors)
{
	for (size_t i = 0; i < TEST_VECTOR_COUNT; i++) {
		const struct test_vector *v = &test_vectors[i];

		/* Initialize with test parameters */
		int ret = hubble_init(v->utc_time, v->key);
		zassert_ok(ret, "hubble_init failed for vector %zu", i);

		/* Set sequence number */
		test_seq_override = v->seq_no;

		/* Generate advertisement */
		uint8_t output[TEST_ADV_BUFFER_SZ];
		size_t output_len = sizeof(output);

		ret = hubble_ble_advertise_get(
			v->payload_len > 0 ? v->payload : NULL,
			v->payload_len, output, &output_len);
		zassert_ok(ret, "hubble_ble_advertise_get failed for vector %zu", i);

		/* Verify output length matches */
		zassert_equal(output_len, v->expected_output_len,
			      "Output length mismatch for vector %zu: got %zu, expected %zu",
			      i, output_len, v->expected_output_len);

		/* Verify output matches expected */
		zassert_mem_equal(output, v->expected_output, output_len,
				  "Output mismatch for vector %zu", i);
	}
}

ZTEST(ble_vector_test, test_vector_coverage)
{
	/* Verify we have a reasonable number of test vectors */
	zassert_true(TEST_VECTOR_COUNT >= 100,
		     "Expected at least 100 test vectors, got %d",
		     TEST_VECTOR_COUNT);

	/* Check that vectors cover different sequence numbers */
	bool has_seq_0 = false;
	bool has_seq_max = false;
	bool has_seq_mid = false;

	for (size_t i = 0; i < TEST_VECTOR_COUNT; i++) {
		if (test_vectors[i].seq_no == 0) {
			has_seq_0 = true;
		}
		if (test_vectors[i].seq_no == 1023) {
			has_seq_max = true;
		}
		if (test_vectors[i].seq_no == 512) {
			has_seq_mid = true;
		}
	}

	zassert_true(has_seq_0, "No vectors with seq_no = 0");
	zassert_true(has_seq_max, "No vectors with seq_no = 1023");
	zassert_true(has_seq_mid, "No vectors with seq_no = 512");
}

static void *ble_vector_test_setup(void)
{
	test_seq_override = 0;
	return NULL;
}

ZTEST_SUITE(ble_vector_test, NULL, ble_vector_test_setup, NULL, NULL, NULL);

/*===========================================================================*/
/* Test Suite: ble_decrypt_test - Round-trip encryption/decryption           */
/*===========================================================================*/

ZTEST(ble_decrypt_test, test_roundtrip_empty_payload)
{
	uint64_t utc_time = 20ULL * TIMER_COUNTER_FREQUENCY;
	uint32_t time_counter = 20;

	hubble_init(utc_time, test_key_primary);
	test_seq_override = 0;

	uint8_t output[TEST_ADV_BUFFER_SZ];
	size_t output_len = sizeof(output);

	int ret = hubble_ble_advertise_get(NULL, 0, output, &output_len);
	zassert_ok(ret);

	/* Parse the advertisement */
	struct test_ble_adv_parsed parsed;
	ret = test_parse_ble_adv(output, output_len, &parsed);
	zassert_ok(ret);

	/* Verify sequence number in output */
	zassert_equal(parsed.seq_no, 0);

	/* Verify encrypted length is 0 */
	zassert_equal(parsed.encrypted_len, 0);

	/* Verify auth tag (CMAC of empty data) */
	ret = test_verify_auth_tag(test_key_primary, time_counter, 0,
				   parsed.encrypted_data, 0, parsed.auth_tag);
	zassert_ok(ret, "Auth tag verification failed");
}

ZTEST(ble_decrypt_test, test_roundtrip_max_payload)
{
	uint64_t utc_time = 20ULL * TIMER_COUNTER_FREQUENCY;
	uint32_t time_counter = 20;
	uint8_t payload[HUBBLE_BLE_MAX_DATA_LEN];

	/* Fill with recognizable pattern */
	for (size_t i = 0; i < sizeof(payload); i++) {
		payload[i] = (uint8_t)(i * 17 + 3);
	}

	hubble_init(utc_time, test_key_primary);
	test_seq_override = 100;

	uint8_t output[TEST_ADV_BUFFER_SZ];
	size_t output_len = sizeof(output);

	int ret = hubble_ble_advertise_get(payload, sizeof(payload), output, &output_len);
	zassert_ok(ret);

	/* Parse and decrypt */
	struct test_ble_adv_parsed parsed;
	ret = test_parse_ble_adv(output, output_len, &parsed);
	zassert_ok(ret);

	zassert_equal(parsed.encrypted_len, sizeof(payload));

	uint8_t decrypted[HUBBLE_BLE_MAX_DATA_LEN];
	ret = test_decrypt_payload(test_key_primary, time_counter, 100,
				   parsed.encrypted_data, parsed.encrypted_len,
				   decrypted);
	zassert_ok(ret);

	/* Verify decrypted matches original */
	zassert_mem_equal(decrypted, payload, sizeof(payload),
			  "Decrypted data does not match original");

	/* Verify auth tag */
	ret = test_verify_auth_tag(test_key_primary, time_counter, 100,
				   parsed.encrypted_data, parsed.encrypted_len,
				   parsed.auth_tag);
	zassert_ok(ret, "Auth tag verification failed");
}

ZTEST(ble_decrypt_test, test_roundtrip_various_payloads)
{
	uint64_t utc_time = 1ULL * TIMER_COUNTER_FREQUENCY;
	uint32_t time_counter = 1;

	static const uint8_t test_payloads[][13] = {
		{0xDE, 0xAD, 0xBE, 0xEF},
		{0x00},
		{0xFF},
		{0x01, 0x02, 0x03, 0x04, 0x05},
		{'H', 'e', 'l', 'l', 'o'},
	};
	static const size_t test_payload_lens[] = {4, 1, 1, 5, 5};

	hubble_init(utc_time, test_key_primary);

	for (size_t i = 0; i < ARRAY_SIZE(test_payloads); i++) {
		test_seq_override = (uint16_t)(i * 50);

		uint8_t output[TEST_ADV_BUFFER_SZ];
		size_t output_len = sizeof(output);

		int ret = hubble_ble_advertise_get(test_payloads[i],
						   test_payload_lens[i],
						   output, &output_len);
		zassert_ok(ret, "Failed for payload %zu", i);

		struct test_ble_adv_parsed parsed;
		ret = test_parse_ble_adv(output, output_len, &parsed);
		zassert_ok(ret);

		uint8_t decrypted[HUBBLE_BLE_MAX_DATA_LEN];
		ret = test_decrypt_payload(test_key_primary, time_counter,
					   test_seq_override,
					   parsed.encrypted_data,
					   parsed.encrypted_len, decrypted);
		zassert_ok(ret);

		zassert_mem_equal(decrypted, test_payloads[i], test_payload_lens[i],
				  "Roundtrip failed for payload %zu", i);
	}
}

ZTEST(ble_decrypt_test, test_auth_tag_validates)
{
	uint64_t utc_time = 20ULL * TIMER_COUNTER_FREQUENCY;
	uint32_t time_counter = 20;
	uint8_t payload[] = {0xDE, 0xAD, 0xBE, 0xEF};

	hubble_init(utc_time, test_key_primary);
	test_seq_override = 42;

	uint8_t output[TEST_ADV_BUFFER_SZ];
	size_t output_len = sizeof(output);

	int ret = hubble_ble_advertise_get(payload, sizeof(payload), output, &output_len);
	zassert_ok(ret);

	struct test_ble_adv_parsed parsed;
	ret = test_parse_ble_adv(output, output_len, &parsed);
	zassert_ok(ret);

	/* Auth tag should validate */
	ret = test_verify_auth_tag(test_key_primary, time_counter, 42,
				   parsed.encrypted_data, parsed.encrypted_len,
				   parsed.auth_tag);
	zassert_ok(ret, "Valid auth tag should verify successfully");
}

ZTEST(ble_decrypt_test, test_tampered_data_fails)
{
	uint64_t utc_time = 20ULL * TIMER_COUNTER_FREQUENCY;
	uint32_t time_counter = 20;
	uint8_t payload[] = {0xDE, 0xAD, 0xBE, 0xEF};

	hubble_init(utc_time, test_key_primary);
	test_seq_override = 42;

	uint8_t output[TEST_ADV_BUFFER_SZ];
	size_t output_len = sizeof(output);

	int ret = hubble_ble_advertise_get(payload, sizeof(payload), output, &output_len);
	zassert_ok(ret);

	struct test_ble_adv_parsed parsed;
	ret = test_parse_ble_adv(output, output_len, &parsed);
	zassert_ok(ret);

	/* Tamper with encrypted data */
	uint8_t tampered_data[HUBBLE_BLE_MAX_DATA_LEN];
	memcpy(tampered_data, parsed.encrypted_data, parsed.encrypted_len);
	tampered_data[0] ^= 0xFF;

	/* Auth tag should fail verification */
	ret = test_verify_auth_tag(test_key_primary, time_counter, 42,
				   tampered_data, parsed.encrypted_len,
				   parsed.auth_tag);
	zassert_equal(ret, -EBADMSG, "Tampered data should fail auth verification");
}

static void *ble_decrypt_test_setup(void)
{
	test_seq_override = 0;
	return NULL;
}

ZTEST_SUITE(ble_decrypt_test, NULL, ble_decrypt_test_setup, NULL, NULL, NULL);

/*===========================================================================*/
/* Test Suite: ble_multikey_test - Various master keys                       */
/*===========================================================================*/

ZTEST(ble_multikey_test, test_different_keys_different_output)
{
	uint64_t utc_time = 20ULL * TIMER_COUNTER_FREQUENCY;
	uint8_t payload[] = {0xDE, 0xAD, 0xBE, 0xEF};

	const uint8_t *keys[] = {
		test_key_primary,
		test_key_zeros,
		test_key_ones,
		test_key_sequential
	};

	uint8_t outputs[4][TEST_ADV_BUFFER_SZ];
	size_t output_lens[4];

	for (size_t i = 0; i < ARRAY_SIZE(keys); i++) {
		hubble_init(utc_time, keys[i]);
		test_seq_override = 0;

		output_lens[i] = sizeof(outputs[i]);
		int ret = hubble_ble_advertise_get(payload, sizeof(payload),
						   outputs[i], &output_lens[i]);
		zassert_ok(ret, "Failed for key %zu", i);
	}

	/* All outputs should be different (except service UUID) */
	for (size_t i = 0; i < ARRAY_SIZE(keys); i++) {
		for (size_t j = i + 1; j < ARRAY_SIZE(keys); j++) {
			/* Compare encrypted portion (skip UUID bytes) */
			bool different = false;
			for (size_t k = 2; k < output_lens[i] && k < output_lens[j]; k++) {
				if (outputs[i][k] != outputs[j][k]) {
					different = true;
					break;
				}
			}
			zassert_true(different,
				     "Keys %zu and %zu produced same output", i, j);
		}
	}
}

ZTEST(ble_multikey_test, test_key_derivation_consistency)
{
	uint64_t utc_time = 20ULL * TIMER_COUNTER_FREQUENCY;
	uint8_t payload[] = {0x01, 0x02, 0x03};

	/* Same inputs should always produce same output */
	for (int trial = 0; trial < 3; trial++) {
		hubble_init(utc_time, test_key_primary);
		test_seq_override = 100;

		uint8_t output1[TEST_ADV_BUFFER_SZ];
		uint8_t output2[TEST_ADV_BUFFER_SZ];
		size_t len1 = sizeof(output1);
		size_t len2 = sizeof(output2);

		int ret = hubble_ble_advertise_get(payload, sizeof(payload),
						   output1, &len1);
		zassert_ok(ret);

		/* Re-init with same parameters */
		hubble_init(utc_time, test_key_primary);
		test_seq_override = 100;

		ret = hubble_ble_advertise_get(payload, sizeof(payload),
					       output2, &len2);
		zassert_ok(ret);

		zassert_equal(len1, len2);
		zassert_mem_equal(output1, output2, len1,
				  "Same inputs should produce same output");
	}
}

ZTEST(ble_multikey_test, test_cross_key_decrypt_fails)
{
	uint64_t utc_time = 20ULL * TIMER_COUNTER_FREQUENCY;
	uint32_t time_counter = 20;
	uint8_t payload[] = {0xDE, 0xAD, 0xBE, 0xEF};

	/* Encrypt with primary key */
	hubble_init(utc_time, test_key_primary);
	test_seq_override = 50;

	uint8_t output[TEST_ADV_BUFFER_SZ];
	size_t output_len = sizeof(output);

	int ret = hubble_ble_advertise_get(payload, sizeof(payload), output, &output_len);
	zassert_ok(ret);

	struct test_ble_adv_parsed parsed;
	ret = test_parse_ble_adv(output, output_len, &parsed);
	zassert_ok(ret);

	/* Try to verify with wrong key - should fail */
	ret = test_verify_auth_tag(test_key_zeros, time_counter, 50,
				   parsed.encrypted_data, parsed.encrypted_len,
				   parsed.auth_tag);
	zassert_equal(ret, -EBADMSG, "Wrong key should fail auth verification");

	/* Decrypt with wrong key produces garbage (not original) */
	uint8_t decrypted[HUBBLE_BLE_MAX_DATA_LEN];
	ret = test_decrypt_payload(test_key_zeros, time_counter, 50,
				   parsed.encrypted_data, parsed.encrypted_len,
				   decrypted);
	zassert_ok(ret, "Decryption operation should succeed");

	/* But decrypted data should NOT match original */
	bool matches = (memcmp(decrypted, payload, sizeof(payload)) == 0);
	zassert_false(matches, "Wrong key should not decrypt to original");
}

static void *ble_multikey_test_setup(void)
{
	test_seq_override = 0;
	return NULL;
}

ZTEST_SUITE(ble_multikey_test, NULL, ble_multikey_test_setup, NULL, NULL, NULL);

/*===========================================================================*/
/* Test Suite: ble_counter_test - Time counter and sequence variations       */
/*===========================================================================*/

ZTEST(ble_counter_test, test_different_time_counters)
{
	uint8_t payload[] = {0xAB, 0xCD};
	/* Note: time_counter=0 means utc_time=0 which is rejected by hubble_init */
	uint64_t time_counters[] = {1, 2, 20, 100, 1000};

	uint8_t outputs[5][TEST_ADV_BUFFER_SZ];
	size_t output_lens[5];

	for (size_t i = 0; i < ARRAY_SIZE(time_counters); i++) {
		uint64_t utc_time = time_counters[i] * TIMER_COUNTER_FREQUENCY;
		hubble_init(utc_time, test_key_primary);
		test_seq_override = 0;

		output_lens[i] = sizeof(outputs[i]);
		int ret = hubble_ble_advertise_get(payload, sizeof(payload),
						   outputs[i], &output_lens[i]);
		zassert_ok(ret, "Failed for time_counter %llu", time_counters[i]);
	}

	/* All outputs should be different */
	for (size_t i = 0; i < ARRAY_SIZE(time_counters); i++) {
		for (size_t j = i + 1; j < ARRAY_SIZE(time_counters); j++) {
			bool different = false;
			for (size_t k = 2; k < output_lens[i] && k < output_lens[j]; k++) {
				if (outputs[i][k] != outputs[j][k]) {
					different = true;
					break;
				}
			}
			zassert_true(different,
				     "Time counters %llu and %llu produced same output",
				     time_counters[i], time_counters[j]);
		}
	}
}

ZTEST(ble_counter_test, test_sequence_number_boundary)
{
	uint64_t utc_time = 20ULL * TIMER_COUNTER_FREQUENCY;
	uint8_t payload[] = {0x01};

	uint16_t seq_nos[] = {0, 1, 1023};

	uint8_t outputs[3][TEST_ADV_BUFFER_SZ];
	size_t output_lens[3];

	hubble_init(utc_time, test_key_primary);

	for (size_t i = 0; i < ARRAY_SIZE(seq_nos); i++) {
		test_seq_override = seq_nos[i];
		output_lens[i] = sizeof(outputs[i]);

		int ret = hubble_ble_advertise_get(payload, sizeof(payload),
						   outputs[i], &output_lens[i]);
		zassert_ok(ret, "Failed for seq_no %u", seq_nos[i]);

		/* Verify seq_no is encoded correctly in output */
		struct test_ble_adv_parsed parsed;
		ret = test_parse_ble_adv(outputs[i], output_lens[i], &parsed);
		zassert_ok(ret);

		zassert_equal(parsed.seq_no, seq_nos[i],
			      "Seq_no mismatch: got %u, expected %u",
			      parsed.seq_no, seq_nos[i]);
	}

	/* All outputs should be different */
	for (size_t i = 0; i < ARRAY_SIZE(seq_nos); i++) {
		for (size_t j = i + 1; j < ARRAY_SIZE(seq_nos); j++) {
			zassert_false(
				memcmp(outputs[i], outputs[j], output_lens[i]) == 0,
				"Seq_nos %u and %u produced same output",
				seq_nos[i], seq_nos[j]);
		}
	}
}

ZTEST(ble_counter_test, test_same_seq_different_time)
{
	uint8_t payload[] = {0xFE, 0xED};

	/* Same seq_no but different time counters */
	uint64_t utc_times[] = {
		0ULL * TIMER_COUNTER_FREQUENCY,
		20ULL * TIMER_COUNTER_FREQUENCY
	};

	uint8_t outputs[2][TEST_ADV_BUFFER_SZ];
	size_t output_lens[2];

	for (size_t i = 0; i < ARRAY_SIZE(utc_times); i++) {
		hubble_init(utc_times[i], test_key_primary);
		test_seq_override = 100;

		output_lens[i] = sizeof(outputs[i]);
		int ret = hubble_ble_advertise_get(payload, sizeof(payload),
						   outputs[i], &output_lens[i]);
		zassert_ok(ret);
	}

	/* Outputs should be different despite same seq_no */
	zassert_false(memcmp(outputs[0], outputs[1], output_lens[0]) == 0,
		      "Same seq_no with different time should produce different output");
}

ZTEST(ble_counter_test, test_time_counter_derived_correctly)
{
	/* Verify that utc_time / 86400000 gives correct time_counter */
	/* Note: hubble_init rejects utc_time=0, so we start from non-zero values */
	struct {
		uint64_t utc_time;
		uint32_t expected_time_counter;
	} test_cases[] = {
		{1ULL, 0},             /* Non-zero utc but time_counter=0 */
		{86400000ULL - 1, 0},  /* Just before first day ends */
		{86400000ULL, 1},      /* Exactly one day */
		{86400000ULL * 20, 20},
		{86400000ULL * 1000, 1000},
	};

	uint8_t payload[] = {0x01};

	for (size_t i = 0; i < ARRAY_SIZE(test_cases); i++) {
		hubble_init(test_cases[i].utc_time, test_key_primary);
		test_seq_override = 0;

		uint8_t output[TEST_ADV_BUFFER_SZ];
		size_t output_len = sizeof(output);

		int ret = hubble_ble_advertise_get(payload, sizeof(payload),
						   output, &output_len);
		zassert_ok(ret);

		/* Parse and verify device_id matches expected derivation */
		struct test_ble_adv_parsed parsed;
		ret = test_parse_ble_adv(output, output_len, &parsed);
		zassert_ok(ret);

		uint32_t expected_device_id;
		ret = test_derive_device_id(test_key_primary,
					    test_cases[i].expected_time_counter,
					    &expected_device_id);
		zassert_ok(ret);

		zassert_equal(parsed.device_id, expected_device_id,
			      "Device ID mismatch for utc_time %llu",
			      test_cases[i].utc_time);
	}
}

static void *ble_counter_test_setup(void)
{
	test_seq_override = 0;
	return NULL;
}

ZTEST_SUITE(ble_counter_test, NULL, ble_counter_test_setup, NULL, NULL, NULL);

/*===========================================================================*/
/* Test Suite: ble_component_test - Individual component verification        */
/*===========================================================================*/

ZTEST(ble_component_test, test_device_id_derivation)
{
	uint64_t utc_time = 20ULL * TIMER_COUNTER_FREQUENCY;
	uint32_t time_counter = 20;

	hubble_init(utc_time, test_key_primary);
	test_seq_override = 0;

	uint8_t output[TEST_ADV_BUFFER_SZ];
	size_t output_len = sizeof(output);

	int ret = hubble_ble_advertise_get(NULL, 0, output, &output_len);
	zassert_ok(ret);

	struct test_ble_adv_parsed parsed;
	ret = test_parse_ble_adv(output, output_len, &parsed);
	zassert_ok(ret);

	/* Verify device_id using test helper */
	uint32_t expected_device_id;
	ret = test_derive_device_id(test_key_primary, time_counter,
				    &expected_device_id);
	zassert_ok(ret);

	zassert_equal(parsed.device_id, expected_device_id,
		      "Device ID derivation mismatch");
}

ZTEST(ble_component_test, test_nonce_derivation)
{
	/* Verify nonce derivation produces consistent results */
	uint8_t nonce1[12];
	uint8_t nonce2[12];

	int ret = test_derive_nonce(test_key_primary, 20, 100, nonce1);
	zassert_ok(ret);

	ret = test_derive_nonce(test_key_primary, 20, 100, nonce2);
	zassert_ok(ret);

	zassert_mem_equal(nonce1, nonce2, sizeof(nonce1),
			  "Same inputs should produce same nonce");

	/* Different seq_no should produce different nonce */
	ret = test_derive_nonce(test_key_primary, 20, 101, nonce2);
	zassert_ok(ret);

	zassert_false(memcmp(nonce1, nonce2, sizeof(nonce1)) == 0,
		      "Different seq_no should produce different nonce");
}

ZTEST(ble_component_test, test_service_uuid_correct)
{
	uint64_t utc_time = 20ULL * TIMER_COUNTER_FREQUENCY;

	hubble_init(utc_time, test_key_primary);
	test_seq_override = 0;

	uint8_t output[TEST_ADV_BUFFER_SZ];
	size_t output_len = sizeof(output);

	int ret = hubble_ble_advertise_get(NULL, 0, output, &output_len);
	zassert_ok(ret);

	struct test_ble_adv_parsed parsed;
	ret = test_parse_ble_adv(output, output_len, &parsed);
	zassert_ok(ret);

	/* Service UUID should always be 0xFCA6 */
	zassert_equal(parsed.service_uuid, HUBBLE_BLE_UUID,
		      "Service UUID should be 0xFCA6, got 0x%04X",
		      parsed.service_uuid);
}

ZTEST(ble_component_test, test_output_format_structure)
{
	uint64_t utc_time = 20ULL * TIMER_COUNTER_FREQUENCY;
	uint8_t payload[] = {0xDE, 0xAD, 0xBE, 0xEF};

	hubble_init(utc_time, test_key_primary);
	test_seq_override = 0;

	uint8_t output[TEST_ADV_BUFFER_SZ];
	size_t output_len = sizeof(output);

	int ret = hubble_ble_advertise_get(payload, sizeof(payload),
					   output, &output_len);
	zassert_ok(ret);

	/* Verify output structure:
	 * [0-1]: Service UUID (little-endian, 0xFCA6 → 0xA6, 0xFC)
	 * [2-7]: Address (6 bytes: protocol_version|seq_no + device_id)
	 * [8-11]: Auth tag (4 bytes)
	 * [12+]: Encrypted data
	 */
	zassert_equal(output_len, 2 + 6 + 4 + sizeof(payload),
		      "Output length should be %zu, got %zu",
		      2 + 6 + 4 + sizeof(payload), output_len);

	/* Service UUID bytes */
	zassert_equal(output[0], 0xA6, "UUID low byte should be 0xA6");
	zassert_equal(output[1], 0xFC, "UUID high byte should be 0xFC");

	/* Protocol version should be 0 (top 6 bits of byte 2) */
	uint8_t protocol_version = (output[2] >> 2) & 0x3F;
	zassert_equal(protocol_version, 0, "Protocol version should be 0");
}

ZTEST(ble_component_test, test_encryption_key_derivation)
{
	/* Verify encryption key derivation produces consistent results */
	uint8_t enc_key1[CONFIG_HUBBLE_KEY_SIZE];
	uint8_t enc_key2[CONFIG_HUBBLE_KEY_SIZE];

	int ret = test_derive_encryption_key(test_key_primary, 20, 100, enc_key1);
	zassert_ok(ret);

	ret = test_derive_encryption_key(test_key_primary, 20, 100, enc_key2);
	zassert_ok(ret);

	zassert_mem_equal(enc_key1, enc_key2, sizeof(enc_key1),
			  "Same inputs should produce same encryption key");

	/* Different inputs should produce different keys */
	ret = test_derive_encryption_key(test_key_primary, 20, 101, enc_key2);
	zassert_ok(ret);

	zassert_false(memcmp(enc_key1, enc_key2, sizeof(enc_key1)) == 0,
		      "Different seq_no should produce different encryption key");

	ret = test_derive_encryption_key(test_key_primary, 21, 100, enc_key2);
	zassert_ok(ret);

	zassert_false(memcmp(enc_key1, enc_key2, sizeof(enc_key1)) == 0,
		      "Different time_counter should produce different encryption key");
}

static void *ble_component_test_setup(void)
{
	test_seq_override = 0;
	return NULL;
}

ZTEST_SUITE(ble_component_test, NULL, ble_component_test_setup, NULL, NULL, NULL);

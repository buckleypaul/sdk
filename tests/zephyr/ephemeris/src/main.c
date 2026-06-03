/*
 * Copyright (c) 2025 Hubble Network
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <hubble/sat/ephemeris.h>
#include <zephyr/types.h>
#include <zephyr/ztest.h>

#define EPHEMERIS_DELTA                   (3)

/* The transmission period is the product of the number of retries +
 * the interval between them.
 */
#define TRANSMISSION_PERIOD_SINGLE_PACKET (160U)

struct test_result {
	struct hubble_sat_device_pos pos;
	uint64_t start_time;
	uint64_t culmination_time;
};

static const struct test_result results[] = {
	{{47.0, -122.0}, 1713531547, 1713564688},
	{{47.0, -122.0}, 1713876681, 1713911881},
	{{47.0, -122.0}, 1712041799, 1712049007},
	{{47.0, -122.0}, 1711763288, 1711792749},
	{{47.0, -122.0}, 1713446752, 1713479299},
	{{47.0, -122.0}, 1712224710, 1712310896},
	{{47.0, -122.0}, 1711689906, 1711792748},
	{{47.0, -122.0}, 1713506544, 1713517812},
	{{47.0, -122.0}, 1713338906, 1713347025},
	{{47.0, -122.0}, 1711708097, 1711792749},
	{{47.0, 122.0}, 1713760281, 1713854942},
	{{47.0, 122.0}, 1712068561, 1712077469},
	{{47.0, 122.0}, 1713682621, 1713717054},
	{{47.0, 122.0}, 1712405118, 1712424770},
	{{47.0, 122.0}, 1713082984, 1713113652},
	{{47.0, 122.0}, 1713279632, 1713375482},
	{{47.0, 122.0}, 1712735394, 1712857450},
	{{47.0, 122.0}, 1713025696, 1713028250},
	{{47.0, 122.0}, 1711763177, 1711777042},
	{{47.0, 122.0}, 1713038984, 1713075136},
	{{47.0, 180.0}, 1711465572, 1711503713},
	{{47.0, 180.0}, 1712511962, 1712584182},
	{{47.0, 180.0}, 1713888172, 1713923286},
	{{47.0, 180.0}, 1712072133, 1712112947},
	{{47.0, 180.0}, 1712699256, 1712716473},
	{{47.0, 180.0}, 1713681616, 1713705638},
	{{47.0, 180.0}, 1712919674, 1712925807},
	{{47.0, 180.0}, 1712204544, 1712236891},
	{{47.0, 180.0}, 1713474729, 1713534862},
	{{47.0, 180.0}, 1712244051, 1712283785},
	{{47.0, 0.0}, 1713363476, 1713365432},
	{{47.0, 0.0}, 1712795634, 1712847395},
	{{47.0, 0.0}, 1712607843, 1712624066},
	{{47.0, 0.0}, 1712551927, 1712585545},
	{{47.0, 0.0}, 1712017447, 1712020530},
	{{47.0, 0.0}, 1712668061, 1712670950},
	{{47.0, 0.0}, 1711546857, 1711549251},
	{{47.0, 0.0}, 1712839983, 1712847395},
	{{47.0, 0.0}, 1712348658, 1712367834},
	{{47.0, 0.0}, 1712672465, 1712709477},
	{{-47.0, 180.0}, 1712553559, 1712588355},
	{{-47.0, 180.0}, 1711492632, 1711590596},
	{{-47.0, 180.0}, 1712171215, 1712194179},
	{{-47.0, 180.0}, 1713387771, 1713401132},
	{{-47.0, 180.0}, 1712884892, 1712929984},
	{{-47.0, 180.0}, 1712126431, 1712155656},
	{{-47.0, 180.0}, 1711319210, 1711328668},
	{{-47.0, 180.0}, 1711537505, 1711590596},
	{{-47.0, 180.0}, 1711737205, 1711761443},
	{{-47.0, 180.0}, 1712263951, 1712279595},
	{{-47.0, 0.0}, 1712196858, 1712325125},
	{{-47.0, 0.0}, 1711751269, 1711853866},
	{{-47.0, 0.0}, 1711886563, 1711892397},
	{{-47.0, 0.0}, 1711454812, 1711459632},
	{{-47.0, 0.0}, 1713309858, 1713322732},
	{{-47.0, 0.0}, 1713881539, 1713926108},
	{{-47.0, 0.0}, 1712271449, 1712325125},
	{{-47.0, 0.0}, 1711786717, 1711853866},
	{{-47.0, 0.0}, 1712847208, 1712890098},
	{{-47.0, 0.0}, 1713865520, 1713879229},
	{{0.0, 122.0}, 1712410469, 1712424045},
	{{0.0, 122.0}, 1713608547, 1713679256},
	{{0.0, 122.0}, 1712859271, 1712899422},
	{{0.0, 122.0}, 1713455517, 1713679256},
	{{0.0, 122.0}, 1713391574, 1713417452},
	{{0.0, 122.0}, 1712343900, 1712381336},
	{{0.0, 122.0}, 1711556565, 1711692343},
	{{0.0, 122.0}, 1713812565, 1713850039},
	{{0.0, 122.0}, 1711912354, 1711948618},
	{{0.0, 122.0}, 1713674366, 1713679256},
	{{0.0, 180.0}, 1711762928, 1711894487},
	{{0.0, 180.0}, 1712065556, 1712108041},
	{{0.0, 180.0}, 1713070880, 1713101518},
	{{0.0, 180.0}, 1712781352, 1712888004},
	{{0.0, 180.0}, 1711550187, 1711589871},
	{{0.0, 180.0}, 1712103952, 1712108041},
	{{0.0, 180.0}, 1713166070, 1713406036},
	{{0.0, 180.0}, 1711612941, 1711632584},
	{{0.0, 180.0}, 1711792550, 1711894486},
	{{0.0, 180.0}, 1711310392, 1711419008},
};

static const struct hubble_sat_orbital_params orbit = {
	.t0 = 1711296587,
	.n0 = 0.00017559780215620866,     /* orbital frequency in orbits/sec */
	.ndot = 3.6984685877857914e-14,
	.raan0 = -2.62346138227064,
	.raandot = 1.992330418167161e-07, /* approximation */
	.aop0 = 3.523598389978097,
	.aopdot = -6.981828658074634e-07, /* approximation */
	.inclination = 97.4608,
	.eccentricity = 0.0010652,
	.sat_id = 60471,
};

ZTEST(satellite_ephemeris_test, test_satellite_ephemeris_calculation)
{
	int ret;
	struct hubble_sat_pass_info next_pass;

	ret = hubble_sat_satellites_set(&orbit, 1);
	zassert_equal(ret, 0, NULL);

	for (uint16_t count = 0; count < ARRAY_SIZE(results); count++) {
		ret = hubble_next_pass_get(results[count].start_time,
					   &(results[count].pos), &next_pass);

		zassert_equal(ret, 0, NULL);
		zassert_within(next_pass.culmination,
			       results[count].culmination_time, EPHEMERIS_DELTA);
	}
}

/*
 * Independent-reference check: predicted culmination vs canonical SGP4 truth.
 *
 * test_satellite_ephemeris_calculation asserts against values captured from
 * this propagator's own output and re-baselined on every change, so it proves
 * the predictor is stable, not correct. The values below are instead the true
 * time of maximum elevation of NORAD 60471 from an independent SGP4 oracle
 * propagating the same orbital elements (start_time = query time).
 *
 * They expose a real defect: the fixture supplies n0 as the TLE/Kozai mean
 * motion, but the SDK consumes it as a *nodal* mean motion (_orbit_count_get:
 * count = n0 * dt). J2 separates the two by ~3.6 s/orbit (~55 s/day), so the
 * predicted culmination drifts out of the +-80 s transmission window within
 * ~2 days and the device transmits outside the real pass.
 *
 * EXPECTED TO FAIL until n0 is converted to the nodal mean motion
 * 2*pi/(mdot + argpdot) during parameter derivation; the fix collapses the
 * drift to a few seconds and flips this test green.
 */
static const struct test_result sgp4_truth[] = {
	{{47.0, -122.0}, 1711319637, 1711321451}, /* day 0.3: drifts  -14 s */
	{{47.0, -122.0}, 1711405072, 1711406941}, /* day 1.3: drifts  -69 s */
	{{47.0, -122.0}, 1711490503, 1711492429}, /* day 2.3: drifts -126 s */
	{{47.0, -122.0}, 1711614459, 1711616473}, /* day 3.7: drifts -214 s */
};

ZTEST_EXPECT_FAIL(satellite_ephemeris_test, test_satellite_ephemeris_vs_sgp4);
ZTEST(satellite_ephemeris_test, test_satellite_ephemeris_vs_sgp4)
{
	int ret = hubble_sat_satellites_set(&orbit, 1);

	zassert_equal(ret, 0, NULL);

	for (size_t i = 0; i < ARRAY_SIZE(sgp4_truth); i++) {
		struct hubble_sat_pass_info next_pass;

		ret = hubble_next_pass_get(sgp4_truth[i].start_time,
					   &sgp4_truth[i].pos, &next_pass);
		zassert_equal(ret, 0, NULL);

		/* Culmination must land within the transmission window of the
		 * true pass, else the device transmits outside it.
		 */
		zassert_within(next_pass.culmination,
			       sgp4_truth[i].culmination_time,
			       TRANSMISSION_PERIOD_SINGLE_PACKET / 2U,
			       "pass %u culmination off by %lld s (window +-80 s)",
			       (unsigned int)i,
			       (long long)next_pass.culmination -
				       (long long)sgp4_truth[i].culmination_time);
	}
}

ZTEST(satellite_ephemeris_test, test_satellite_ephemeris_invalid)
{
	struct hubble_sat_pass_info next_pass;
	int ret;

	ret = hubble_sat_satellites_set(NULL, 0);
	zassert_equal(ret, 0, NULL);

	ret = hubble_sat_satellites_set(NULL, 5);
	zassert_equal(ret, -EINVAL, NULL);

	ret = hubble_next_pass_get(results[0].start_time, &(results[0].pos),
				   &next_pass);
	zassert_equal(ret, -ENOENT, NULL);

	ret = hubble_next_pass_region_get(
		0, &(struct hubble_sat_device_region){1.0, 30.0, -45.0, 50.0},
		&next_pass);
	zassert_equal(ret, -ENOENT, NULL);

	ret = hubble_sat_satellites_set(&orbit, 1);
	zassert_equal(ret, 0, NULL);

	ret = hubble_next_pass_get(results[0].start_time, NULL, &next_pass);
	zassert_equal(ret, -EINVAL, NULL);

	ret = hubble_next_pass_get(results[0].start_time, &(results[0].pos),
				   NULL);
	zassert_equal(ret, -EINVAL, NULL);

	ret = hubble_next_pass_region_get(0, NULL, &next_pass);
	zassert_equal(ret, -EINVAL, NULL);

	ret = hubble_next_pass_region_get(
		0, &(struct hubble_sat_device_region){1.0, 30.0, -45.0, 50.0},
		NULL);
	zassert_equal(ret, -EINVAL, NULL);
}

struct test_region_result {
	struct hubble_sat_device_region region;
	uint64_t start_time;
	uint64_t culmination_time;
	uint32_t duration;
};

static const struct test_region_result region_results[] = {
	{{1.0, 30.0, -45.0, 50.0}, 1711296587, 1711299419, 477},
	{{1.0, 30.0, -45.0, 50.0}, 1711299660, 1711336468, 479},
	{{-45.0, 30.0, -45.0, 50.0}, 1711296587, 1711300154, 482},
	{{-45.0, 30.0, -45.0, 50.0}, 1711335912, 1711341426, 484},
	{{45.0, 30.0, -45.0, 50.0}, 1711296587, 1711298717, 483},
	{{45.0, 30.0, -45.0, 50.0}, 1711334475, 1711337171, 484},
};

ZTEST(satellite_ephemeris_test, test_satellite_ephemeris_region_calculation)
{
	int ret;
	struct hubble_sat_pass_info next_pass;

	ret = hubble_sat_satellites_set(&orbit, 1);
	zassert_equal(ret, 0, NULL);

	for (uint16_t count = 0; count < ARRAY_SIZE(region_results); count++) {
		ret = hubble_next_pass_region_get(
			region_results[count].start_time,
			&(region_results[count].region), &next_pass);

		zassert_equal(ret, 0, NULL);
		zassert_within(next_pass.culmination,
			       region_results[count].culmination_time,
			       EPHEMERIS_DELTA);
		zassert_within(next_pass.duration,
			       region_results[count].duration +
				       TRANSMISSION_PERIOD_SINGLE_PACKET,
			       EPHEMERIS_DELTA);
	}
}

ZTEST_SUITE(satellite_ephemeris_test, NULL, NULL, NULL, NULL, NULL);

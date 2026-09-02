/* Tests for the state_records wire format: the encode/decode round trip and
   the two properties the format exists for, namely that an input has no
   header a mutation can destroy and that the per-record length is never the
   only separator, so a record list resynchronises after a byte is inserted
   or deleted. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>
#include "state_records.h"

#define TEST_MAX_RECS 16

static const uint8_t payload_a[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
static const uint8_t payload_b[] = {0x10, 0x11, 0x12};
static const uint8_t payload_c[] = {0xff, 0xfe, 0xfd, 0xfc};
static const uint8_t payload_marker[] = {0x00, STATE_REC_MARK0, STATE_REC_MARK1,
                                         0x00, 0x7f};

static size_t build_program(state_rec_t *recs) {

  state_rec_make(&recs[0], STATE_OP_OPEN, 1, 0, 0x00, payload_a,
                 (uint16_t)sizeof(payload_a));
  state_rec_make(&recs[1], STATE_OP_WRITE, 2, 1, 0x02, payload_b,
                 (uint16_t)sizeof(payload_b));
  state_rec_make(&recs[2], STATE_OP_READ, 0, 2, 0x01, NULL, 0);
  state_rec_make(&recs[3], STATE_OP_CLOSE, 2, 0, 0x00, payload_c,
                 (uint16_t)sizeof(payload_c));

  return 4;

}

static void assert_rec_equal(const state_rec_t *got, const state_rec_t *want) {

  assert_int_equal(got->opcode, want->opcode);
  assert_int_equal(got->dst, want->dst);
  assert_int_equal(got->src, want->src);
  assert_int_equal(got->flags, want->flags);
  assert_int_equal(got->len, want->len);

  if (want->len) {

    assert_memory_equal(got->payload, want->payload, want->len);

  }

}

static void test_round_trip(void **state) {

  (void)state;

  state_rec_t want[TEST_MAX_RECS], got[TEST_MAX_RECS];
  uint8_t     buf[512];
  size_t      n, len, back, i;

  n = build_program(want);
  len = state_rec_encode(want, n, buf, sizeof(buf));

  assert_int_equal(len, state_rec_encoded_len(want, n));
  assert_int_equal(buf[0], STATE_REC_MARK0);
  assert_int_equal(buf[1], STATE_REC_MARK1);

  back = state_rec_decode(buf, len, got, TEST_MAX_RECS);
  assert_int_equal(back, n);

  for (i = 0; i < n; ++i) {

    assert_rec_equal(&got[i], &want[i]);

  }

}

/* A payload may contain the sync marker: on the happy path the validated
   length hint carries the decoder past it. */

static void test_round_trip_marker_in_payload(void **state) {

  (void)state;

  state_rec_t want[2], got[TEST_MAX_RECS];
  uint8_t     buf[128];
  size_t      len, back;

  state_rec_make(&want[0], STATE_OP_OPEN, 3, 0, 0, payload_marker,
                 (uint16_t)sizeof(payload_marker));
  state_rec_make(&want[1], STATE_OP_COMMIT, 0, 3, 0, payload_a,
                 (uint16_t)sizeof(payload_a));

  len = state_rec_encode(want, 2, buf, sizeof(buf));
  back = state_rec_decode(buf, len, got, TEST_MAX_RECS);

  assert_int_equal(back, 2);
  assert_rec_equal(&got[0], &want[0]);
  assert_rec_equal(&got[1], &want[1]);

}

/* No header, no leading length, no item count: a byte glued to the front of
   the input shifts every record but destroys none of them. */

static void test_insert_at_offset_zero(void **state) {

  (void)state;

  state_rec_t want[TEST_MAX_RECS], got[TEST_MAX_RECS];
  uint8_t     buf[512], damaged[513];
  size_t      n, len, back, i;

  n = build_program(want);
  len = state_rec_encode(want, n, buf, sizeof(buf));

  damaged[0] = 0x00;
  memcpy(damaged + 1, buf, len);

  back = state_rec_decode(damaged, len + 1, got, TEST_MAX_RECS);
  assert_int_equal(back, n);

  for (i = 0; i < n; ++i) {

    assert_rec_equal(&got[i], &want[i]);

  }

}

/* A byte inserted inside the first record invalidates its length hint. The
   decoder discards the hint, rescans to the next marker, and every later
   record comes back untouched. */

static void test_insert_mid_input_resyncs(void **state) {

  (void)state;

  state_rec_t want[TEST_MAX_RECS], got[TEST_MAX_RECS];
  uint8_t     buf[512], damaged[513];
  size_t      n, len, back, at = STATE_REC_HDR + 2, i;

  n = build_program(want);
  len = state_rec_encode(want, n, buf, sizeof(buf));

  memcpy(damaged, buf, at);
  damaged[at] = 0x42;
  memcpy(damaged + at + 1, buf + at, len - at);

  back = state_rec_decode(damaged, len + 1, got, TEST_MAX_RECS);
  assert_int_equal(back, n);

  assert_int_equal(got[0].opcode, want[0].opcode);
  assert_int_equal(got[0].len, want[0].len + 1);

  for (i = 1; i < n; ++i) {

    assert_rec_equal(&got[i], &want[i]);

  }

}

static void test_delete_mid_input_resyncs(void **state) {

  (void)state;

  state_rec_t want[TEST_MAX_RECS], got[TEST_MAX_RECS];
  uint8_t     buf[512], damaged[512];
  size_t      n, len, back, at = STATE_REC_HDR + 2, i;

  n = build_program(want);
  len = state_rec_encode(want, n, buf, sizeof(buf));

  memcpy(damaged, buf, at);
  memcpy(damaged + at, buf + at + 1, len - at - 1);

  back = state_rec_decode(damaged, len - 1, got, TEST_MAX_RECS);
  assert_int_equal(back, n);

  assert_int_equal(got[0].opcode, want[0].opcode);
  assert_int_equal(got[0].len, want[0].len - 1);

  for (i = 1; i < n; ++i) {

    assert_rec_equal(&got[i], &want[i]);

  }

}

/* Bytes before the first marker are skipped rather than treated as a
   header. */

static void test_leading_garbage_skipped(void **state) {

  (void)state;

  state_rec_t want[TEST_MAX_RECS], got[TEST_MAX_RECS];
  uint8_t     buf[512], damaged[560];
  size_t      n, len, back, i;

  n = build_program(want);
  len = state_rec_encode(want, n, buf, sizeof(buf));

  memset(damaged, 0x37, 24);
  memcpy(damaged + 24, buf, len);

  back = state_rec_decode(damaged, len + 24, got, TEST_MAX_RECS);
  assert_int_equal(back, n);

  for (i = 0; i < n; ++i) {

    assert_rec_equal(&got[i], &want[i]);

  }

}

/* The encoder emits whole records only, so a capacity that cuts through a
   record drops it instead of truncating it. */

static void test_encode_stops_at_record_boundary(void **state) {

  (void)state;

  state_rec_t want[TEST_MAX_RECS];
  uint8_t     buf[512];
  size_t      n, full, cut;

  n = build_program(want);
  full = state_rec_encoded_len(want, n);

  cut = state_rec_encode(want, n, buf, full - 1);
  assert_int_equal(cut, full - (STATE_REC_HDR + want[n - 1].len));

  assert_int_equal(state_rec_encode(want, n, buf, 0), 0);
  assert_int_equal(state_rec_encode(want, n, buf, STATE_REC_HDR - 1), 0);

}

/* Every byte string has to decode to some record list without reading out of
   bounds and without exceeding max_recs. */

static void test_random_buffers_stay_in_bounds(void **state) {

  (void)state;

  uint8_t    *buf;
  state_rec_t got[TEST_MAX_RECS];
  uint32_t    rng = 0x1234abcdU;
  size_t      round;

  for (round = 0; round < 1000; ++round) {

    size_t len, i, n;

    rng = rng * 1103515245U + 12345U;
    len = (rng >> 8) % 513;

    buf = (uint8_t *)malloc(len ? len : 1);
    assert_non_null(buf);

    for (i = 0; i < len; ++i) {

      rng = rng * 1103515245U + 12345U;

      /* one byte in eight is a marker byte, so that markers and truncated
         markers actually occur */
      if (((rng >> 16) & 7) == 0) {

        buf[i] = ((rng >> 20) & 1) ? STATE_REC_MARK0 : STATE_REC_MARK1;

      } else {

        buf[i] = (uint8_t)(rng >> 16);

      }

    }

    n = state_rec_decode(buf, len, got, TEST_MAX_RECS);
    assert_true(n <= TEST_MAX_RECS);

    for (i = 0; i < n; ++i) {

      assert_true(got[i].payload >= buf);
      assert_true((size_t)(got[i].payload - buf) <= len);
      assert_true((size_t)(got[i].payload - buf) + got[i].len <= len);

    }

    /* counting without an output array must agree */
    assert_int_equal(state_rec_decode(buf, len, NULL, TEST_MAX_RECS), n);

    free(buf);

  }

}

int main(void) {

  const struct CMUnitTest tests[] = {

      cmocka_unit_test(test_round_trip),
      cmocka_unit_test(test_round_trip_marker_in_payload),
      cmocka_unit_test(test_insert_at_offset_zero),
      cmocka_unit_test(test_insert_mid_input_resyncs),
      cmocka_unit_test(test_delete_mid_input_resyncs),
      cmocka_unit_test(test_leading_garbage_skipped),
      cmocka_unit_test(test_encode_stops_at_record_boundary),
      cmocka_unit_test(test_random_buffers_stay_in_bounds),

  };

  return cmocka_run_group_tests(tests, NULL, NULL);

}


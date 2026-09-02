/*
   state_records - a resynchronising record format for stateful targets
   --------------------------------------------------------------------

   Written for AFL++.

   An input is a bare concatenation of records. There is no file header, no
   leading length and no item count, and the per-record length is a hint that
   the decoder validates against the next sync marker rather than the only
   separator. Both properties exist so that ordinary byte mutation of an
   encoded program damages one record instead of the whole input; see
   README.md for the numbers.

   This header is self contained: it needs nothing but <stdint.h>,
   <stddef.h> and <string.h>, so a target harness can decode records without
   linking or including anything from AFL++.
 */

#ifndef _STATE_RECORDS_H
#define _STATE_RECORDS_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* One record on the wire:

     offset 0   0x5a         sync marker byte 0
     offset 1   0xa5         sync marker byte 1
     offset 2   opcode   u8
     offset 3   dst slot u8
     offset 4   src slot u8
     offset 5   flags    u8
     offset 6   len      u16 little endian
     offset 8   payload[len]
 */

#define STATE_REC_MARK0 0x5a
#define STATE_REC_MARK1 0xa5
#define STATE_REC_HDR 8
#define STATE_REC_MAX_PAYLOAD 0xffff

/* The slot store the records address. dst and src are taken modulo this, so
   every byte value names a live slot and no record is ever rejected for
   naming one that does not exist. */

#define STATE_REC_SLOTS 8
#define STATE_REC_SLOT(x) ((x) & (STATE_REC_SLOTS - 1))

enum {

  STATE_OP_NOP = 0,
  STATE_OP_OPEN,                                              /* writes dst */
  STATE_OP_WRITE,                                  /* reads src, writes dst */
  STATE_OP_READ,                                               /* reads src */
  STATE_OP_DUP,                                    /* reads src, writes dst */
  STATE_OP_CLOSE,                                           /* releases dst */
  STATE_OP_COMMIT,                              /* depends on state reached */
  STATE_OP_RESET,                                    /* releases everything */
  STATE_OP_COUNT

};

typedef struct state_rec {

  uint8_t        opcode;
  uint8_t        dst;
  uint8_t        src;
  uint8_t        flags;
  uint16_t       len;
  const uint8_t *payload;

} state_rec_t;

/* True when the opcode leaves a usable value in dst, i.e. when a later record
   naming that slot as src has something to read. The mutator uses this to
   prefer slots an earlier record actually wrote. */

static inline int state_op_writes_dst(uint8_t opcode) {

  return opcode == STATE_OP_OPEN || opcode == STATE_OP_WRITE ||
         opcode == STATE_OP_DUP;

}

/* True when the opcode consumes src. */

static inline int state_op_reads_src(uint8_t opcode) {

  return opcode == STATE_OP_WRITE || opcode == STATE_OP_READ ||
         opcode == STATE_OP_DUP;

}

static inline const char *state_op_name(uint8_t opcode) {

  switch (opcode) {

    case STATE_OP_NOP:
      return "NOP";
    case STATE_OP_OPEN:
      return "OPEN";
    case STATE_OP_WRITE:
      return "WRITE";
    case STATE_OP_READ:
      return "READ";
    case STATE_OP_DUP:
      return "DUP";
    case STATE_OP_CLOSE:
      return "CLOSE";
    case STATE_OP_COMMIT:
      return "COMMIT";
    case STATE_OP_RESET:
      return "RESET";
    default:
      return "UNKNOWN";

  }

}

/* Fill in a record. The payload is not copied, the caller keeps it alive. */

static inline void state_rec_make(state_rec_t *rec, uint8_t opcode, uint8_t dst,
                                  uint8_t src, uint8_t flags,
                                  const uint8_t *payload, uint16_t len) {

  rec->opcode = opcode;
  rec->dst = dst;
  rec->src = src;
  rec->flags = flags;
  rec->len = len;
  rec->payload = payload;

}

/* Index of the first sync marker at or after from, or len when there is
   none. */

static inline size_t state_rec_scan(const uint8_t *buf, size_t len,
                                    size_t from) {

  size_t i;

  if (!buf || len < 2 || from > len - 2) { return len; }

  for (i = from; i + 2 <= len; ++i) {

    if (buf[i] == STATE_REC_MARK0 && buf[i + 1] == STATE_REC_MARK1) {

      return i;

    }

  }

  return len;

}

/* The length hint is only believed when the bytes it points at are the next
   sync marker or the end of the buffer. This is the rule that makes the
   format survive an inserted or deleted byte. */

static inline int state_rec_boundary_ok(const uint8_t *buf, size_t len,
                                        size_t end) {

  if (end == len) { return 1; }
  if (end + 2 > len) { return 0; }
  return buf[end] == STATE_REC_MARK0 && buf[end + 1] == STATE_REC_MARK1;

}

/* Decode buf into at most max_recs records and return how many were found.
   Any byte string decodes to some record list; bytes before the first marker
   are skipped, a hint that fails validation is discarded and the payload runs
   to the next marker instead. out may be NULL to count records only. */

static inline size_t state_rec_decode(const uint8_t *buf, size_t len,
                                      state_rec_t *out, size_t max_recs) {

  size_t n = 0, pos = 0;

  if (!buf || len < STATE_REC_HDR) { return 0; }

  while (n < max_recs) {

    size_t body, avail, hint, plen, next;

    pos = state_rec_scan(buf, len, pos);
    if (pos > len - STATE_REC_HDR) { break; }

    body = pos + STATE_REC_HDR;
    avail = len - body;
    hint = (size_t)buf[pos + 6] | ((size_t)buf[pos + 7] << 8);

    if (hint <= avail && state_rec_boundary_ok(buf, len, body + hint)) {

      plen = hint;

    } else {

      next = state_rec_scan(buf, len, body);
      plen = (next >= len) ? avail : next - body;
      if (plen > STATE_REC_MAX_PAYLOAD) { plen = STATE_REC_MAX_PAYLOAD; }

    }

    if (out) {

      out[n].opcode = buf[pos + 2];
      out[n].dst = buf[pos + 3];
      out[n].src = buf[pos + 4];
      out[n].flags = buf[pos + 5];
      out[n].len = (uint16_t)plen;
      out[n].payload = buf + body;

    }

    ++n;
    pos = body + plen;

  }

  return n;

}

/* Bytes state_rec_encode() needs for n records. */

static inline size_t state_rec_encoded_len(const state_rec_t *recs, size_t n) {

  size_t i, total = 0;

  if (!recs) { return 0; }

  for (i = 0; i < n; ++i) {

    total += STATE_REC_HDR + (size_t)recs[i].len;

  }

  return total;

}

/* Encode records into out and return the bytes written. Records are written
   whole: when the next one does not fit in out_cap, encoding stops and the
   result is the prefix that did fit, which is how callers honour a size
   limit without producing a truncated record. */

static inline size_t state_rec_encode(const state_rec_t *recs, size_t n,
                                      uint8_t *out, size_t out_cap) {

  size_t i, used = 0;

  if (!recs || !out) { return 0; }

  for (i = 0; i < n; ++i) {

    size_t   need = STATE_REC_HDR + (size_t)recs[i].len;
    uint8_t *p;

    if (need > out_cap - used) { break; }

    p = out + used;
    p[0] = STATE_REC_MARK0;
    p[1] = STATE_REC_MARK1;
    p[2] = recs[i].opcode;
    p[3] = recs[i].dst;
    p[4] = recs[i].src;
    p[5] = recs[i].flags;
    p[6] = (uint8_t)(recs[i].len & 0xff);
    p[7] = (uint8_t)(recs[i].len >> 8);

    if (recs[i].len && recs[i].payload) {

      memcpy(p + STATE_REC_HDR, recs[i].payload, recs[i].len);

    } else if (recs[i].len) {

      memset(p + STATE_REC_HDR, 0, recs[i].len);

    }

    used += need;

  }

  return used;

}

#endif                                                 /* !_STATE_RECORDS_H */


#ifndef _AFL_REDQUEEN_H
#define _AFL_REDQUEEN_H

#include "config.h"

#define CMP_MAP_W 65536
#define CMP_MAP_H 256

#define SHAPE_BYTES(x) (x+1)

#define CMP_TYPE_INS 0
#define CMP_TYPE_RTN 1

struct cmp_header {

  unsigned hits : 20;

  unsigned cnt : 20;
  unsigned id : 16;

  unsigned shape : 5; // from 0 to 31
  unsigned type : 1;
  
} __attribute__((packed));

struct cmp_operands {

  u64 v0;
  u64 v1;

};

struct cmpfn_operands {

  u8 v0[32];
  u8 v1[32];

};

typedef struct cmp_operands cmp_map_list[CMP_MAP_H];

struct cmp_map {

  struct cmp_header headers[CMP_MAP_W];
  struct cmp_operands log[CMP_MAP_W][CMP_MAP_H];

};

#endif

/*
   american fuzzy lop++ - comparison attributes
   ------------------------------------------------

   Copyright 2019-2026 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

   Exact LLVM comparison predicates shared by CmpLog and value profiling.
*/

#ifndef _AFL_CMP_ATTRS_H
#define _AFL_CMP_ATTRS_H

#define CMP_ATTR_FCMP_FALSE 0
#define CMP_ATTR_FCMP_OEQ 1
#define CMP_ATTR_FCMP_OGT 2
#define CMP_ATTR_FCMP_OGE 3
#define CMP_ATTR_FCMP_OLT 4
#define CMP_ATTR_FCMP_OLE 5
#define CMP_ATTR_FCMP_ONE 6
#define CMP_ATTR_FCMP_ORD 7
#define CMP_ATTR_FCMP_UNO 8
#define CMP_ATTR_FCMP_UEQ 9
#define CMP_ATTR_FCMP_UGT 10
#define CMP_ATTR_FCMP_UGE 11
#define CMP_ATTR_FCMP_ULT 12
#define CMP_ATTR_FCMP_ULE 13
#define CMP_ATTR_FCMP_UNE 14
#define CMP_ATTR_FCMP_TRUE 15
#define CMP_ATTR_ICMP_EQ 32
#define CMP_ATTR_ICMP_NE 33
#define CMP_ATTR_ICMP_UGT 34
#define CMP_ATTR_ICMP_UGE 35
#define CMP_ATTR_ICMP_ULT 36
#define CMP_ATTR_ICMP_ULE 37
#define CMP_ATTR_ICMP_SGT 38
#define CMP_ATTR_ICMP_SGE 39
#define CMP_ATTR_ICMP_SLT 40
#define CMP_ATTR_ICMP_SLE 41
#define CMP_ATTR_MOD_FLOAT 240
#define CMP_ATTR_MOD_INTEGER 241
#define CMP_ATTR_TRANSFORM 242
#define CMP_ATTR_NONE 255

#endif


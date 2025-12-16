#include "afl-fuzz.h"
#include "cJSON/cJSON.h"
#ifndef AFLPLUSPLUS_JSON_PARSER_H
#define AFLPLUSPLUS_JSON_PARSER_H

cJSON *load_json_file(u8 *automation_file);

#endif  // AFLPLUSPLUS_JSON_PARSER_H

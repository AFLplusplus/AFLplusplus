#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "cJSON/cJSON.h"
#include "afl-fuzz.h"
cJSON *load_json_file(u8 *automation_file);

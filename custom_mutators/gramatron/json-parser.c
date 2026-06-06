#include "json-parser.h"

cJSON *load_json_file(u8 *automation_file) {
  FILE *f = fopen(automation_file, "rb");
  if (!f) {
    perror("fopen");
    return NULL;
  }

  if (fseek(f, 0, SEEK_END) != 0) {
    fclose(f);
    return NULL;
  }

  long size = ftell(f);
  if (size < 0) {
    fclose(f);
    return NULL;
  }
  rewind(f);

  char *buf = malloc((size_t)size + 1);
  if (!buf) {
    fclose(f);
    return NULL;
  }

  size_t n = fread(buf, 1, (size_t)size, f);
  fclose(f);

  if (n != (size_t)size) {
    free(buf);
    return NULL;
  }

  buf[size] = '\0';

  cJSON *root = cJSON_Parse(buf);
  free(buf);

  if (!root) {
    fprintf(stderr, "[GF] JSON parse error in %s: %s\n",
            automation_file, cJSON_GetErrorPtr());
    return NULL;
  }

  return root;
}


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cJSON.h"

/* Public line-oriented parser/serializer contract; no challenge data. */
int main(void) {
  char line[65536];
  while (fgets(line, sizeof(line), stdin)) {
    size_t length = strlen(line);
    if (length == sizeof(line) - 1 && line[length - 1] != '\n')
      return 2;
    cJSON *value = cJSON_ParseWithLengthOpts(line, length + 1, NULL, 1);
    if (!value) {
      puts("invalid");
      continue;
    }
    char *text = cJSON_PrintUnformatted(value);
    if (!text) {
      cJSON_Delete(value);
      return 3;
    }
    puts(text);
    cJSON_free(text);
    cJSON_Delete(value);
  }
  return ferror(stdin) || ferror(stdout) ? 1 : 0;
}

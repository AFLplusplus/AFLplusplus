/////////////////////////////////////////////////////////////////////////
//
// Author: Mateusz Jurczyk (mjurczyk@google.com)
//
// Copyright 2019-2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

// solution: echo -ne 'The quick brown fox jumps over the lazy
// dog\xbe\xba\xfe\xca\xbe\xba\xfe\xca\xde\xc0\xad\xde\xef\xbe' | ./compcovtest

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

int main() {

  char buffer[44] = {/* zero padding */};
  fread(buffer, 1, sizeof(buffer) - 1, stdin);

  if (memcmp(&buffer[0], "The quick brown fox ", 20) != 0 ||
      strncmp(&buffer[20], "jumps over ", 11) != 0 ||
      strcmp(&buffer[31], "the lazy dog") != 0) {

    return 1;

  }

  uint64_t x = 0;
  fread(&x, sizeof(x), 1, stdin);
  if (x != 0xCAFEBABECAFEBABE) { return 2; }

  uint32_t y = 0;
  fread(&y, sizeof(y), 1, stdin);
  if (y != 0xDEADC0DE) { return 3; }

  uint16_t z = 0;
  fread(&z, sizeof(z), 1, stdin);

  switch (z) {

    case 0xBEEF:
      break;

    default:
      return 4;

  }

  printf("Puzzle solved, congrats!\n");
  abort();
  return 0;

}


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

int main(int argc, char** argv)
{
  assert(argc == 2);
  char* fn = argv[1];
  FILE* f = fopen(fn, "r");
  fseek(f, 0, SEEK_END);
  int l = ftell(f);
  int ll = (l + 3) / 4;
  fseek(f, 0, SEEK_SET);
  char *b = malloc(ll * 4);
  memset(b, 0, ll * 4);
  fread(b, l, 1, f);
  fclose(f);
  uint32_t *u = (uint32_t *)b;
  printf("var payload = [");
  for (int i = 0; i < ll; i++)
  {
    printf("%u", *u++);
    if (i < (ll - 1)) printf(",");
  }
  printf("];\n");
  free(b);
}

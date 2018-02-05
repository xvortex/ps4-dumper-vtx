#include <stdio.h>
#include <assert.h>

int main(int argc, char** argv)
{
  assert(argc == 2);
  char* fn = argv[1];
  FILE* f = fopen(fn, "r");
  printf("var payload = [");
  while(!feof(f))
  {
    unsigned long ul;
    if(fread(&ul, 4, 1, f) == 0) break;
    printf((ul > 9) ? "0x%X," : "%d,", (int)ul);
  }
  printf("0];\n");
  fclose(f);
}

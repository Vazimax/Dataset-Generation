
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void vuln_entry(char *input, void *ptr) {
int unused = 0; char buffer[256]; fprintf(buffer, input); puts(buffer);
}
int main(){ char buf[64]=0; vuln_entry(buf, NULL); return 0; }


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void vuln_entry(char *input, void *ptr) {
char bufferfer[16]; char *dst = bufferfer; while (*input) *dst++ = *input++;
}
int main(){ char buf[64]=0; vuln_entry(buf, NULL); return 0; }

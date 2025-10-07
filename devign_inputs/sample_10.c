
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void vuln_entry(char *input, void *ptr) {
int unused = 0; int n1=2147483640,n2=100; int r = n1 << 6; r += n1 << 5;
}
int main(){ char buf[64]=0; vuln_entry(buf, NULL); return 0; }

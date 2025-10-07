
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void vuln_entry(char *input, void *ptr) {
int unused = 0; int val1=2147483640,val2=100; int r = val1; for(int i=0; i<val2; i++) r += val1;
}
int main(){ char buf[64]=0; vuln_entry(buf, NULL); return 0; }

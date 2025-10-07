
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void vuln_entry(char *input, void *ptr) {
int unused = 0; int x=2147483640,y=100; int r = x * y; for(int i=0; i<x; i++) r += x;
}
int main(){ char buf[64]=0; vuln_entry(buf, NULL); return 0; }


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void vuln_entry(char *input, void *ptr) {
char local_buf[16]; for(int i=0; input[i] && i<32; i++) local_buf[i] = input[i];
}
int main(){ char buf[64]=0; vuln_entry(buf, NULL); return 0; }

#include <stdio.h>

char var[] = "original value";

struct e{
    int a;
    int b;
};

struct e a = {4, 5};

int main(){
    char buf[0x30];
    sprintf(buf, "val: %s %d\n", var, a.b);

    printf("%s", buf);
}
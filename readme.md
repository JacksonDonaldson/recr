# recr
reverse engineer's c (rec) is a variant of C designed for second-stage compilation.

The rec recompiler (recr) takes as input:
- An already compiled binary (the source binary)
- A list of symbols found in that binary
- Some number of .rec source files

And produces a new binary (the patched binary) that contains the modifications specified in the .rec files.

The reverse engineer's c recompiler (recr) is designed to work with ELF and raw source binaries.

Valid symbol sources are: binaries with debug information or a ghidra repository.

## A Minimal Example

<details open>
<summary><code>source.c</code></summary>

```c
#include <stdio.h>
char global_dat[] = "original data";
int main(){
    printf("my data: %s\n", global_dat);
}
```      
</details>

<details open>
<summary><code>patch.rec</code></summary>

```c
char @global_dat[] = "REPLACED"
@main(char * msg, ...){
    printf("I get control before main()\n");
    main();
    printf("and after\n");
}
```
</details>

```
gcc source.c -o source
recr source patch.rec -o patched
echo "source result:"
./source
echo "patched result:"
./patched
```
```
source result:
my data: original data
patched result:
I get control before main()
my data: REPLACED
and after
```

## Additions to C
Prepending @ to a function in the source binary hooks that function. Both the hooked and hooking function can be called from .rec code.

Prepending @ to a global variable in the source binary replaces that variable with your new value. The original is no longer available.

Functions, types, and structs from the source binary can be called and used at any time; no need to #include anything.

The following types are automatically defined:
- `byte` --> `unsigned char`
- `uint` --> `unsigned int`
- `ushort` --> `unsigned short`
- `ulong` --> `unsigned long`
- `ulonglong` --> `unsigned long long`

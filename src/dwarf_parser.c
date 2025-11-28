#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <string.h>

#include <dwarf.h>
#include <libdwarf.h>

//#include "libdwarf_private.h"

typedef unsigned char byte;

void print_out_all_functions(Dwarf_Debug dbg){
    
}

void parse_DWARF(char * name, char* output){
    char path_out[2000];
    Dwarf_Debug dbg = 0;
    Dwarf_Error error = 0;
    Dwarf_Handler errhand = 0;
    Dwarf_Ptr errarg = 0;

    int res = dwarf_init_path(name, path_out, sizeof(path_out), DW_GROUPNUMBER_ANY, errhand, errarg, &dbg, &error);
    if(res == DW_DLV_ERROR){
        fprintf(stderr, "Error doing initial dwarf parsing");
        dwarf_dealloc_error(dbg, error);
        dwarf_finish(dbg);
        exit(1);
    }
    else if(res == DW_DLV_NO_ENTRY){
        fprintf(stderr, "No such file found");
        exit(1);
    }
    print_out_all_functions(dbg);
}


void usage(){
    fprintf(stdout, "./dwarf_parser [ELF file] [out file]");
    exit(1);
}
int main(int argc, char** argv){
    if(argc != 3){
        usage();
    }
    parse_DWARF(argv[1], argv[2]);

}
#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <string.h>

#include <dwarf.h>
#include <libdwarf.h>

//#include "libdwarf_private.h"

typedef unsigned char byte;

//precondition: die is a DW_TAG_subprogram
//prints name of subprogram by parsing die
void print_function_name(Dwarf_Debug dbg, Dwarf_Die die, Dwarf_Error * errp){
    char *name = NULL;
    int res = dwarf_diename(die, &name, errp);
    if(res == DW_DLV_OK){
        printf(": %s\n", name);
        dwarf_dealloc(dbg, name, DW_DLA_STRING);
    } else if(res == DW_DLV_NO_ENTRY){
        printf(": <no name>\n");
    } else {
        fprintf(stderr, "Error in dwarf_diename\n");
        if(errp && *errp){
            dwarf_dealloc_error(dbg, *errp);
        }
    }
}

int examine_die(Dwarf_Debug dbg, Dwarf_Die die, Dwarf_Error * errp){
    int res = 0;
    Dwarf_Half tag;
    res = dwarf_tag(die, &tag, errp);

    if(tag == DW_TAG_subprogram){
        printf("found function");
        print_function_name(dbg, die, errp);
    }



    return res;
}
int recursively_examine_die(Dwarf_Debug dbg, Dwarf_Die in_die, int is_info, int in_level, Dwarf_Error * errp){
    int res = DW_DLV_ERROR;
    Dwarf_Die cur_die = in_die;
    Dwarf_Die child = 0, sib_die = 0;

    res = examine_die(dbg, cur_die, errp);

    while(1){
        res = dwarf_child(cur_die, &child, errp);
        if( res == DW_DLV_ERROR ){
            fprintf(stderr, "error in dwarf_child");
            exit(1);
        }
        if(res == DW_DLV_OK){
            recursively_examine_die(dbg, child, is_info, in_level + 1, errp);
            dwarf_dealloc(dbg, child, DW_DLA_DIE);
            child = 0;
        }
        res = dwarf_siblingof_b(dbg, cur_die, is_info, &sib_die, errp);
        if(res == DW_DLV_ERROR){
            fprintf(stderr, "error in dwarf_siblingsof_b");
            exit(1);
        }
        if(res == DW_DLV_NO_ENTRY){
            break;
        }
        if(cur_die != in_die){
            dwarf_dealloc(dbg, cur_die, DW_DLA_DIE);
        }
        cur_die = sib_die;
        res = examine_die(dbg, cur_die, errp);
    }

    return res;
}
int print_out_all_functions(Dwarf_Debug dbg){
    Dwarf_Unsigned cu_header_length, abbrev_offset, next_cu_header, typeoffset;
    Dwarf_Half version_stamp, address_size, offset_size, extension_size, header_cu_type;
    Dwarf_Sig8 signature;
    Dwarf_Bool is_info = 1;
    Dwarf_Error error;
    Dwarf_Die cu_die;
    int res = 0;

    while(1){
        //grab next cu header -> it's in cu_die
        res = dwarf_next_cu_header_e(dbg,is_info,
                &cu_die,
                &cu_header_length,
                &version_stamp, &abbrev_offset,
                &address_size, &offset_size,
                &extension_size,&signature,
                &typeoffset, &next_cu_header,
                &header_cu_type,&error);
        if (res == DW_DLV_ERROR) {
            return res;
        }
        if (res == DW_DLV_NO_ENTRY) {
            if (is_info == 1) {
                /*  Done with .debug_info, now check for
                    .debug_types. */
                is_info = 0;
                continue;
            }
            /*  No more CUs to read! Never found
                what we were looking for in either
                .debug_info or .debug_types. */
            return res;
        }
        recursively_examine_die(dbg, cu_die, is_info,0, &error);

        printf("loop\n");


    }
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
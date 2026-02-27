//
//  main.cpp
//  suspender
//
//  Created by Dora Orak on 23.02.2026.
//

#include <stdio.h>
#include <IOKit/IOKitLib.h>
#include <simplePatchFinder.h>
#include <libkextrw.h>
#include <mach-o/loader.h>
#include <sys/kernel_types.h>

typedef struct {
    uint64_t buffer_start;
    uint64_t buffer_end;
    uint64_t original_vmaddr;
    char* name;
} section_mapping_t;

section_mapping_t* mappings = NULL;
size_t mapping_count = 0;

uint64_t find_fileset_header(uint64_t start_addr);
uint64_t fileset_find_kext_addr(void *kc_base, const char *kext_id);

typedef void (^segment_block_t)(struct segment_command_64 *segment, bool *stop);
typedef void (^section_block_t)(struct section_64 *section, bool *stop);
    
void for_each_segment(struct mach_header_64 *header, segment_block_t block);
void for_each_section(struct mach_header_64 *header, section_block_t block);

uint64_t kernelBase = 0;
uint64_t k_slide = 0;

void fix_kernel_addresses(struct mach_header_64* mh){
    for_each_section(mh, ^(struct section_64* sect, bool* stop){
        if (((sect->flags & SECTION_ATTRIBUTES) & (S_ATTR_SOME_INSTRUCTIONS)) || ((sect->flags & SECTION_ATTRIBUTES) & S_ATTR_PURE_INSTRUCTIONS)) {
            
            void* buffer = calloc(1, sect->size);
            
            mappings = (section_mapping_t*)realloc(mappings, sizeof(section_mapping_t) * (mapping_count + 1));
            
            mappings[mapping_count].buffer_start = (uint64_t)buffer;
            mappings[mapping_count].buffer_end = (uint64_t)buffer + sect->size;
            mappings[mapping_count].original_vmaddr = sect->addr;
            
            char tmp[64];
            
            snprintf(tmp, sizeof(tmp), "%s,%s",
                     sect->segname,
                     sect->sectname);
            
            mappings[mapping_count].name = strdup(tmp);
            mapping_count++;
            
            __unused int e = kreadbuf((sect->addr), buffer, sect->size);
            sect->addr = (uint64_t)buffer;
            
            printf("done for %s %s\n", sect->segname, sect->sectname);
            printf("buffer: %llx\n", sect->addr);
        }
    });
}

uint64_t translate(uint64_t result)
{
    for (size_t i = 0; i < mapping_count; i++) {

        if (result >= mappings[i].buffer_start && result <  mappings[i].buffer_end) {
            uint64_t offset = result - mappings[i].buffer_start;
            uint64_t kernel = mappings[i].original_vmaddr + offset;
           // printf("result: %llx\tslid: %llx\tunslid: %llx\tstart: %llx\tname: %s\n", result, kernel, kernel - k_slide, mappings[i].buffer_start, mappings[i].name);
            return kernel;
        }
    }

    return 0; // not found
}

int main(int argc, const char * argv[]) {
    
    if (argc < 2){
        printf("usage: %s <pid>", argv[0]);
        return -1;
    }
    
    kextrw_init();
    kernelBase = get_kernel_base();
    k_slide = kslide(0);
    
    struct mach_header_64 header = {};
    kreadbuf(kernelBase, &header, sizeof(struct mach_header_64));
    
    uint64_t* buffer = (uint64_t*)malloc(header.sizeofcmds);
    kreadbuf(kernelBase, buffer, header.sizeofcmds);
    
    struct mach_header_64* kernel_mh = (struct mach_header_64*)buffer;
    
    fix_kernel_addresses(kernel_mh);
    
    size_t outCount = 0;
    uint64_t* results = NULL;
    
    char* targetSeq[] = {"pacibsp", "sub", "stp", "stp", "stp", "stp", "stp", "stp", "add", "cbz w0"}; //proc_find
    results = image_findInstructions(kernel_mh, targetSeq, 10, &outCount);
    
    uint64_t procfind = translate(*results);
    free(results);
        
    pid_t targetPid = atoi(argv[1]);
    
    uint64_t args[] = {(uint64_t)targetPid};
    uint64_t ret = kcall(procfind, args, 1);
    
    proc_t proc = (proc_t)ret;
    
    char* targetSeq_2[] = {"pacibsp", "stp", "stp", "stp", "add", "mov x19 x0", "mrs x20 tpidr_el1", "ldr", "add", "str"}; //kauth_cred_proc_ref
    results = image_findInstructions(kernel_mh, targetSeq_2, 10, &outCount);
    
    uint64_t kauthcredprocref = translate(*results);
    free(results);
    
    uint64_t args2[] = {(uint64_t)proc};
    ret = kcall(kauthcredprocref, args2, 1);
    
    uint64_t cred = ret;
    
    //now we should find sandbox kext
    
    uint64_t fileset = find_fileset_header(kernelBase);
    kreadbuf(fileset, &header, sizeof(struct mach_header_64));
    
    buffer = (uint64_t*)malloc(header.sizeofcmds);
    kreadbuf(fileset, buffer, header.sizeofcmds);
    
    struct mach_header_64* kernelcache_mh = (struct mach_header_64*)buffer;
    
    uint64_t sandboxKext = fileset_find_kext_addr(kernelcache_mh, "com.apple.security.sandbox");
    kreadbuf(sandboxKext, &header, sizeof(struct mach_header_64));
    
    buffer = (uint64_t*)malloc(header.sizeofcmds);
    kreadbuf(sandboxKext, buffer, header.sizeofcmds);
    
    struct mach_header_64* sandbox_mh = (struct mach_header_64*)buffer;
    fix_kernel_addresses(sandbox_mh);
    
    char* targetSeq_3[] = {"pacibsp", "stp", "stp", "add", "cbz x0", "adrp", "ldr"}; //label_get_sandbox
    results = image_findInstructions(sandbox_mh, targetSeq_3, 7, &outCount);
    
    uint64_t label_get_sandbox = translate(*results);
    free(results);
        
    uint64_t labelptr = kreadptr(cred + 0x78);
    
    uint64_t args3[] = {labelptr};
    ret = kcall(label_get_sandbox, args3, 1);
    
    uint64_t sandbox = ret;
    
    char* targetSeq_4[] = {"pacibsp", "sub", "stp", "stp", "add", "mov", "mov", "strb", "adrp"}; //sandbox_suspend
    results = image_findInstructions(sandbox_mh, targetSeq_4, 9, &outCount);
    
    uint64_t sandbox_suspend = translate(*results);
    free(results);
    
    uint64_t args4[] = {sandbox};
    ret = kcall(sandbox_suspend, args4, 1);
    
    if(ret != 0){
        printf("succesfully disabled sandbox for pid: %d", targetPid);
    }

    kextrw_deinit();
}

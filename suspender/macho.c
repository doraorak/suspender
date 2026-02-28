//
//  macho.c
//  suspender
//
//  Created by Dora Orak on 24.02.2026.
//

#include <mach-o/loader.h>
#include <libkextrw.h>

uint64_t find_fileset_header(uint64_t start_addr) {
    uint64_t addr = start_addr & ~(PAGE_SIZE - 1);

    while (addr > PAGE_SIZE) {
        addr -= PAGE_SIZE;

        uint32_t magic = kread32(addr);
        if (magic != MH_MAGIC_64)
            continue;

        struct mach_header_64 hdr;
        kreadbuf(addr, &hdr, sizeof(hdr));

        if (hdr.filetype == MH_FILESET)
            return addr;
    }

    return 0;
}

uint64_t fileset_find_kext_addr(void *kc_base, const char *kext_id) {
    struct mach_header_64 *mh = (struct mach_header_64 *)kc_base;

    if (mh->magic != MH_MAGIC_64 || mh->filetype != MH_FILESET) {
        return 0;
    }

    struct load_command *lc = (struct load_command *)((uint8_t *)mh + sizeof(struct mach_header_64));

    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (lc->cmd == LC_FILESET_ENTRY) {
            struct fileset_entry_command *fsec = (struct fileset_entry_command *)lc;

            const char *entry_name = (const char *)fsec + fsec->entry_id.offset;

            if (strcmp(entry_name, kext_id) == 0) {
                return fsec->vmaddr;
            }
        }

        lc = (struct load_command *)((uint8_t *)lc + lc->cmdsize);
    }

    return 0;
}

typedef void (^section_block_t)(struct section_64 *section, bool *stop);

void for_each_section(struct mach_header_64 *header, section_block_t block) {
    if (!header || !block) return;

    bool stop = false;

    const uint8_t *cursor = (const uint8_t *)header +
                            (header->magic == MH_MAGIC_64 || header->magic == MH_CIGAM_64
                             ? sizeof(struct mach_header_64)
                             : sizeof(struct mach_header));

    for (uint32_t i = 0; i < header->ncmds; i++) {
        const struct load_command *loadCmd = (const struct load_command *)cursor;

        if (header->magic == MH_MAGIC_64 || header->magic == MH_CIGAM_64) {
            if (loadCmd->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg =
                    (const struct segment_command_64 *)loadCmd;

                const struct section_64 *section =
                    (const struct section_64 *)((const uint8_t *)seg +
                                                sizeof(struct segment_command_64));

                for (uint32_t j = 0; j < seg->nsects; j++) {
                    block((struct section_64 *)section, &stop);
                    if (stop) return;
                    section++;
                }
            }
        } else {
            if (loadCmd->cmd == LC_SEGMENT) {
                const struct segment_command *seg =
                    (const struct segment_command *)loadCmd;

                const struct section *section =
                    (const struct section *)((const uint8_t *)seg +
                                             sizeof(struct segment_command));

                for (uint32_t j = 0; j < seg->nsects; j++) {
                    block(section, &stop);
                    if (stop) return;
                    section++;
                }
            }
        }

        cursor += loadCmd->cmdsize;
    }
}



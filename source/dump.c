#include "ps4.h"
#include "defines.h"
#include "debug.h"
#include "dump.h"
#include "main.h"
#include "elf64.h"
#include "unpfs.h"
#include "unpkg.h"

#define TRUE 1
#define FALSE 0

extern int run;

typedef struct {
    int index;
    uint64_t fileoff;
    size_t bufsz;
    size_t filesz;
    int enc;
} SegmentBufInfo;

void print_phdr(Elf64_Phdr *phdr) {
    printfsocket("=================================\n");
    printfsocket("     p_type %08x\n", phdr->p_type);
    printfsocket("     p_flags %08x\n", phdr->p_flags);
    printfsocket("     p_offset %016llx\n", phdr->p_offset);
    printfsocket("     p_vaddr %016llx\n", phdr->p_vaddr);
    printfsocket("     p_paddr %016llx\n", phdr->p_paddr);
    printfsocket("     p_filesz %016llx\n", phdr->p_filesz);
    printfsocket("     p_memsz %016llx\n", phdr->p_memsz);
    printfsocket("     p_align %016llx\n", phdr->p_align);
}

#define SELF_MAGIC	0x1D3D154F
#define ELF_MAGIC	0x464C457F

int is_self(const char *fn)
{
    struct stat st;
    int res = 0;
    int fd = open(fn, O_RDONLY, 0);
    if (fd != -1) {
        stat(fn, &st);
        void *addr = mmap(0, 0x4000, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
        if (addr != MAP_FAILED) {
            printfsocket("mmap %s : %p\n", fn, addr);
            if (st.st_size >= 4)
            {
                uint32_t selfMagic = *(uint32_t*)((uint8_t*)addr + 0x00);
                if (selfMagic == SELF_MAGIC)
                {
                    uint16_t snum = *(uint16_t*)((uint8_t*)addr + 0x18);
                    if (st.st_size >= (0x20 + snum * 0x20 + 4))
                    {
                        uint32_t elfMagic = *(uint32_t*)((uint8_t*)addr + 0x20 + snum * 0x20);
                        if ((selfMagic == SELF_MAGIC) && (elfMagic == ELF_MAGIC))
                            res = 1;
                    }
                }
            }
            munmap(addr, 0x4000);
        }
        else {
            printfsocket("mmap file %s err : %s\n", fn, strerror(errno));
        }
        close(fd);
    }
    else {
        printfsocket("open %s err : %s\n", fn, strerror(errno));
    }

    return res;
}

#define DECRYPT_SIZE 0x100000

bool read_decrypt_segment(int fd, uint64_t index, uint64_t offset, size_t size, uint8_t *out)
{
    uint8_t *outPtr = out;
    uint64_t outSize = size;
    uint64_t realOffset = (index << 32) | offset;
    while (outSize > 0)
    {
        size_t bytes = (outSize > DECRYPT_SIZE) ? DECRYPT_SIZE : outSize;
        uint8_t *addr = (uint8_t*)mmap(0, bytes, PROT_READ, MAP_PRIVATE | 0x80000, fd, realOffset);
        if (addr != MAP_FAILED)
        {
            memcpy(outPtr, addr, bytes);
            munmap(addr, bytes);
        }
        else
        {
            printfsocket("mmap segment [%d] err(%d) : %s\n", index, errno, strerror(errno));
            return FALSE;
        }
        outPtr += bytes;
        outSize -= bytes;
        realOffset += bytes;
    }
    return TRUE;
}

int is_segment_in_other_segment(Elf64_Phdr *phdr, int index, Elf64_Phdr *phdrs, int num) {
    for (int i = 0; i < num; i += 1) {
        Elf64_Phdr *p = &phdrs[i];
        if (i != index) {
            if (p->p_filesz > 0) {
                printfsocket("offset : %016x,  toffset : %016x\n", phdr->p_offset, p->p_offset);
                printfsocket("offset : %016x,  toffset + size : %016x\n", phdr->p_offset, p->p_offset + p->p_filesz);
                if ((phdr->p_offset >= p->p_offset) && ((phdr->p_offset + phdr->p_filesz) <= (p->p_offset + p->p_filesz))) {
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}

SegmentBufInfo *parse_phdr(Elf64_Phdr *phdrs, int num, int *segBufNum) {
    printfsocket("segment num : %d\n", num);
    SegmentBufInfo *infos = (SegmentBufInfo *)malloc(sizeof(SegmentBufInfo) * num);
    int segindex = 0;
    for (int i = 0; i < num; i += 1) {
        Elf64_Phdr *phdr = &phdrs[i];
        print_phdr(phdr);

        if (phdr->p_filesz > 0) {
            if ((!is_segment_in_other_segment(phdr, i, phdrs, num)) || (phdr->p_type == 0x6fffff01)) {
                SegmentBufInfo *info = &infos[segindex];
                segindex += 1;
                info->index = i;
                info->bufsz = (phdr->p_filesz + (phdr->p_align - 1)) & (~(phdr->p_align - 1));
                info->filesz = phdr->p_filesz;
                info->fileoff = phdr->p_offset;
                info->enc = (phdr->p_type != 0x6fffff01) ? TRUE : FALSE;

                printfsocket("seg buf info %d -->\n", segindex);
                printfsocket("    index : %d\n    bufsz : 0x%016llX\n", info->index, info->bufsz);
                printfsocket("    filesz : 0x%016llX\n    fileoff : 0x%016llX\n", info->filesz, info->fileoff);
            }
        }
    }
    *segBufNum = segindex;
    return infos;
}

void do_dump(char *saveFile, int fd, SegmentBufInfo *segBufs, int segBufNum, Elf64_Ehdr *ehdr) {
    int sf = open(saveFile, O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (sf != -1) {
        size_t elfsz = 0x40 + ehdr->e_phnum * sizeof(Elf64_Phdr);
        printfsocket("elf header + phdr size : 0x%08X\n", elfsz);
        write(sf, ehdr, elfsz);

        for (int i = 0; i < segBufNum; i += 1) {
            printfsocket("sbuf index : %d, offset : 0x%016x, bufsz : 0x%016x, filesz : 0x%016x, enc : %d\n", segBufs[i].index, segBufs[i].fileoff, segBufs[i].bufsz, segBufs[i].filesz, segBufs[i].enc);
            uint8_t *buf = (uint8_t*)malloc(segBufs[i].bufsz);
            memset(buf, 0, segBufs[i].bufsz);
            if (segBufs[i].enc)
            {
                if (read_decrypt_segment(fd, segBufs[i].index, 0, segBufs[i].filesz, buf)) {
                    lseek(sf, segBufs[i].fileoff, SEEK_SET);
                    write(sf, buf, segBufs[i].bufsz);
                }
            }
            else
            {
                lseek(fd, -segBufs[i].filesz, SEEK_END);
                read(fd, buf, segBufs[i].filesz);
                lseek(sf, segBufs[i].fileoff, SEEK_SET);
                write(sf, buf, segBufs[i].filesz);
            }
            free(buf);
        }
        close(sf);
    }
    else {
        printfsocket("open %s err : %s\n", saveFile, strerror(errno));
    }
}

void decrypt_and_dump_self(char *selfFile, char *saveFile) {
    int fd = open(selfFile, O_RDONLY, 0);
    if (fd != -1) {
        void *addr = mmap(0, 0x4000, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
        if (addr != MAP_FAILED) {
            printfsocket("mmap %s : %p\n", selfFile, addr);

            uint16_t snum = *(uint16_t*)((uint8_t*)addr + 0x18);
            Elf64_Ehdr *ehdr = (Elf64_Ehdr *)((uint8_t*)addr + 0x20 + snum * 0x20);
            printfsocket("ehdr : %p\n", ehdr);

            // shdr fix
            ehdr->e_shoff = ehdr->e_shentsize = ehdr->e_shnum = ehdr->e_shstrndx = 0;

            Elf64_Phdr *phdrs = (Elf64_Phdr *)((uint8_t *)ehdr + 0x40);
            printfsocket("phdrs : %p\n", phdrs);

            int segBufNum = 0;
            SegmentBufInfo *segBufs = parse_phdr(phdrs, ehdr->e_phnum, &segBufNum);
            do_dump(saveFile, fd, segBufs, segBufNum, ehdr);
            printfsocket("dump completed\n");

            free(segBufs);
            munmap(addr, 0x4000);
        }
        else {
            printfsocket("mmap file %s err : %s\n", selfFile, strerror(errno));
        }
        close(fd);
    }
    else {
        printfsocket("open %s err : %s\n", selfFile, strerror(errno));
    }
}

#define BUFFER_SIZE 65536

static void copy_file(char *sourcefile, char* destfile)
{
    int fdin = open(sourcefile, O_RDONLY, 0);
    if (fdin != -1)
    {
        int fdout = open(destfile, O_WRONLY | O_CREAT | O_TRUNC, 0777);
        if (fdout != -1)
        {
            size_t bytes;
            char *buffer = malloc(BUFFER_SIZE);
            if (buffer != NULL)
            {
                while (0 < (bytes = read(fdin, buffer, BUFFER_SIZE)))
                    write(fdout, buffer, bytes);
                    free(buffer);
            }
            close(fdout);
        }
        else {
            printfsocket("write %s err : %s\n", destfile, strerror(errno));
        }
        close(fdin);
    }
    else {
        printfsocket("open %s err : %s\n", sourcefile, strerror(errno));
    }
}

static void touch_file(char* destfile)
{
    int fd = open(destfile, O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (fd != -1) close(fd);
}

static void decrypt_dir(char *sourcedir, char* destdir)
{
    DIR *dir;
    struct dirent *dp;
    struct stat info;
    char src_path[1024], dst_path[1024];

    dir = opendir(sourcedir);
    if (!dir)
        return;

    mkdir(destdir, 0777);

    while ((dp = readdir(dir)) != NULL)
    {
        if (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, ".."))
        {
            // do nothing (straight logic)
        }
        else
        {
            sprintf(src_path, "%s/%s", sourcedir, dp->d_name);
            sprintf(dst_path, "%s/%s", destdir  , dp->d_name);
            if (!stat(src_path, &info))
            {
                if (S_ISDIR(info.st_mode))
                {
                    decrypt_dir(src_path, dst_path);
                }
                else
                if (S_ISREG(info.st_mode))
                {
                    if (is_self(src_path))
                        decrypt_and_dump_self(src_path, dst_path);
                }
            }
        }
    }
    closedir(dir);
}

int wait_for_game(char *title_id)
{
    int res = 0;

    DIR *dir;
    struct dirent *dp;

    dir = opendir("/mnt/sandbox/pfsmnt");
    if (!dir)
        return 0;

    while ((dp = readdir(dir)) != NULL)
    {
        if (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, ".."))
        {
            // do nothing (straight logic)
        }
        else
        {
            if (strstr(dp->d_name, "-app0") != NULL)
            {
                sscanf(dp->d_name, "%[^-]", title_id);
                res = 1;
                break;
            }
        }
    }
    closedir(dir);

    return res;
}

int wait_for_bdcopy(char *title_id)
{
    char path[256];
    char *buf;
    size_t filelen, progress;

    sprintf(path, "/system_data/playgo/%s/bdcopy.pbm", title_id);
    FILE *pbm = fopen(path, "rb");
    if (!pbm) return 100;

    fseek(pbm, 0, SEEK_END);
    filelen = ftell(pbm);
    fseek(pbm, 0, SEEK_SET);

    buf = malloc(filelen);

    fread(buf, sizeof(char), filelen, pbm);
    fclose(pbm);

    progress = 0;
    for (int i = 0x100; i < filelen; i++)
    {
        if (buf [i]) progress++;
    }

    free(buf);

    return (progress * 100 / (filelen - 0x100));
}

int wait_for_usb(char *usb_name, char *usb_path)
{
    int fd = open("/mnt/usb0/.probe", O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (fd != -1)
    {
        close(fd);
        unlink("/mnt/usb0/.probe");
        sprintf(usb_name, "%s", "USB0");
        sprintf(usb_path, "%s", "/mnt/usb0");
        return 1;
    }
    return 0;
}

int file_exists(char *fname)
{
    FILE *file = fopen(fname, "rb");
    if (file)
    {
        fclose(file);
        return 1;
    }
    return 0;
}

void dump_game(char *title_id, char *usb_path)
{
    char base_path[64];
    char src_path[64];
    char dst_file[64];
    char dst_app[64];
    char dst_pat[64];
    char dump_sem[64];
    char comp_sem[64];

    sprintf(base_path, "%s/%s", usb_path, title_id);

    sprintf(dump_sem, "%s.dumping", base_path);
    sprintf(comp_sem, "%s.complete", base_path);

    unlink(comp_sem);
    touch_file(dump_sem);

    if (config.split)
    {
        sprintf(dst_app, "%s-app", base_path);
        sprintf(dst_pat, "%s-patch", base_path);
        if (config.split & SPLIT_APP)
            mkdir(dst_app, 0777);
        if (config.split & SPLIT_PATCH)
            mkdir(dst_pat, 0777);
    }
    else
    {
        sprintf(dst_app, "%s", base_path);
        sprintf(dst_pat, "%s", base_path);
        mkdir(base_path, 0777);
    }

    if ((!config.split) || (config.split & SPLIT_APP))
    {
        sprintf(src_path, "/user/app/%s/app.pkg", title_id);
        notify("Extracting app package...");
        unpkg(src_path, dst_app);
        sprintf(src_path, "/system_data/priv/appmeta/%s/nptitle.dat", title_id);
        sprintf(dst_file, "%s/sce_sys/nptitle.dat", dst_app);
        copy_file(src_path, dst_file);
        sprintf(src_path, "/system_data/priv/appmeta/%s/npbind.dat", title_id);
        sprintf(dst_file, "%s/sce_sys/npbind.dat", dst_app);
        copy_file(src_path, dst_file);
    }

    if ((!config.split) || (config.split & SPLIT_PATCH))
    {
        sprintf(src_path, "/user/patch/%s/patch.pkg", title_id);
        if (file_exists(src_path))
        {
            if (config.split)
                notify("Extracting patch package...");
            else
                notify("Merging patch package...");
            unpkg(src_path, dst_pat);
            sprintf(src_path, "/system_data/priv/appmeta/%s/nptitle.dat", title_id);
            sprintf(dst_file, "%s/sce_sys/nptitle.dat", dst_pat);
            copy_file(src_path, dst_file);
            sprintf(src_path, "/system_data/priv/appmeta/%s/npbind.dat", title_id);
            sprintf(dst_file, "%s/sce_sys/npbind.dat", dst_pat);
            copy_file(src_path, dst_file);
        }
    }

    if ((!config.split) || (config.split & SPLIT_APP))
    {
        sprintf(src_path, "/mnt/sandbox/pfsmnt/%s-app0-nest/pfs_image.dat", title_id);
        notify("Extracting app image...");
        unpfs(src_path, dst_app);
    }

    if ((!config.split) || (config.split & SPLIT_PATCH))
    {
        sprintf(src_path, "/mnt/sandbox/pfsmnt/%s-patch0-nest/pfs_image.dat", title_id);
        if (file_exists(src_path))
        {
            if (config.split)
                notify("Extracting patch image...");
            else
                notify("Applying patch...");
            unpfs(src_path, dst_pat);
        }
    }

    if ((!config.split) || (config.split & SPLIT_APP))
    {
        sprintf(src_path, "/mnt/sandbox/pfsmnt/%s-app0", title_id);
        notify("Decrypting selfs...");
        decrypt_dir(src_path, dst_app);
    }

    if ((!config.split) || (config.split & SPLIT_PATCH))
    {
        sprintf(src_path, "/mnt/sandbox/pfsmnt/%s-patch0", title_id);
        if (file_exists(src_path))
        {
            notify("Decrypting patch...");
            decrypt_dir(src_path, dst_pat);
        }
    }

    unlink(dump_sem);
    touch_file(comp_sem);
}

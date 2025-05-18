#include "afl/config.h"
#include "afl/common.h"
#include "afl/instrumentation.h"

#include "io/channel-file.h"
#include "migration/qemu-file.h"
#include "migration/savevm.h"
#include "sysemu/runstate.h"
#include "migration/global_state.h"
#include "qemu/userfaultfd.h"

#define PAGE_SIZE   4096

static char *temp_file_reg;
static int temp_fd_reg;

#ifdef UFFD_SNAPSHOT
    static uint8_t *temp_map_ram;
#endif
#ifndef SHARED_SNAPSHOT
static char *temp_file_ram;
#endif
static int temp_fd_ram;

#ifdef UFFD_SNAPSHOT
static int uffd_fd;
static uint64_t *bitmap;
static size_t size_bitmap;

static void *handler(void *arg) {
    afl_t *afl = (afl_t *)arg;
    struct uffd_msg uffd_msg;
    ssize_t res;
    uint64_t offset;

    uint8_t *sram_mem = memory_region_get_ram_ptr(afl->arch.ram_mr);

    while (true) {
        res = uffd_read_events(uffd_fd, &uffd_msg, 1);

        if (res) {
            offset = ((uint64_t)uffd_msg.arg.pagefault.address - (uint64_t)sram_mem);
            bitmap[offset / (PAGE_SIZE * 64)] |= 1 << (((offset % (PAGE_SIZE * 64)) / PAGE_SIZE));

            if (uffd_change_protection(uffd_fd, (void *)uffd_msg.arg.pagefault.address, PAGE_SIZE, false, false)) {
                fprintf(stderr, "failed to change protection mode unset\n");
                exit(EXIT_FAILURE);
            }
        }
    }

    return NULL;
}
#endif

#ifdef SHARED_SNAPSHOT
static void snapshot_shared_create(afl_t *afl) {
    temp_fd_ram = shm_open(SHARED_SNAPSHOT_NAME, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);

    if (temp_fd_ram < 0) {
        fprintf(stderr, "can't create shared snapshot SHM\n");
        exit(EXIT_FAILURE);
    }
}
#endif

void afl_init_snapshot(afl_t *afl) {
    temp_file_reg = g_strdup_printf("%s/vmst.reg.XXXXXX", g_get_tmp_dir());
    temp_fd_reg = mkostemp(temp_file_reg, O_RDWR | O_CREAT | O_TRUNC);

#ifdef SHARED_SNAPSHOT
    temp_fd_ram = shm_open(SHARED_SNAPSHOT_NAME, O_RDONLY, S_IRUSR | S_IWUSR);
    
    if (temp_fd_ram < 0)
        snapshot_shared_create(afl);
#else
    temp_file_ram = g_strdup_printf("%s/vmst.ram.XXXXXX", g_get_tmp_dir());
    temp_fd_ram = mkostemp(temp_file_ram, O_RDWR | O_CREAT | O_TRUNC);
#endif

#ifdef UFFD_SNAPSHOT
    uffd_fd = uffd_create_fd(UFFD_FEATURE_PAGEFAULT_FLAG_WP, true);

    if (uffd_fd < 0) {
        fprintf(stderr, "failed to create uffd\n");
        exit(EXIT_FAILURE);
    }
#endif
}

void afl_snapshot_cleanup(afl_t *afl) {
#ifdef SHARED_SNAPSHOT
    shm_unlink(SHARED_SNAPSHOT_NAME);
#endif
}

void afl_save_ram(afl_t *afl)
{
    uint8_t *sram_mem = memory_region_get_ram_ptr(afl->arch.ram_mr);
    size_t sram_size = memory_region_size(afl->arch.ram_mr);

    if (ftruncate(temp_fd_ram, sram_size)) {
        fprintf(stderr, "failed to ftruncate temp_fd_ram to %zu bytes\n", sram_size);
        exit(EXIT_FAILURE);
    }

    char *map = mmap(0, sram_size, PROT_READ | PROT_WRITE, MAP_SHARED, temp_fd_ram, 0);

    memcpy(map, sram_mem, sram_size);
    msync(map, sram_size, MS_SYNC);
    
    munmap(map, sram_size);
    close(temp_fd_ram);

#ifdef SHARED_SNAPSHOT
    temp_fd_ram = shm_open(SHARED_SNAPSHOT_NAME, O_RDONLY, S_IRUSR | S_IWUSR);
#else
    temp_fd_ram = open((const char *)temp_file_ram, O_RDONLY);
#ifdef UFFD_SNAPSHOT
    temp_map_ram = mmap(0, sram_size, PROT_READ, MAP_SHARED, temp_fd_ram, 0);
#endif
#endif

#ifdef UFFD_SNAPSHOT
    pthread_t uffd_thread;

    size_bitmap = (sram_size / PAGE_SIZE / 64) ? (sram_size / PAGE_SIZE / 64) : 1;
    bitmap = malloc(size_bitmap * sizeof(uint64_t));
    memset(bitmap, 0, size_bitmap * sizeof(uint64_t));

    if (uffd_register_memory(uffd_fd, sram_mem,
                sram_size, UFFDIO_REGISTER_MODE_WP, NULL)) {
        fprintf(stderr, "failed to register memory to uffd\n"); 
        exit(EXIT_FAILURE);
    }

    if (uffd_change_protection(uffd_fd, sram_mem, sram_size, true, false)) {
            fprintf(stderr, "failed to change protection mode set\n");
            exit(EXIT_FAILURE);
    }

    pthread_create(&uffd_thread, NULL, handler, afl);  
#endif

    afl_load_ram(afl);
}

void afl_load_ram(afl_t *afl)
{
    uint8_t *sram_mem = memory_region_get_ram_ptr(afl->arch.ram_mr);
    size_t sram_size = memory_region_size(afl->arch.ram_mr);

#ifdef UFFD_SNAPSHOT
    uint64_t offset;

    for (uint64_t i = 0; i < size_bitmap; i++) {
        for (uint64_t j = 0; j < 64; j++) {
            if (bitmap[i] & ((uint64_t)1 << j)) {
                offset = i * PAGE_SIZE * 64 + j * PAGE_SIZE;
                memcpy((void *)(sram_mem + offset), (void *)(temp_map_ram + offset), PAGE_SIZE);
            }
        }
    }

    /* Optional, reset bitmap and protection bit */
    if (!UFFD_SNAPSHOT_SNOWBALL) {
        memset(bitmap, 0, size_bitmap * sizeof(uint64_t));

        if (uffd_change_protection(uffd_fd, sram_mem, sram_size, true, false)) {
            fprintf(stderr, "failed to change protection mode set\n");
            exit(EXIT_FAILURE);
        }
    }
#else
    if (munmap(sram_mem, sram_size) == -1) {
        fprintf(stderr, "failed to munmap the ram snapshot\n");
        exit(EXIT_FAILURE);
    }
   if (mmap(sram_mem, sram_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED, temp_fd_ram, 0) == (void *)-1) {  
        fprintf(stderr, "failed to mmap the ram snapshot\n");
        exit(EXIT_FAILURE);
    }

#endif
}

void afl_save_reg(afl_t *afl) 
{
    int fd;
    QIOChannel *ioc;
    QEMUFile *f;

    fd = dup(temp_fd_reg);
    lseek(fd, 0, SEEK_SET);
    if (ftruncate(fd, 0))
        fprintf(stderr, "failed to ftruncate qemu file\n");

    ioc = QIO_CHANNEL(qio_channel_file_new_fd(fd));
    f = qemu_file_new_output(ioc);
    object_unref(OBJECT(ioc));

    global_state_store();
    vm_stop(RUN_STATE_SAVE_VM);

    qemu_save_device_state(f);

    qemu_fclose(f);
}

void afl_load_reg(afl_t *afl) 
{
    int fd;
    QIOChannel *ioc;
    QEMUFile *f;

    fd = dup(temp_fd_reg);
    lseek(fd, 8, SEEK_SET);
    ioc = QIO_CHANNEL(qio_channel_file_new_fd(fd));
    f = qemu_file_new_input(ioc);
    object_unref(OBJECT(ioc));

    qemu_system_reset(SHUTDOWN_CAUSE_NONE);

    qemu_load_device_state(f);
    
    qemu_fclose(f);
}
#include "afl/config.h"
#include "afl/common.h"

#include "io/channel-file.h"
#include "migration/qemu-file.h"
#include "migration/savevm.h"

static char *temp_file_reg;
static int temp_fd_reg;

static char *temp_file_ram;
static int temp_fd_ram;

void afl_init_snapshot(afl_t *afl) {
    temp_file_reg = g_strdup_printf("%s/vmst.reg.XXXXXX", g_get_tmp_dir());
    temp_fd_reg = mkostemp(temp_file_reg, O_RDWR | O_CREAT | O_TRUNC);

    temp_file_ram = g_strdup_printf("%s/vmst.ram.XXXXXX", g_get_tmp_dir());
    temp_fd_ram = mkostemp(temp_file_ram, O_RDWR | O_CREAT | O_TRUNC);
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

    temp_fd_ram = open((const char *)temp_file_ram, O_RDONLY);

    afl_load_ram(afl);
}

void afl_load_ram(afl_t *afl)
{
    uint8_t *sram_mem = memory_region_get_ram_ptr(afl->arch.ram_mr);
    size_t sram_size = memory_region_size(afl->arch.ram_mr);

    munmap(sram_mem, sram_size);
    mmap(sram_mem, sram_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED, temp_fd_ram, 0);  
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
    qemu_save_device_state(f);
    qemu_fclose(f);
}

void afl_load_reg(afl_t *afl) 
{
    int fd;
    QIOChannel *ioc;
    QEMUFile *f;

    fd = dup(temp_fd_reg);
    lseek(fd, 0, SEEK_SET);
    ioc = QIO_CHANNEL(qio_channel_file_new_fd(fd));
    f = qemu_file_new_input(ioc);
    object_unref(OBJECT(ioc));
    qemu_load_device_state(f);
    qemu_fclose(f);
}
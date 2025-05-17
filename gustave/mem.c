#include "afl/config.h"
#include "afl/common.h"
#include "afl/instrumentation.h"

#include <sys/shm.h>
#include "sysemu/runstate.h"

uint8_t *mem_bitmap;

static int flt_bitmap_init(afl_t *afl)
{
    target_ulong (*ranges)[2] = NULL;
    uint8_t      *mm = mem_bitmap;
    const char   *fname = afl->config.qemu.mm_ranges;
    struct stat  st;
    size_t       i, nr;
    int          fd;

    if (stat(fname, &st) < 0) {
        fprintf(stderr, "can't stat %s\n", fname);
        return -1;
    }

    fd = open(fname, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "can't open %s\n", fname);
        return -1;
    }

    ranges = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if ((void*)ranges == MAP_FAILED) {
        fprintf(stderr, "can't mmap filter ranges\n");
        close(fd);
        return -1;
    }

    nr = st.st_size / FLT_RNG_ENTRY_SZ;
    for (i = 0 ; i < nr ; i++) {
        target_ulong s = ranges[i][0];
        target_ulong e = ranges[i][1];

        target_ulong sq = s / 8;
        target_ulong sr = s % 8;

        target_ulong eq = e / 8;
        target_ulong er = e % 8;

        if (sq == eq) {
            while (sr <= er) { mm[sq] |= (1 << sr++); }
        } else {
            while (sr < 8)   { mm[sq] |= (1 << sr++); }
            sq++;
            while (sq < eq)  { mm[sq++] = 0xff; }
            sr = 0;
            while (sr <= er) { mm[sq] |= (1 << sr++); }
        }
    }

    munmap(ranges, st.st_size);
    close(fd);
    return 0;
}

/*
 * Creates a shared memory object for several AFL instances of the
 * full VM memory space, to speed-up memory filtering.
 */
static void flt_bitmap_create(afl_t *afl)
{
    int fd = shm_open(FILTER_BITMAP_NAME, O_RDWR|O_CREAT, S_IRUSR|S_IWUSR);
    if (fd < 0) {
        fprintf(stderr, "can't create filter bitmap SHM\n");
        exit(EXIT_FAILURE);
    }

    if (ftruncate(fd, FILTER_BITMAP_SIZE) < 0) {
        fprintf(stderr, "can't resize filter bitmap SHM\n");
        goto __shm_create_failure;
    }

    void *mm = mmap(NULL, FILTER_BITMAP_SIZE,
                    PROT_READ|PROT_WRITE,
                    MAP_SHARED, fd, 0);

    if (mm == MAP_FAILED) {
        fprintf(stderr, "can't mmap(RW) filter SHM\n");
        goto __shm_create_failure;
    }

    mem_bitmap = (uint8_t*)mm;

    if (flt_bitmap_init(afl) < 0)
        goto __shm_create_failure;

    return;

__shm_create_failure:
    shm_unlink(FILTER_BITMAP_NAME);
    fprintf(stderr, "can't finalize filter bitmap SHM\n");
    exit(EXIT_FAILURE);
}

void afl_init_mem_bitmap(afl_t *afl)
{
    int fd = shm_open(FILTER_BITMAP_NAME, O_RDONLY, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        flt_bitmap_create(afl);
        return;
    }

    /* up-and-running filter bitmap, just attach */
    void *mm = mmap(NULL, FILTER_BITMAP_SIZE,
                    PROT_READ, MAP_SHARED, fd, 0);

    if (mm == MAP_FAILED) {
        fprintf(stderr, "can't mmap(RO) filter SHM\n");
        exit(EXIT_FAILURE);
    }

    mem_bitmap = (uint8_t*)mm;
}

void afl_bitmap_cleanup(afl_t *afl) {
    shm_unlink(FILTER_BITMAP_NAME);
}
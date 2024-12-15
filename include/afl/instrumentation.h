#ifndef AFL_INSTRUMENTATION_H
#define AFL_INSTRUMENTATION_H

#define AFL_QEMU_NOT_ZERO

#define FILTER_BITMAP_NAME "/GUSTAVE.BITMAP"
#define FILTER_BITMAP_SIZE (1 << 29)
#define FLT_RNG_ENTRY_SZ   (sizeof(target_ulong) * 2)

#define MAP_SIZE_POW2 16
#define MAP_SIZE (1U << MAP_SIZE_POW2)

#define FORKSRV_CONTROL_FD 198
#define FORKSRV_STATUS_FD 199

#define FS_OPT_ENABLED 0x80000001
#define FS_OPT_MAPSIZE 0x40000000
#define FS_OPT_SNAPSHOT 0x20000000
#define FS_OPT_SHDMEM_FUZZ 0x01000000
// FS_OPT_MAX_MAPSIZE is 8388608 = 0x800000 = 2^23 = 1 << 22
#define FS_OPT_MAX_MAPSIZE ((0x00fffffeU >> 1) + 1)

#define FS_OPT_GET_MAPSIZE(x) (((x & 0x00fffffe) >> 1) + 1)
#define FS_OPT_SET_MAPSIZE(x) \
  (x <= 1 || x > FS_OPT_MAX_MAPSIZE ? 0 : ((x - 1) << 1))

#if (defined(__x86_64__) || defined(__i386__)) && defined(AFL_QEMU_NOT_ZERO)
  #define INC_AFL_AREA(loc)           \
    asm volatile(                     \
        "addb $1, (%0, %1, 1)\n"      \
        "adcb $0, (%0, %1, 1)\n"      \
        : /* no out */                \
        : "r"(afl_area_ptr), "r"(loc) \
        : "memory", "eax")
#else
  #define INC_AFL_AREA(loc) afl_area_ptr[loc]++
#endif

extern __thread uint64_t afl_prev_loc;
extern unsigned char *afl_area_ptr;
extern unsigned int afl_inst_rms;

extern uint8_t *mem_bitmap;

void oracle_illegal_memory_access(void);
#endif
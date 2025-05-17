#ifndef AFL_INSTRUMENTATION_H
#define AFL_INSTRUMENTATION_H

#define SHARED_SNAPSHOT_NAME  "/GUSTAVE.SNAPSHOT"

#define FILTER_BITMAP_NAME "/GUSTAVE.BITMAP"
#define FILTER_BITMAP_SIZE (1 << 29)
#define FLT_RNG_ENTRY_SZ   (sizeof(target_ulong) * 2)

#define MAP_SIZE_POW2 16
#define MAP_SIZE (1U << MAP_SIZE_POW2)

#define FORKSRV_CONTROL_FD 198
#define FORKSRV_STATUS_FD 199

/* New Forkserver */
#define FORKSERVER_VERSION 0x41464c01
#define FS_NEW_VERSION_MIN 1
#define FS_NEW_VERSION_MAX 1
#define FS_NEW_ERROR 0xeffe0000
#define FS_NEW_OPT_MAPSIZE 0x00000001      // parameter: 32 bit value
#define FS_NEW_OPT_SHDMEM_FUZZ 0x00000002  // parameter: none
#define FS_NEW_OPT_AUTODICT 0x00000800     // autodictionary data

/* Reporting options */
#define FS_OPT_ENABLED 0x80000001
#define FS_OPT_MAPSIZE 0x40000000
#define FS_OPT_SNAPSHOT 0x20000000
#define FS_OPT_AUTODICT 0x10000000
#define FS_OPT_SHDMEM_FUZZ 0x01000000
#define FS_OPT_NEWCMPLOG 0x02000000
#define FS_OPT_OLD_AFLPP_WORKAROUND 0x0f000000
// FS_OPT_MAX_MAPSIZE is 8388608 = 0x800000 = 2^23 = 1 << 23
#define FS_OPT_MAX_MAPSIZE ((0x00fffffeU >> 1) + 1)
#define FS_OPT_GET_MAPSIZE(x) (((x & 0x00fffffe) >> 1) + 1)
#define FS_OPT_SET_MAPSIZE(x) \
  (x <= 1 || x > FS_OPT_MAX_MAPSIZE ? 0 : ((x - 1) << 1))

#define AFL_QEMU_NOT_ZERO

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
extern bool fuzzing_started;

#endif
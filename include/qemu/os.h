#ifndef __OS_H__
#define __OS_H__

#include "qemu/os_syscall.h"
#include <stdint.h>
#include <sys/types.h>

/********* Generator operating mode ************/

/*
 * inputs are interpreted as syscall id, followed by syscall
 * arguments. Arguments which are user memory pointers are ensured to
 * be valid and afl fuzzed values are inserted into these user memory
 * areas
 */

//#define GENERATOR_RAND_ID_ARGS_VALID_USERMEM

/*
 * Use given ID and random arguments values from afl fuzzed input
 */

#define GENERATOR_RAND_ID_RAND_ARGS */

typedef struct {
   int         os_syscall_id;
   const char *os_syscall_name;
   uint8_t     os_syscall_nbargs;
   uint32_t    os_param_sizes[3];
   int         enabled;

} os_syscall_generator_info_t;

#define OS_SYSCALLS_NR sizeof(os_syscall_table)/sizeof(os_syscall_table[0])
static os_syscall_generator_info_t __attribute__((unused)) os_syscall_table[] = {
   {OS_SYSCALL_FORK,
    "OS_SYSCALL_FORK",
    0,
    {},
    1,
   }
};

ssize_t os_afl_inject_test_case(afl_t *afl, uint8_t *in, size_t in_size);
ssize_t os_afl_gen_code(uint8_t *in, size_t in_size, uint8_t* out, size_t out_max);

#endif
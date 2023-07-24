#include "qemu/afl.h"
#include "qemu/os.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef AFL_GENCODE
#ifdef GENERATOR_RAND_ID_RAND_ARGS
static size_t generate_rand_id_rand_args(
    uint8_t *in, size_t in_size,
    uint8_t* out, size_t out_max)
{
    size_t in_cur = 0;
    size_t out_cur = 0;
    int f_id;

    uint32_t value = 0;
    uint32_t mask = 0;

    if (in_size == 0) {
        return 0;
    }

    while (in_cur < in_size && out_cur < out_max) {

        if (in[in_cur] >= OS_SYSCALLS_NR) {
#ifdef AFL_GENCODE_DEBUG
            debug("Warning: Invalid ID in input file; parsing stopped\n");
#endif
            return out_cur;
        }

        f_id = in[in_cur++];

#ifdef AFL_GENCODE_DEBUG
        debug("f_id 0x%x\n", f_id);
#endif

        if ((in_cur == in_size) ||
            (in_cur + 4 * os_syscall_table[f_id].os_syscall_nbargs > in_size + 1)) {
#ifdef AFL_GENCODE_DEBUG
            debug("Warning: Invalid argument size in input file; parsing stopped\n");
#endif
            return out_cur;
        }

        // correct syscall but disabled in generator configuration
        // silently drop its generation
        if (!os_syscall_table[f_id].enabled) {
#ifdef AFL_GENCODE_DEBUG
            debug("Warning: Dropped syscall 0x%x\n", f_id);
#endif
            in_cur += 4 * os_syscall_table[f_id].os_syscall_nbargs;
            continue;
        }

        for (int i = 0; i < os_syscall_table[f_id].os_syscall_nbargs; i++) {
            value = *(uint32_t *)(in + in_cur);
            in_cur += 4;

            // lui aX, YYYY
            mask = (value & 0xfffff000) >> 12;
            mask = mask << 5;
            mask ^= (12 + i) & 0b11111;
            mask = mask << 7;
            mask ^= 0b0110111;

            out[out_cur + 0] = (mask & 0xff000000) >> 24;
            out[out_cur + 1] = (mask & 0x00ff0000) >> 16;
            out[out_cur + 2] = (mask & 0x0000ff00) >> 8;
            out[out_cur + 3] = mask & 0x000000ff;
            out_cur += 4;

            // addi aX, aX, YYYY
            mask = value & 0x00000fff;
            mask = mask << 5;
            mask ^= (12 + i) & 0b11111;
            mask = mask << 3;
            mask ^= 0b000;
            mask = mask << 5;
            mask ^= (12 + i) & 0b11111;
            mask = mask << 7;
            mask ^= 0b0010011;

            out[out_cur + 0] = (mask & 0xff000000) >> 24;
            out[out_cur + 1] = (mask & 0x00ff0000) >> 16;
            out[out_cur + 2] = (mask & 0x0000ff00) >> 8;
            out[out_cur + 3] = mask & 0x000000ff;
            out_cur += 4;
        }

        // xor a1, a1
        mask = 0b0000000;
        mask = mask << 5;
        mask ^= 11;
        mask = mask << 5;
        mask ^= 11;
        mask = mask << 3;
        mask ^= 0b100;
        mask = mask << 5;
        mask ^= 11;
        mask = mask << 7;
        mask ^= 0b0110011;

        out[out_cur + 0] = (mask & 0xff000000) >> 24;
        out[out_cur + 1] = (mask & 0x00ff0000) >> 16;
        out[out_cur + 2] = (mask & 0x0000ff00) >> 8;
        out[out_cur + 3] = mask & 0x000000ff;
        out_cur += 4;

        // addi a1, 0xXXXX
        mask = os_syscall_table[f_id].os_syscall_id & 0x00000fff;
        mask = mask << 5;
        mask ^= 11;
        mask = mask << 3; 
        mask ^= 0b000;
        mask = mask << 5;
        mask ^= 11;
        mask = mask << 7;
        mask ^= 0b0010011;

        out[out_cur + 0] = (mask & 0xff000000) >> 24;
        out[out_cur + 1] = (mask & 0x00ff0000) >> 16;
        out[out_cur + 2] = (mask & 0x0000ff00) >> 8;
        out[out_cur + 3] = mask & 0x000000ff;
        out_cur += 4;

        // ecall
        mask = 0x73;

        out[out_cur + 0] = (mask & 0xff000000) >> 24;
        out[out_cur + 1] = (mask & 0x00ff0000) >> 16;
        out[out_cur + 2] = (mask & 0x0000ff00) >> 8;
        out[out_cur + 3] = mask & 0x000000ff;
        out_cur += 4;
    }

    return out_cur;
}
#endif

#if defined(GENERATOR_RAND_ID_ARGS_VALID_USERMEM)
static uint32_t compute_expected_stack_size(uint8_t syscall_id) {
    uint32_t size = 0;
    for (int i = 0; i < os_syscall_table[syscall_id].os_syscall_nbargs; i++) {
        size += (os_syscall_table[syscall_id]).os_param_sizes[i];
    }
    return size;
}

static size_t generate_rand_but_valid_memory_areas(
    uint8_t *in, size_t in_size,
    uint8_t* out, size_t out_max)
{
    size_t in_cur = 0;
    size_t out_cur = 0;
    int f_id;

    uint32_t value = 0;
    uint32_t mask = 0;
    
    if (in_size == 0) {
        return 0;
    }

    while (in_cur < in_size && out_cur < out_max) {

        if (in[in_cur] >= OS_SYSCALLS_NR) {
#ifdef AFL_GENCODE_DEBUG
            afl_debug("Warning: Invalid ID in input file; parsing stopped\n");
#endif
            return out_cur;
        }

        f_id = in[in_cur++];

#ifdef AFL_GENCODE_DEBUG
        afl_debug("f_id 0x%x\n", f_id);
#endif

        if ((in_cur == in_size) ||
            (in_cur + 4 * os_syscall_table[f_id].os_syscall_nbargs > in_size + 1)) {
#ifdef AFL_GENCODE_DEBUG
            afl_debug("Warning: Invalid argument size in input file; parsing stopped\n");
#endif
            return out_cur;
        }

        // correct syscall but disabled in generator configuration
        // silently drop its generation
        if (!os_syscall_table[f_id].enabled) {
#ifdef AFL_GENCODE_DEBUG
            afl_debug("Warning: Dropped syscall 0x%x\n", f_id);
#endif
            in_cur += 4 * os_syscall_table[f_id].os_syscall_nbargs;
            continue;
        }

        for (int i = 0; i < (os_syscall_table[f_id]).os_syscall_nbargs; i++) {
            if ((os_syscall_table[f_id]).os_param_sizes[i] == 0) {
                // The argument is not a "pointer"

                value = *(uint32_t *)(in + in_cur);
                in_cur += 4;

                // lui aX, YYYY
                mask = (value & 0xfffff000) >> 12;
                mask = mask << 5;
                mask ^= (12 + i) & 0b11111;
                mask = mask << 7;
                mask ^= 0b0110111;

                out[out_cur + 0] = (mask & 0xff000000) >> 24;
                out[out_cur + 1] = (mask & 0x00ff0000) >> 16;
                out[out_cur + 2] = (mask & 0x0000ff00) >> 8;
                out[out_cur + 3] = mask & 0x000000ff;
                out_cur += 4;

                // addi aX, aX, YYYY
                mask = value & 0x00000fff;
                mask = mask << 5;
                mask ^= (12 + i) & 0b11111;
                mask = mask << 3;
                mask ^= 0b000;
                mask = mask << 5;
                mask ^= (12 + i) & 0b11111;
                mask = mask << 7;
                mask ^= 0b0010011;

                out[out_cur + 0] = (mask & 0xff000000) >> 24;
                out[out_cur + 1] = (mask & 0x00ff0000) >> 16;
                out[out_cur + 2] = (mask & 0x0000ff00) >> 8;
                out[out_cur + 3] = mask & 0x000000ff;
                out_cur += 4;
            } else {
                // The argument is a "pointer"

                // addi sp, sp, -YYYY
                mask = (-(os_syscall_table[f_id]).os_param_sizes[i]) & 0x00000fff;
                mask = mask << 5;
                mask ^= 2;
                mask = mask << 3;
                mask ^= 0b000;
                mask = mask << 5;
                mask ^= 2;
                mask = mask << 7;
                mask ^= 0b0010011;

                out[out_cur + 0] = (mask & 0xff000000) >> 24;
                out[out_cur + 1] = (mask & 0x00ff0000) >> 16;
                out[out_cur + 2] = (mask & 0x0000ff00) >> 8;
                out[out_cur + 3] = mask & 0x000000ff;
                out_cur += 4;

                for (int j = 0; j < (os_syscall_table[f_id]).os_param_sizes[i]; j += 4) {
                    value = *(uint32_t *)(in + in_cur);
                    in_cur += 4;

                    // lui t1, YYYY
                    mask = (value & 0xfffff000) >> 12;
                    mask = mask << 5;
                    mask ^= 6;
                    mask = mask << 7;
                    mask ^= 0b0110111;

                    out[out_cur + 0] = (mask & 0xff000000) >> 24;
                    out[out_cur + 1] = (mask & 0x00ff0000) >> 16;
                    out[out_cur + 2] = (mask & 0x0000ff00) >> 8;
                    out[out_cur + 3] = mask & 0x000000ff;
                    out_cur += 4;

                    // addi t1, t1, YYYY
                    mask = value & 0x00000fff;
                    mask = mask << 5;
                    mask ^= 6;
                    mask = mask << 3;
                    mask ^= 0b000;
                    mask = mask << 5;
                    mask ^= 6;
                    mask = mask << 7;
                    mask ^= 0b0010011;

                    out[out_cur + 0] = (mask & 0xff000000) >> 24;
                    out[out_cur + 1] = (mask & 0x00ff0000) >> 16;
                    out[out_cur + 2] = (mask & 0x0000ff00) >> 8;
                    out[out_cur + 3] = mask & 0x000000ff;
                    out_cur += 4;

                    // sd t1, j(sp)
                    mask = j & 0b111111100000;
                    mask = mask << 5;
                    mask ^= 6;
                    mask = mask << 5;
                    mask ^= 0;
                    mask = mask << 3;
                    mask ^= 0b011;
                    mask = mask << 5;
                    mask ^= j & 0b000000011111;
                    mask = mask << 7;
                    mask ^= 0b0100011;

                    out[out_cur + 0] = (mask & 0xff000000) >> 24;
                    out[out_cur + 1] = (mask & 0x00ff0000) >> 16;
                    out[out_cur + 2] = (mask & 0x0000ff00) >> 8;
                    out[out_cur + 3] = mask & 0x000000ff;
                    out_cur += 4;
                }

                // xor ai, ai
                mask = 0b0000000;
                mask = mask << 5;
                mask ^= (12 + i) & 0b11111;
                mask = mask << 5;
                mask ^= (12 + i) & 0b11111;
                mask = mask << 3;
                mask ^= 0b100;
                mask = mask << 5;
                mask ^= (12 + i) & 0b11111;
                mask = mask << 7;
                mask ^= 0b0110011;

                out[out_cur + 0] = (mask & 0xff000000) >> 24;
                out[out_cur + 1] = (mask & 0x00ff0000) >> 16;
                out[out_cur + 2] = (mask & 0x0000ff00) >> 8;
                out[out_cur + 3] = mask & 0x000000ff;
                out_cur += 4;

                // add sp, zero, ai
                mask = 0b0000000;
                mask = mask << 5;
                mask ^= 2;
                mask = mask << 5;
                mask ^= 0;
                mask = mask << 3;
                mask ^= 0b000;
                mask = mask << 5;
                mask ^= (12 + i) & 0b11111;
                mask = mask << 7;
                mask ^= 0b0110011;

                out[out_cur + 0] = (mask & 0xff000000) >> 24;
                out[out_cur + 1] = (mask & 0x00ff0000) >> 16;
                out[out_cur + 2] = (mask & 0x0000ff00) >> 8;
                out[out_cur + 3] = mask & 0x000000ff;
                out_cur += 4;
            }
            
        }

        // xor a1, a1
        mask = 0b0000000;
        mask = mask << 5;
        mask ^= 11;
        mask = mask << 5;
        mask ^= 11;
        mask = mask << 3;
        mask ^= 0b100;
        mask = mask << 5;
        mask ^= 11;
        mask = mask << 7;
        mask ^= 0b0110011;

        out[out_cur + 0] = (mask & 0xff000000) >> 24;
        out[out_cur + 1] = (mask & 0x00ff0000) >> 16;
        out[out_cur + 2] = (mask & 0x0000ff00) >> 8;
        out[out_cur + 3] = mask & 0x000000ff;
        out_cur += 4;

        // addi a1, 0xXXXX
        mask = os_syscall_table[f_id].os_syscall_id & 0x00000fff;
        mask = mask << 5;
        mask ^= 11;
        mask = mask << 3; 
        mask ^= 0b000;
        mask = mask << 5;
        mask ^= 11;
        mask = mask << 7;
        mask ^= 0b0010011;

        out[out_cur + 0] = (mask & 0xff000000) >> 24;
        out[out_cur + 1] = (mask & 0x00ff0000) >> 16;
        out[out_cur + 2] = (mask & 0x0000ff00) >> 8;
        out[out_cur + 3] = mask & 0x000000ff;
        out_cur += 4;

        // ecall
        mask = 0x73;

        out[out_cur + 0] = (mask & 0xff000000) >> 24;
        out[out_cur + 1] = (mask & 0x00ff0000) >> 16;
        out[out_cur + 2] = (mask & 0x0000ff00) >> 8;
        out[out_cur + 3] = mask & 0x000000ff;
        out_cur += 4;

        if (compute_expected_stack_size(f_id) != 0) {
            // addi sp, 0xXXXX
            mask = compute_expected_stack_size(f_id) & 0xfff;
            mask = mask << 5;
            mask ^= 2;
            mask = mask << 3; 
            mask ^= 0b000;
            mask = mask << 5;
            mask ^= 2;
            mask = mask << 7;
            mask ^= 0b0010011;

            out[out_cur + 0] = (mask & 0xff000000) >> 24;
            out[out_cur + 1] = (mask & 0x00ff0000) >> 16;
            out[out_cur + 2] = (mask & 0x0000ff00) >> 8;
            out[out_cur + 3] = mask & 0x000000ff;
            out_cur += 4;
        }
    }
    return out_cur;
}
#endif

ssize_t os_afl_gen_code(uint8_t *in, size_t in_size, uint8_t* out, size_t out_max)
{
#if defined(GENERATOR_RAND_ID_RAND_ARGS)
    generate_rand_id_rand_args(in, in_size, out, out_max);
#elif defined(GENERATOR_RAND_ID_ARGS_VALID_USERMEM)
    generate_rand_but_valid_memory_areas(in, in_size, out, out_max);
#endif
    return in_size;
}

#else // ! GENCODE

/*
 * No code injection variant (simple), only arguments.
 *
 * Generate a single system call based on given input. The R3 register
 * is fuzzed on a byte provided by AFL. No need to fuzz the complete
 * 32 bits range, as we know the kernel already checks for that. It
 * also speeds up AFL to succeed generating enough data to execute a
 * system call.
 */
ssize_t os_afl_inject_test_case(afl_t *afl, uint8_t *in, size_t in_size)
{
    os_syscall_generator_info_t *sys;
    uint8_t  id;
    size_t   in_cur = 0;

    if (in_size < 1) {
        return 0;
    }

    id = in[in_cur++];
    if (id >= OS_SYSCALLS_NR)
        return 0;

    /* convert AFL byte to real (sparse) OS syscall number */
    sys = &os_syscall_table[id];
    if(!sys->enabled)
        return 0;

#ifdef AFL_GENCODE_DEBUG
    afl_debug("syscall [%d:%s]\n", sys->os_syscall_id, sys->os_syscall_name);
#endif

    CPURISCVState *env  = &afl->arch.cpu->env;
    uint32_t      *args = (uint32_t*)&in[in_cur];
    int            reg  = xA0;

    while (reg < xA4 && (in_size - in_cur) >= sizeof(uint32_t)) {
        env->gpr[reg++] = *args++;
        in_cur += sizeof(uint32_t);
    }

    /* the syscall insn is already present in the VM partition code */
    return 4;
}

#endif // GENCODE
#include "afl/common.h"

size_t afl_inject_test_case(afl_t *afl)
{
    CPUARMState *env = &afl->arch.cpu->env;
    uint32_t *args = (uint32_t *)afl->shared_buf;
    uint32_t  args_len = *afl->shared_buf_len / sizeof(uint32_t);
    int i = 0;

    while (i < args_len && i < 7) {      
        env->regs[i] = args[i];
        i++;
    }

    return i;
}
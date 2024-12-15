
#include "afl/common.h"

#include "exec/cpu-all.h"
#include "sysemu/hw_accel.h"
/*
 * Initial breakpoint (EP_FUZZ) should not be of SW type because
 * memory will be overwritten while the kernel is loaded by its boot
 * loader.
 */
void afl_remove_breakpoint(afl_t *afl, uint64_t pc)
{
    CPUState *cpu = CPU(afl->arch.cpu);
    cpu_breakpoint_remove(cpu, pc, BP_AFL);
}

void afl_insert_breakpoint(afl_t *afl, uint64_t pc)
{
    CPUState *cpu = CPU(afl->arch.cpu);
    cpu_breakpoint_insert(cpu, pc, BP_AFL, NULL);
    cpu_synchronize_state(cpu);
}
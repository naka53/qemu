/*
 * QEMU American Fuzzy Lop board
 * Copyright (c) 2019 S. Duverger Airbus
 * GPLv2
 */

#ifndef __AFL_H__
#define __AFL_H__


#include "qemu/osdep.h"
#include "qemu/units.h"
#include "qemu/log.h"
#include "qemu/error-report.h"
#include "qemu/coroutine.h"
#include "qemu/timer.h"

#include "qapi/error.h"
#include "qapi/qapi-commands-misc.h"
#include "qapi/qapi-events-run-state.h"
#include "qapi/qmp/qerror.h"

#include "cpu.h"
#include "exec/translate-all.h"

#include "hw/hw.h"
#include "hw/loader.h"
#include "hw/boards.h"
#include "hw/pci/pci.h"
#include "hw/pci/pci_host.h"
#include "hw/sysbus.h"

#include "exec/memory.h"
#include "exec/address-spaces.h"
#include "exec/ram_addr.h"
#include "exec/gdbstub.h"
#include "semihosting/semihost.h"
#include "exec/exec-all.h"

#include "sysemu/hw_accel.h"
#include "sysemu/arch_init.h"
#include "sysemu/numa.h"
#include "sysemu/kvm.h"
#include "sysemu/runstate.h"

#include "migration/migration.h"
#include "migration/global_state.h"
#include "migration/misc.h"
#include "migration/vmstate.h"
#include "migration/qemu-file-types.h"
#include "migration/qemu-file.h"
#include "migration/savevm.h"
#include "io/channel-file.h"

#include <sys/types.h>
#include <sys/shm.h>


typedef uint8_t  u8;
typedef uint32_t u32;
typedef uint64_t u64;

/*
 * AFL board configuration mode
 */
#define AFL_DEBUG                1
//#define AFL_GENCODE_DEBUG        1
#define AFL_CONTACT              1
#define AFL_INJECT_TESTCASE      1
//#define AFL_GENCODE              1

#define AFL_CONTROL_EXECUTION    1
#define AFL_CONTROL_EXEC_ZERO    1
#define AFL_CONTROL_PANIC        1
//#define AFL_CONTROL_CSWITCH      1
//#define AFL_TRACE_MMIO           1
//#define AFL_PRESERVE_TRACEMAP    1

#ifdef AFL_CONTACT
#ifndef AFL_INJECT_TESTCASE
#define AFL_INJECT_TESTCASE 1
#endif
#endif

#ifdef AFL_DEBUG
#define AFL_ALTERNATE_STDOUT     1
#define AFL_ALTERNATE_STDERR     1
//#define AFL_TRACE_CHKSM          1
//#define AFL_TRACE_COUNT          1
#ifdef AFL_INJECT_TESTCASE
//#define AFL_DUMP_TESTCASE        1
//#define AFL_DUMP_PARTITION       1
#endif
#define debug(fmt, ...) do {qemu_log("afl-"TARGET_NAME": "fmt, ## __VA_ARGS__);} while(0)

#else // NO DEBUG
#define debug(fmt, ...) do {} while(0)
#endif

#define TYPE_AFL_MACHINE "afl"

#ifdef TARGET_ARM

#include "hw/arm/armv7m.h"

#define SYSCLK_FRQ 112000000ULL
#define REFCLK_FRQ 112000000ULL

struct AFLMachineState {
   /*< private >*/
   SysBusDevice parent_obj;
   /*< public >*/

   ARMv7MState armv7m;

   Clock *sysclk;
   Clock *refclk;

   MemoryRegion flash;
   MemoryRegion ram;
};

typedef struct afl_arm_board
{
   ARMCPU *cpu;

} afl_arm_t;

typedef afl_arm_t afl_arch_t;

static inline target_ulong afl_get_pc(afl_arch_t *arch)
{
   CPUARMState *env = &arch->cpu->env;
   return env->regs[15];
}

static inline void afl_set_pc(afl_arch_t *arch, target_ulong pc)
{
   CPUARMState *env = &arch->cpu->env;
   env->regs[15] = pc;
}

static inline target_ulong afl_get_stack(afl_arch_t *arch)
{
   CPUARMState *env = &arch->cpu->env;
   return env->regs[13];
}

#endif

#ifdef TARGET_RISCV64

#define AFL_CPU TYPE_RISCV_CPU_AFL

#define AFL_PLIC_BASE            0x40000000
#define AFL_PLIC_HART_CONFIG     "MS"
#define AFL_PLIC_NUM_HARTS       1
#define AFL_PLIC_HARTID_BASE     0
#define AFL_PLIC_NUM_SOURCES     33
#define AFL_PLIC_NUM_PRIORITIES  2
#define AFL_PLIC_PRIORITY_BASE   0x0
#define AFL_PLIC_PENDING_BASE    0x1000
#define AFL_PLIC_ENABLE_BASE     0x2000
#define AFL_PLIC_ENABLE_STRIDE   0x80
#define AFL_PLIC_CONTEXT_BASE    0x200000
#define AFL_PLIC_CONTEXT_STRIDE  0x1000
#define AFL_PLIC_APERTURE_SIZE   0x4000000

#define AFL_CLINT_BASE           0x44010000
#define AFL_CLINT_MTIMER_SIZE    0x20000
#define AFL_CLINT_HARTID_BASE    0
#define AFL_CLINT_NUM_HARTS      1
#define AFL_CLINT_TIMECMP_BASE   0x10000
#define AFL_CLINT_TIME_BASE      0x0
#define AFL_CLINT_MSWI_BASE      0x20000
#define AFL_CLINT_SSWI_BASE      0x30000
#define AFL_CLINT_TIMEBASE_FREQ  900000

#include "hw/riscv/riscv_hart.h"
#include "hw/intc/sifive_plic.h"
#include "hw/misc/afl_uart.h"

struct AFLMachineState {
   /*< private >*/
   SysBusDevice parent_obj;
   /*< public >*/

   RISCVHartArrayState riscv;

   MemoryRegion rom;
   MemoryRegion ram;
};

typedef struct afl_riscv_board
{
   RISCVCPU *cpu;

} afl_riscv_t;

typedef afl_riscv_t afl_arch_t;

static inline target_ulong afl_get_pc(afl_arch_t *arch)
{
   CPURISCVState *env = &arch->cpu->env;
   return env->pc;
}

static inline void afl_set_pc(afl_arch_t *arch, target_ulong pc)
{
   CPURISCVState *env = &arch->cpu->env;
   env->pc = pc;
}

static inline target_ulong afl_get_stack(afl_arch_t *arch)
{
   CPURISCVState *env = &arch->cpu->env;
   return env->gpr[xSP];
}

#endif

/*
 * Generic AFL board
 */

/* waitpid() status format */
#define create_wait_status(code, signal)        \
   (((int)code)<<8 | (int)(signal & 0x7f))

#define sts_abort()      create_wait_status(0, SIGABRT)
#define sts_kill()       create_wait_status(0, SIGKILL)
#define sts_exit(code)   create_wait_status(code, 0)
#define sts_stopped(sig) create_wait_status(sig, 0x7f)

typedef struct afl_configuration
{
   /* QEMU / AFL interaction information */
   struct __afl_qemu_conf {
      int64_t     timeout;  /* AFL cmd line user time out in ms */
      int64_t     overhead; /* Estimated overhead for qemu/afl
                             * transitions used to setup timer */
      const char *vms_tpl;  /* vmstate template file path */
   } qemu;

   /* AFL internals */
   struct __afl_int_conf {
      int         ctl_fd;     /* AFL control file descriptor */
      int         sts_fd;     /* AFL status file descriptor */
      size_t      trace_size; /* AFL coverage bitmap size in bytes */
      uint64_t    trace_addr; /* AFL coverage bitmap target mmio
                               * address */
      const char *trace_env;  /* AFL coverage bitmap shared memory
                               * identifier environment variable
                               * name */
      uint64_t    prev_loc_addr;
   } afl;

   /* Virtual Machine (Target) partition information */
   struct __afl_target_conf {
      target_ulong  part_base;        /* Partition base paddr */
      uint64_t      part_size;        /* Allocated partition size */
      target_ulong  part_kstack;      /* Partition thread allocated
                                       * kernel stack vaddr */
      uint64_t      part_kstack_size; /* Partition thread allocated
                                       * kernel stack size */
      uint64_t      nop_size;         /* NOP-sled size */
      target_ulong  part_off;         /* NOP-sled offset */
      target_ulong  fuzz_inj;         /* Generated code injection paddr */
      target_ulong  fuzz_ep;          /* Fuzzing starting point vaddr */
      target_ulong  fuzz_ep_next;     /* Insn vaddr following FUZZ_EP */
      target_ulong  size;             /* Effective target physical memory
                                       * used */
      target_ulong  panic;            /* Target 'kernel panic' vaddr */
      target_ulong  cswitch;          /* Target context switch vaddr */
      target_ulong  cswitch_next;     /* Insn vaddr follwing 'vm_cswitch_next' */
   } tgt;

   /* Runtime operating mode/strategy */
   /* struct __afl_running_mode { */
   /*    bool    fast_restore; */
   /*    bool    control_execution; */
   /*    bool    control_exec_zero; */
   /*    bool    control_panic; */
   /*    bool    control_cswitch; */
   /*    bool    ram_guard; */
   /*    bool    trace_mmio; */
   /*    bool    preserve_tracemap; */
   /*    bool    trace_chksm; */
   /*    bool    trace_count; */
   /*    bool    dump_test; */
   /*    bool    dump_part; */
   /* } mode; */

} afl_conf_t;

typedef struct afl_board
{
   afl_conf_t     config;
   QEMUTimer     *user_timer;

   // VM state
   char           vms_path[32];
   int            vms_fd;
   MemoryRegion  *ram_mr;
   void          *ram_ptr;
   uint32_t       ram_size;
   target_ulong   vm_exit;
   int            status;

   // AFL internals
   int            shm_id;
   MemoryRegion   trace_mr;
   MemoryRegion   prev_loc_mr;
   void          *trace_bits;
#ifdef AFL_CONTROL_CSWITCH
   MemoryRegion   fake_mr;
   void          *fake_bits;
#endif
   uid_t          euid;
   int            pid, ppid;

   // Architecture specific
   afl_arch_t     arch;

} afl_t;

/*
 * Functions
 */
afl_t*  afl_pre_init(void);
void    afl_cleanup(afl_t*);

void    afl_init(afl_t*, MachineState*);
void    afl_init_conf(afl_t*);
void    afl_init_trace_mem(afl_t *afl);

void    afl_remove_breakpoint(afl_t*, target_ulong);
void    afl_insert_breakpoint(afl_t*, target_ulong);
void    afl_vm_state_change(void*, bool, RunState);
void    afl_forward_child(afl_t*);
void    afl_user_timeout_cb(void*);
void    afl_save_vm(afl_t*, int);
void    afl_load_vm(afl_t*, int);
size_t  afl_inject_test_case(afl_t*);
size_t  afl_gen_code(uint8_t*, size_t, uint8_t*, size_t);
void    afl_mem_invalidate(MemoryRegion*, hwaddr, hwaddr);

void    afl_trace_checksum(afl_t*, const char*);
void    afl_trace_count(afl_t*, const char*);

// __AFL_H__
#endif
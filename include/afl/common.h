#ifndef AFL_COMMON_H
#define AFL_COMMON_H

#include "qemu/osdep.h"
#include "exec/abi_ptr.h"

#include "cpu.h"
#include "hw/intc/armv7m_nvic.h"
#include "hw/timer/armv7m_systick.h"

/* waitpid() status format */
#define create_wait_status(code, signal)        \
    (((int)code) << 8 | (int)(signal & 0x7f))

#define sts_abort()      create_wait_status(0, SIGABRT)
#define sts_kill()       create_wait_status(0, SIGKILL)
#define sts_exit(code)   create_wait_status(code, 0)
#define sts_stopped(sig) create_wait_status(sig, 0x7f)

typedef struct afl_configuration
{
    /* QEMU / AFL interaction information */
    struct __afl_qemu_conf {
        int64_t     timeout;   /* AFL cmd line user time out in ms */
        int64_t     overhead;  /* Estimated overhead for qemu/afl
                                * transitions used to setup timer */
        const char *mm_ranges; /* binary memory ranges file path */
    } qemu;

    /* Virtual Machine (Target) partition information */
    struct __afl_target_conf {
        target_ulong fork;
        target_ulong start;          /* Fuzzing starting point addr */
        target_ulong end;            /* Fuzzing ending point addr */
        target_ulong panic;          /* Target 'kernel panic' addr */
    } tgt;

} afl_conf_t;

typedef struct afl_arm_t {
  ARMCPU *cpu;
  NVICState *nvic;
  SysTickState (*systick)[M_REG_NUM_BANKS];
  MemoryRegion *ram_mr;
} afl_arm_t;

typedef struct afl_t {
  uid_t euid;
  int pid;
  int ppid;
  
  int status;

  uint8_t *shared_buf;
  uint32_t *shared_buf_len;
  
  QEMUTimer *user_timer;
  target_ulong vm_exit;
  
  afl_conf_t config;
  afl_arm_t arch;
} afl_t;

extern afl_t *afl;

void afl_cleanup(afl_t *);
void afl_init(afl_t *);
void afl_init_conf(afl_t *);
void afl_init_snapshot(afl_t *);
void afl_init_mem_bitmap(afl_t *);
void afl_remove_breakpoint(afl_t *, uint64_t);
void afl_insert_breakpoint(afl_t *, uint64_t);
void afl_vm_state_change(void*, bool, RunState);
void afl_user_timeout_cb(void*);
void afl_forkserver(afl_t *);
void afl_persistent(afl_t *);
void afl_persistent_return(afl_t *);
size_t afl_inject_test_case(afl_t *);
void afl_forward_child(afl_t*);
void afl_save_reg(afl_t *);
void afl_load_reg(afl_t *);
void afl_save_ram(afl_t *);
void afl_load_ram(afl_t *);
#endif
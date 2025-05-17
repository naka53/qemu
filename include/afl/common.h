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
        int64_t     timeout;              	/* AFL cmd line user time out in ms */
        const char  *mm_ranges;           /* binary memory ranges file path */
    } qemu;

    /* Virtual Machine (Target) partition information */
    struct __afl_target_conf {
        target_ulong forkserver;			/* Forkserver initialization addr */
        target_ulong persistent;          	/* Fuzzing starting point addr */
        target_ulong persistent_return;   	/* Fuzzing ending point addr */
        target_ulong panic;               	/* Target 'kernel panic' addr */
    } tgt;

} afl_conf_t;

typedef struct afl_arch_t {
	ArchCPU			*cpu;
	MemoryRegion 	*ram_mr;
} afl_arch_t;

typedef struct afl_t {
	uid_t 		euid;
	int 		pid;
	int 		ppid;

	int 		status;						/* status forwarded to AFL */
	uint8_t     *shared_buf;				/* input data from AFL */
	uint32_t    *shared_buf_len;    		/* input data len from AFL */

	QEMUTimer 	*user_timer;

	afl_conf_t 	config;
	afl_arch_t 	arch;
} afl_t;

extern afl_t *__global_afl;

void afl_cleanup(afl_t *);
void afl_bitmap_cleanup(afl_t *);
void afl_snapshot_cleanup(afl_t *);
void afl_init(afl_t *);
void afl_init_conf(afl_t *);
void afl_init_mem_bitmap(afl_t *);
void afl_init_snapshot(afl_t *);
void afl_user_timeout_cb(void*);
void afl_forkserver(afl_t *);
void afl_persistent(afl_t *);
void afl_persistent_return(afl_t *);
void afl_panic_return(afl_t *);
size_t afl_inject_test_case(afl_t *);
void afl_forward_child(afl_t *);
void afl_forward_status(afl_t *);
void afl_save_reg(afl_t *);
void afl_load_reg(afl_t *);
void afl_save_ram(afl_t *);
void afl_load_ram(afl_t *);
void afl_vm_state_change(void*, bool, RunState);
#endif
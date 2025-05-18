#include "afl/config.h"
#include "afl/common.h"
#include "afl/instrumentation.h"

#include <sys/shm.h>
#include "exec/tb-flush.h"
#include "sysemu/hw_accel.h"
#include "sysemu/runstate.h"

/*
 * Qemu AFL user-timeout implementation. We use VirtualClock
 * to only count time elapsed during target execution.
 * The callback is called during qemu main_loop()
 * thus we can't change VM state directly, because
 * the VM might be running and stopping it from here
 * might deadlock due to qemu virtual clock disabling
 * waiting for timer callback to return.
 *
 * We simulate SIGKILL status for AFL.
 */
void afl_user_timeout_cb(void *opaque)
{
    afl_t *afl = (afl_t*)opaque;
    fprintf(stdout, "Timeout, force to reload\n");

    afl->status = sts_kill();
    afl_forward_status(afl);

    qemu_system_vmstop_request_prepare();
    qemu_system_vmstop_request(RUN_STATE_RESTORE_VM);
}

static inline void afl_setup_timer(QEMUTimer *timer, int64_t duration)
{
    int64_t now = qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL);
    int64_t expire = now + duration;
    timer_mod(timer, expire);
}

static void afl_map_shm_fuzz(afl_t *afl) {
    char *id_str = getenv("__AFL_SHM_FUZZ_ID");

    if (id_str) {
        uint32_t shm_id = atoi(id_str);
        uint8_t *map = (uint8_t *)shmat(shm_id, NULL, 0);

        if (!map || map == (void *)-1) {
            fprintf(stderr, "could not access fuzzing shared memory\n");
            exit(EXIT_FAILURE);
        }

        afl->shared_buf_len = (uint32_t *)map;
        afl->shared_buf = map + sizeof(uint32_t);

    } else {
        fprintf(stderr, "variable for fuzzing shared memory is not set\n");
        exit(EXIT_FAILURE);
    }

}

static bool forkserver_initialized = false;

void afl_forkserver(afl_t *afl) 
{
    uint32_t features = 0;
    uint32_t status = 0;

    if (forkserver_initialized) 
        return;

    forkserver_initialized = true;

    status |= FORKSERVER_VERSION;

    /* Tell the parent that we're alive. */
    if (write(FORKSRV_STATUS_FD, &status, 4) != 4) {
        fprintf(stderr, "not able to send requested features\n");
        exit(EXIT_FAILURE);
    }
    if (read(FORKSRV_CONTROL_FD, &status, 4) != 4) {
        fprintf(stderr, "not able to get supported features\n");
        exit(EXIT_FAILURE);
    }

    if (status != (FORKSERVER_VERSION ^ 0xFFFFFFFF)) {
        fprintf(stderr, "not able to synchronize forkserver version\n");
        exit(EXIT_FAILURE);
    }

    features |= FS_NEW_OPT_SHDMEM_FUZZ;

    /* Tell the parent that we're alive. */
    if (write(FORKSRV_STATUS_FD, &features, 4) != 4) {
        fprintf(stderr, "not able to send requested features\n");
        exit(EXIT_FAILURE);
    }

    status = FORKSERVER_VERSION;

    if (write(FORKSRV_STATUS_FD, &status, 4) != 4) {
        fprintf(stderr, "not able to finalize synchronization forkserver\n");
        exit(EXIT_FAILURE);
    }

    afl_map_shm_fuzz(afl);

}

static bool snapshot_saved = false;

void afl_persistent(afl_t *afl)
{
    int prev_timed_out; /* last child did time out ? */

    if (!snapshot_saved) {
        memset(afl_area_ptr, 0, MAP_SIZE);

        afl_save_ram(afl);
        afl_save_reg(afl);
    
        snapshot_saved = true;
        fuzzing_started = true;
    }

    afl_load_reg(afl);
    afl_load_ram(afl);

    afl_area_ptr[0] = 1;
    afl_prev_loc = 0;

    /* Wait for parent by reading from the pipe. Abort if read fails. */
    if (read(FORKSRV_CONTROL_FD, &prev_timed_out, 4) != 4) {
        fprintf(stderr, "not ready to run test case\n");
        exit(EXIT_FAILURE);
    }

    /* inject test case in VM partition */
    afl_inject_test_case(afl);

    /* Write fake PID to pipe to release AFL (run_target()) */
    afl_forward_child(afl);

    /* At this point, AFL just received the child_pid, set user timeout
     * and wait for child_status from pipe. If user timeout expires,
     * AFL will SIGKILL(child_pid) and set child_timed_out = 1. After
     * receiveing child status, AFL disarms the user timeout and
     * proceed with fault analysis.
     *
     * AFL analyses child status based on waitpid() return.
     * WIFSIGNALED(status): child process was terminated by a signal.
     *
     * if child_pid > 0 && timer expired : child_timed_out = 1
     * if child_pid > 0 && ctrl+c        : stop_soon = 1
     *
     * if (WIFSIGNALED(status) && !stop_soon) {
     *    kill_signal = WTERMSIG(status)
     *    if (child_timed_out && kill_signal == SIGKILL)
     *       return FAULT_TMOUT
     *    return FAULT_CRASH
     * return FAULT_NONE
     */
    afl_setup_timer(afl->user_timer, afl->config.qemu.timeout);

    vm_start();
}

void afl_forward_status(afl_t *afl) {
    /* relay waitpid() status to AFL */
    if (write(FORKSRV_STATUS_FD, &afl->status, 4) != 4) {
        fprintf(stderr, "can't write status to afl\n");
        exit(EXIT_FAILURE);
    }
}

void afl_persistent_return(afl_t *afl) 
{
    afl->status = sts_exit(EXIT_FAILURE);
    afl_forward_status(afl);
}

void afl_panic_return(afl_t *afl) 
{
    afl->status = sts_abort();
    afl_forward_status(afl);
}

static void async_restore_vm(CPUState *cs, run_on_cpu_data data)
{
    afl_t *afl = (afl_t *)data.host_ptr;
    ARMCPU *cpu = ARM_CPU(cs);
    CPUARMState *env = &cpu->env;
    printf("Async handler\n");
    env->regs[15] = afl->config.tgt.persistent & ~1;
    env->thumb = afl->config.tgt.persistent & 1;

    vm_start();
}

void afl_vm_state_change(void *opaque, bool running, RunState state)
{
    afl_t *afl = (afl_t*)opaque;

    if (state == RUN_STATE_SHUTDOWN) {
        afl_cleanup(afl);
        return;
    }

    /* VM async request RESTORE_VM, cf. afl_user_timeout_cb() */
    if (state == RUN_STATE_RESTORE_VM) {
        async_run_on_cpu(first_cpu, async_restore_vm,
                         RUN_ON_CPU_HOST_PTR(afl));
        return;
    }
}
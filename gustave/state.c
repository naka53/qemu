#include "afl/config.h"
#include "afl/common.h"
#include "afl/instrumentation.h"

#include <sys/shm.h>
#include "exec/tb-flush.h"
#include "sysemu/hw_accel.h"
#include "sysemu/runstate.h"

static void afl_run_target(afl_t *afl);

static void afl_forward_status(afl_t *afl)
{
    /* relay waitpid() status to AFL */
    if (write(FORKSRV_STATUS_FD, &afl->status, 4) != 4) {
        fprintf(stderr, "can't write status to afl\n");
        exit(EXIT_FAILURE);
    }
}

static void afl_reload_forward(afl_t *afl)
{
    afl_forward_status(afl);

    afl_load_reg(afl);
    afl_load_ram(afl);

    afl_area_ptr[0] = 1;
    afl_prev_loc = 0;

    afl_run_target(afl);
}

/*
 * Forward fake child fork() and early failing status
 * to generate a new test case without any execution.
 * Used when partition code generator failed parsing.
 * We do not generate fake pid as usual (we get faster
 * to not waste time), because AFL will never have time
 * to SIGKILL it (upon timeout) between read(pid)
 * & read(status).
 */
static void afl_flash_forward(afl_t *afl)
{
    int child_pid = 1;
    if (write(FORKSRV_STATUS_FD, &child_pid, 4) != 4) {
        fprintf(stderr, "can't write fast pid to afl\n");
        exit(EXIT_FAILURE);
    }

    afl->status = sts_exit(EXIT_FAILURE);
    afl_forward_status(afl);
}

/*
 * Qemu AFL user-timeout implementation. We use VirtualClock
 * to only count time elapsed during target execution.
 * The callback is called during qemu main_loop()
 * thus we can't change VM state directly, because
 * the VM might be running and stopping it from here
 * might deadlock due to qemu virtual clock disabling
 * waiting for timer callback to return.
 *
 * So we act asynchronously, by requesting the VM to stop.
 * Out of timer callback execution, the qemu main_loop()
 * will analyse stop requests and change VM state.
 * This will raise our afl_vm_state_change() callback.
 *
 * We simulate SIGKILL status for AFL.
 */
void afl_user_timeout_cb(void *opaque)
{
    afl_t *afl = (afl_t*)opaque;

    afl->status = sts_kill();
    qemu_system_vmstop_request_prepare();
    qemu_system_vmstop_request(RUN_STATE_RESTORE_VM);
}

static inline void afl_setup_timer(QEMUTimer *timer, int64_t duration)
{
    int64_t now = qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL);
    int64_t expire = now + duration;
    timer_mod(timer, expire);
}

static void afl_handle_abort(afl_t *afl)
{
    afl->status = sts_abort();
    afl_reload_forward(afl);
}

static void afl_handle_restore(afl_t *afl)
{
    afl_reload_forward(afl);
}

/*
 * Prepare the VM to be resumed :
 *  - wait for AFL to generate test case
 *  - inject it to the partition
 *  - install BP at new partition code end
 *  - spwan fake pid (no fork)
 *  - setup user time out for this test case
 *
 * Must be called from a Qemu VM callback (ie. vm_state_change())
 * to be able to resume VM upon return.
 */

static void afl_run_target(afl_t *afl)
{
    int len;
    int prev_timed_out; /* last child did time out ? */

__wait_test_case:
    /* Wait for parent by reading from the pipe. Abort if read fails. */
    if (read(FORKSRV_CONTROL_FD, &prev_timed_out, 4) != 4) {
        fprintf(stderr, "not ready to run test case\n");
        exit(EXIT_FAILURE);
    }

    /* inject test case in VM partition */
    len = afl_inject_test_case(afl);

    if (len == 0) {
        afl_flash_forward(afl);
        goto __wait_test_case;
    }

    /* remove previously installed breakpoint */
    afl_remove_breakpoint(afl, afl->vm_exit);

    afl->vm_exit = afl->config.tgt.end;

    afl_insert_breakpoint(afl, afl->vm_exit);

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
    afl_setup_timer(afl->user_timer, afl->config.qemu.timeout - afl->config.qemu.overhead);

    /* Resume VM until memory fault, timeout or end of execution */
    vm_start();
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

void afl_forkserver(afl_t *afl) 
{
    uint32_t requested_features = 0;
    uint32_t supported_features = 0;

    if (MAP_SIZE <= FS_OPT_MAX_MAPSIZE)
        requested_features |= (FS_OPT_SET_MAPSIZE(MAP_SIZE) | FS_OPT_MAPSIZE);

    requested_features |= FS_OPT_ENABLED;
    requested_features |= FS_OPT_SHDMEM_FUZZ;

    /* Tell the parent that we're alive. */
    if (write(FORKSRV_STATUS_FD, &requested_features, 4) != 4) {
        fprintf(stderr, "not able to send requested features\n");
        exit(EXIT_FAILURE);
    }
    if (read(FORKSRV_CONTROL_FD, &supported_features, 4) != 4) {
        fprintf(stderr, "not able to get supported features\n");
        exit(EXIT_FAILURE);
    }

    if ((supported_features & (FS_OPT_ENABLED | FS_OPT_SHDMEM_FUZZ)) ==
        (FS_OPT_ENABLED | FS_OPT_SHDMEM_FUZZ))
      afl_map_shm_fuzz(afl);
    else {
      fprintf(stderr, "afl-fuzz is old and does not support shmem input\n");
      exit(EXIT_FAILURE);
    }

    afl_remove_breakpoint(afl, afl->config.tgt.fork);

    afl->vm_exit = afl->config.tgt.start;
    afl_insert_breakpoint(afl, afl->config.tgt.start);

    tb_flush(CPU(afl->arch.cpu));

    vm_start();
}
#ifdef AFL_ACTIVATED
static bool first_execution = true;

/*
 * The VM has run enough code to boot, init devices, setup partitions
 * and now its interesting to start fuzzing.
 */
void afl_persistent(afl_t *afl)
{
    if (first_execution) {
        first_execution = false;

        memset(afl_area_ptr, 0, MAP_SIZE);
        afl_area_ptr[0] = 1;
        afl_prev_loc = 0;

        afl_save_ram(afl);
        afl_save_reg(afl);
    }

    afl_run_target(afl);
}

void afl_persistent_return(afl_t *afl) 
{
    afl->status = sts_exit(EXIT_FAILURE);
    afl_reload_forward(afl);
}
#endif
/*
 * When running with KVM, it seems unsafe to change vm state inside a
 * vm_state_change_handler(). The vcpu is running very slowly. When
 * looking at kvm_stat, far less virq are injected per second. So we
 * update vm state asynchronously, in the vcpu thread with a queued
 * work. Notice that in TCG mode, we didn't encountered this issue.
 */
static void async_restore_vm(CPUState *cpu, run_on_cpu_data data)
{
    afl_handle_restore((afl_t*)data.host_ptr);
}

/*
 * Dedicated debug handling VM change state
 */
static void async_debug_vm(CPUState *cpu, run_on_cpu_data data)
{
    afl_t *afl = (afl_t*)data.host_ptr;
    target_ulong pc = afl->arch.cpu->env.regs[15];

    /* VM kernel panic */
    if (pc == afl->config.tgt.panic)
        afl_handle_abort(afl);
    else {
        /* VM execution should hit last installed breakpoint */
        if (pc != afl->vm_exit)
            fprintf(stderr, "vm unhandled #debug event 0x"TARGET_FMT_lx  \
                            " (waiting 0x"TARGET_FMT_lx")\n"
                            "----> investigate with monitor", pc, afl->vm_exit);
#ifdef AFL_ACTIVATED
        else if (afl->vm_exit == afl->config.tgt.fork)
            afl_forkserver(afl);
        else if (afl->vm_exit == afl->config.tgt.start)
            afl_persistent(afl);
        else if (afl->vm_exit == afl->config.tgt.end)
            afl_persistent_return(afl);
#endif
    }
}

/*
 * Dedicated panic handling VM change state
 */
static void async_panic_vm(CPUState *cpu, run_on_cpu_data data)
{
    afl_t *afl = (afl_t*)data.host_ptr;

    afl_handle_abort(afl);
}

/*
 * This is our main VM state handler.
 * We trap any VM status change, ie. breakpoints, restore, ...
 * and proceed with corresponding action.
 */
void afl_vm_state_change(void *opaque, bool running, RunState state)
{
    afl_t    *afl = (afl_t*)opaque;
    CPUState *cpu = CPU(afl->arch.cpu);

    if (running || state == RUN_STATE_PAUSED) {
        return;
    }

    if (state == RUN_STATE_SHUTDOWN) {
        afl_cleanup(afl);
        return;
    }

    /* XXX: do it only on async handlers ? */
    cpu_synchronize_state(cpu);

    /* VM async request RESTORE_VM, cf. afl_user_timeout_cb() */
    if (state == RUN_STATE_RESTORE_VM) {
        async_run_on_cpu(first_cpu, async_restore_vm,
                         RUN_ON_CPU_HOST_PTR(afl));
        return;
    }

    if (state == RUN_STATE_DEBUG) {
        async_run_on_cpu(first_cpu, async_debug_vm,
                         RUN_ON_CPU_HOST_PTR(afl));
        return;
    }

    if (state == RUN_STATE_GUEST_PANICKED) {
        async_run_on_cpu(first_cpu, async_panic_vm,
                         RUN_ON_CPU_HOST_PTR(afl));
        return;
    }

    if (runstate_needs_reset()) {
        fprintf(stderr, "vm runstate needs reset !\n");
        exit(EXIT_FAILURE);
    }

    printf("vm unhandled state %s\n", RunState_str(state));
    exit(EXIT_FAILURE);
}
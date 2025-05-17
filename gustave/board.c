#include "afl/config.h"
#include "afl/common.h"
#include "afl/instrumentation.h"

#include <sys/shm.h>
#include "sysemu/runstate.h"

afl_t *__global_afl;

static void afl_setup(afl_t *afl)
{
    char *id_str = getenv("__AFL_SHM_ID");
    char *inst_r = getenv("AFL_INST_RATIO");
    int shm_id;

    if (inst_r) {
        unsigned int r;

        r = atoi(inst_r);

        if (r > 100) r = 100;
        if (!r) r = 1;

        afl_inst_rms = MAP_SIZE * r / 100;
    }

    if (id_str) {
        shm_id = atoi(id_str);
        afl_area_ptr = shmat(shm_id, NULL, 0);

        if (afl_area_ptr == (void *)-1) exit(EXIT_FAILURE);

        /* With AFL_INST_RATIO set to a low value, we want to touch the bitmap
            so that the parent doesn't give up on us. */

        if (inst_r) afl_area_ptr[0] = 1;
    }

    afl->euid = geteuid();
    afl->pid  = getpid();
    afl->ppid = getppid();

    afl->user_timer = timer_new_ms(QEMU_CLOCK_VIRTUAL, afl_user_timeout_cb, afl);
}

void afl_cleanup(afl_t *afl)
{
    if (afl->user_timer)
        timer_del(afl->user_timer);

    afl_snapshot_cleanup(afl);
}

void afl_init(afl_t *afl)
{ 
    afl_setup(afl);
    afl_init_conf(afl);
    afl_init_snapshot(afl);

    qemu_add_vm_change_state_handler(afl_vm_state_change, (void*)afl);
}
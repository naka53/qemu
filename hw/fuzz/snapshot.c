/*
 * QEMU American Fuzzy Lop board
 * snapshot
 *
 * Copyright (c) 2019 S. Duverger Airbus
 * GPLv2
 */
#include "qemu/afl.h"

/* XXX:
 * This is crappy, no check, we know that there is
 * bigger block than AFL trace map before us
 * so prev won't be NULL, but ...
 */
#if !defined(AFL_TRACE_MMIO) && defined(AFL_PRESERVE_TRACEMAP)
static RAMBlock* __qlist_rcu_prev_and_remove(RAMBlock *block)
{
   RAMBlock *prev;
   qemu_mutex_lock_ramlist();

   prev = (RAMBlock*)
      ((ulong)block->next.le_prev - offsetof(RAMBlock, next));

   QLIST_REMOVE_RCU(block, next);
   /* ram_list.mru_block = NULL; */
   /* smp_wmb(); */
   /* ram_list.version++; */
   qemu_mutex_unlock_ramlist();

   return prev;
}

static void __qlist_rcu_restore(RAMBlock *prev, RAMBlock *block)
{
   qemu_mutex_lock_ramlist();
   QLIST_INSERT_AFTER_RCU(prev, block, next);
   /* ram_list.mru_block = NULL; */
   /* smp_wmb(); */
   /* ram_list.version++; */
   qemu_mutex_unlock_ramlist();
}
#endif

/* Save the VM in a "dirty way"
 * (ie. don't use save_snapshot())
 */
void afl_save_vm(afl_t *afl, int afd)
{
   /* int vm_running; */
   int ret;
   int fd = dup(afd); // qfile will close it

   lseek(fd, 0, SEEK_SET);
   if (ftruncate(fd, 0) < 0) {
      error_report("ftruncate failed");
      return;
   }

   QIOChannel *ioc = QIO_CHANNEL(qio_channel_file_new_fd(fd));
   QEMUFile *f = qemu_file_new_output(ioc);

   if (!f) {
      error_report("qemu_fopen failed");
      return;
   }

   object_unref(OBJECT(ioc));

   /* prevent saving AFL trace bitmaps to keep activity trace when
    * reloading the VM.
    */
#if !defined(AFL_TRACE_MMIO) && defined(AFL_PRESERVE_TRACEMAP)
   RAMBlock *prev = __qlist_rcu_prev_and_remove(afl->trace_mr.ram_block);
#endif

   debug("save vm state\n");

   /* vm_running = runstate_is_running(); */
   ret = global_state_store();
   if (ret) {
      error_report("Error saving global state");
      return;
   }

   vm_stop(RUN_STATE_SAVE_VM);

   Error *err = NULL;
    ret = qemu_savevm_state(f, &err);
    if (ret < 0) {
        error_report("%s: error %d while saving VM state", __func__, ret);
        exit(EXIT_FAILURE);
    }

    qemu_fclose(f);

#if !defined(AFL_TRACE_MMIO) && defined(AFL_PRESERVE_TRACEMAP)
   __qlist_rcu_restore(prev, afl->trace_mr.ram_block);
#endif
}

void afl_load_vm(afl_t *afl, int afd)
{
   int ret;
   int fd = dup(afd); // qfile will close it

   lseek(fd, 0, SEEK_SET);

   QIOChannel *ioc = QIO_CHANNEL(qio_channel_file_new_fd(fd));
   QEMUFile *f = qemu_file_new_input(ioc);

   debug("%s()\n", __func__);

   if (!f) {
      error_report("qemu_fopen failed");
      return;
   }
   object_unref(OBJECT(ioc));

#ifdef AFL_TRACE_CHKSM
   afl_trace_checksum(afl, "pre-load");
#endif

   if (!runstate_check(RUN_STATE_RESTORE_VM)) {
      vm_stop(RUN_STATE_RESTORE_VM);
   }

   qemu_system_reset(SHUTDOWN_CAUSE_NONE);
   ret = qemu_loadvm_state(f);
   if (ret < 0) {
      error_report("error %d while loading VM state", ret);
      return;
   }
   qemu_fclose(f);

#ifdef AFL_TRACE_CHKSM
   afl_trace_checksum(afl, "post-load");
#endif
}
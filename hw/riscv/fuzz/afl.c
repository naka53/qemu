#include "qemu/osdep.h"
#include "qapi/error.h"
#include "hw/boards.h"
#include "hw/qdev-properties.h"
#include "hw/qdev-clock.h"
#include "qemu/error-report.h"
#include "hw/riscv/boot.h"
#include "exec/address-spaces.h"
#include "hw/misc/unimp.h"
#include "qemu/afl.h"
#include "hw/misc/afl_uart.h"
#include "hw/intc/riscv_aclint.h"
#include "cpu_bits.h"

OBJECT_DECLARE_SIMPLE_TYPE(AFLMachineState, AFL_MACHINE)

static void afl_common_init(MachineState *m)
{
   AFLMachineState *sms = AFL_MACHINE(m);
   MemoryRegion *sys_mem = get_system_memory();
   DeviceState *dev;

   afl_t *afl = afl_pre_init();

   memory_region_init_rom(&sms->rom, NULL, "ROM", 0x10000, &error_fatal);
   memory_region_add_subregion(sys_mem, 0x00000000, &sms->rom);

   memory_region_init_ram(&sms->ram, NULL, "RAM", 0x30000, &error_fatal);
   memory_region_add_subregion(sys_mem, 0x00010000, &sms->ram);

   object_initialize_child(OBJECT(sms), "riscv", &sms->riscv, TYPE_RISCV_HART_ARRAY);
   dev = DEVICE(&sms->riscv);
   qdev_prop_set_string(dev, "cpu-type", m->cpu_type);
   qdev_prop_set_uint32(dev, "num-harts", 1);
   qdev_prop_set_uint32(dev, "hartid-base", 0);
   qdev_prop_set_uint64(dev, "resetvec", 0x00000000);
   sysbus_realize(SYS_BUS_DEVICE(&sms->riscv), &error_fatal);

   afl->ram_mr = &sms->ram;
   afl->arch.cpu = sms->riscv.harts;

   afl_init(afl, m);

   riscv_load_kernel(m, &sms->riscv, 0x00000000, true, NULL);
}

static void afl_machine_init(MachineClass *mc)
{
   mc->desc = "AFL (RISC-V) __AFL_SHM_ID";
   mc->default_cpu_type = RISCV_CPU_TYPE_NAME("afl");
   mc->init = afl_common_init;
}

DEFINE_MACHINE("afl", afl_machine_init)
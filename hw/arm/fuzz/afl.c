#include "qemu/osdep.h"
#include "qapi/error.h"
#include "hw/boards.h"
#include "hw/qdev-properties.h"
#include "hw/qdev-clock.h"
#include "qemu/error-report.h"
#include "hw/arm/boot.h"
#include "exec/address-spaces.h"
#include "hw/misc/unimp.h"
#include "qemu/afl.h"

void afl_init_arch(afl_t *afl, MachineState *mcs, MemoryRegion *sysmem)
{
   return;
}

size_t afl_gen_code(uint8_t *in, size_t in_size, uint8_t* out, size_t out_max)
{
   size_t len = 20;

   if (in_size < len)
      len = in_size;

   memcpy(out, in, len);
   
   return len;
}

OBJECT_DECLARE_SIMPLE_TYPE(AFLMachineState, AFL_MACHINE)

static void afl_common_init(MachineState *m)
{
   AFLMachineState *sms = AFL_MACHINE(m);
   DeviceState *armv7m;
   MemoryRegion *sys_mem = get_system_memory();

   afl_t *afl = afl_pre_init();

   sms->sysclk = clock_new(OBJECT(m), "SYSCLK");
   clock_set_hz(sms->sysclk, SYSCLK_FRQ);

   sms->refclk = clock_new(OBJECT(m), "REFCLK");
   clock_set_hz(sms->refclk, REFCLK_FRQ);

   memory_region_init_rom(&sms->flash, NULL, "Flash", 0x10000, &error_fatal);
   memory_region_add_subregion(sys_mem, 0x00000, &sms->flash);

   memory_region_init_ram(&sms->ram, NULL, "RAM", 0x40000, &error_fatal);
   memory_region_add_subregion(sys_mem, 0x10000, &sms->ram);

   object_initialize_child(OBJECT(sms), "armv7m", &sms->armv7m, TYPE_ARMV7M);
   armv7m = DEVICE(&sms->armv7m);
   qdev_prop_set_uint32(armv7m, "num-irq", 96);
   qdev_prop_set_string(armv7m, "cpu-type", m->cpu_type);
   qdev_prop_set_bit(armv7m, "enable-bitband", true);
   qdev_connect_clock_in(armv7m, "cpuclk", sms->sysclk);
   qdev_connect_clock_in(armv7m, "refclk", sms->refclk);
   object_property_set_link(OBJECT(&sms->armv7m), "memory", OBJECT(sys_mem), &error_abort);
   sysbus_realize(SYS_BUS_DEVICE(&sms->armv7m), &error_fatal);

   afl->ram_mr = &sms->ram;
   afl->arch.cpu = sms->armv7m.cpu;

   afl_init(afl, m);

   armv7m_load_kernel(ARM_CPU(first_cpu), m->kernel_filename, 0x00000, 0x10000);
}

static void afl_machine_init(MachineClass *mc)
{
   mc->desc = "AFL (Cortex-M4) __AFL_SHM_ID";
   mc->default_cpu_type = ARM_CPU_TYPE_NAME("cortex-m4");
   mc->init = afl_common_init;
}

DEFINE_MACHINE("afl", afl_machine_init)
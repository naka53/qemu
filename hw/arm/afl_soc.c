#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/module.h"
#include "hw/arm/boot.h"
#include "exec/address-spaces.h"
#include "hw/qdev-properties.h"
#include "hw/qdev-clock.h"
#include "hw/arm/afl_soc.h"

#include "afl/config.h"
#include "afl/common.h"

static void afl_soc_initfn(Object *obj)
{
    AFLMachineState *s = AFL_SOC(obj);

    object_initialize_child(OBJECT(s), "armv7m", &s->armv7m, TYPE_ARMV7M);
    
	s->cpuclk = clock_new(OBJECT(s), "CPUCLK");
    clock_set_hz(s->cpuclk, CPUCLK_FRQ);
}

static void afl_soc_realize(DeviceState *dev, Error **errp)
{
	AFLMachineState *s = AFL_SOC(dev);
	DeviceState *armv7m;
	MemoryRegion *sys_mem = get_system_memory();

	memory_region_init_rom(&s->rom, OBJECT(dev), "ROM", AFL_ROM_SIZE, &error_fatal);
	memory_region_add_subregion(sys_mem, AFL_ROM_BASE_ADDR, &s->rom);

	memory_region_init_ram(&s->sram, NULL, "SRAM", AFL_SRAM_SIZE, &error_fatal);
	memory_region_add_subregion(sys_mem, AFL_SRAM_BASE_ADDR, &s->sram);
	
	armv7m = DEVICE(&s->armv7m);
	qdev_prop_set_uint32(armv7m, "num-irq", AFL_IRQ_NUMBER);
	qdev_prop_set_string(armv7m, "cpu-type", ARM_CPU_TYPE_NAME("cortex-m3"));
	qdev_prop_set_bit(armv7m, "enable-bitband", true);
	qdev_connect_clock_in(armv7m, "cpuclk", s->cpuclk);
	object_property_set_link(OBJECT(&s->armv7m), "memory", OBJECT(sys_mem), &error_abort);
	sysbus_realize(SYS_BUS_DEVICE(&s->armv7m), &error_fatal);

#ifdef AFL_ACTIVATED
	afl_t *afl = (afl_t *)g_new0(afl_t, 1);
	afl->arch.cpu = s->armv7m.cpu;
	afl->arch.ram_mr = &s->sram;

	afl_init(afl);

	__global_afl = afl;
#endif
}

static void afl_soc_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = afl_soc_realize;
}

static const TypeInfo afl_soc_info = {
    .name = TYPE_AFL_SOC,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(AFLMachineState),
    .instance_init = afl_soc_initfn,
    .class_init = afl_soc_class_init,
};

static void afl_soc_types(void)
{
    type_register_static(&afl_soc_info);
}

type_init(afl_soc_types)
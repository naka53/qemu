#include "qemu/osdep.h"
#include "qapi/error.h"
#include "hw/boards.h"
#include "hw/qdev-properties.h"
#include "hw/arm/boot.h"
#include "hw/arm/afl_soc.h"

static void afl_board_init(MachineState *m)
{
    DeviceState *dev;

    dev = qdev_new(TYPE_AFL_SOC);
    sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);

    armv7m_load_kernel(ARM_CPU(first_cpu), m->kernel_filename, AFL_ROM_BASE_ADDR, AFL_ROM_SIZE);
}

static void afl_board_machine_init(MachineClass *mc)
{
    mc->desc = "ARMv7-M AFL";
    mc->init = afl_board_init;
}

DEFINE_MACHINE("armv7m", afl_board_machine_init)

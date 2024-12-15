#include "qemu/osdep.h"
#include "qapi/error.h"
#include "hw/boards.h"
#include "hw/qdev-properties.h"
#include "hw/qdev-clock.h"
#include "hw/arm/boot.h"
#include "hw/arm/afl_soc.h"

#include "afl/config.h"
#include "afl/common.h"

#define SYSCLK_FRQ (180 * 1000 * 1000)
#define REFCLK_FRQ (90 * 1000 * 1000)

static void afl_board_init(MachineState *m)
{
    DeviceState *dev;
    Clock *sysclk;
    Clock *refclk;

    sysclk = clock_new(OBJECT(m), "SYSCLK");
    clock_set_hz(sysclk, SYSCLK_FRQ);

    refclk = clock_new(OBJECT(m), "REFCLK");
    clock_set_hz(refclk, REFCLK_FRQ);

    dev = qdev_new(TYPE_AFL_SOC);
    qdev_connect_clock_in(dev, "sysclk", sysclk);
    qdev_connect_clock_in(dev, "refclk", refclk);
    sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);

    armv7m_load_kernel(ARM_CPU(first_cpu), m->kernel_filename, AFL_ROM_BASE_ADDR, AFL_ROM_SIZE);

#ifdef GUSTAVE_ACTIVATED
    afl_init(afl, m);
#endif
}

static void afl_board_machine_init(MachineClass *mc)
{
    static const char * const valid_cpu_types[] = {
        ARM_CPU_TYPE_NAME("cortex-m3"),
        NULL
    };

    mc->desc = "ARMv7-M AFL platform";
    mc->init = afl_board_init;
    mc->valid_cpu_types = valid_cpu_types;
}

DEFINE_MACHINE("afl", afl_board_machine_init)

#ifndef AFL_TIMER_H
#define AFL_TIMER_H

#include "hw/sysbus.h"
#include "qom/object.h"
#include "hw/ptimer.h"
#include "hw/clock.h"

#define AFL_TIMER_BASE_ADDR 0x10000000
#define AFL_TIMER_SIZE      0x10

#define TYPE_AFL_TIMER "afl_timer"

OBJECT_DECLARE_SIMPLE_TYPE(AFLTimerState, AFL_TIMER)

#define AFL_TIMER_CONTROL_OFFSET    0x0000
#define AFL_TIMER_RELOAD_OFFSET     0x0004
#define AFL_TIMER_TICK_OFFSET       0x0008
#define AFL_TIMER_DIVISOR_OFFSET    0x000C

#define AFL_TIMER_CONTROL_ENABLE_MASK   0x00000001

struct AFLTimerState {
    /*< private >*/
    SysBusDevice parent_obj;
    /*< public >*/

    uint32_t control;
    uint32_t divisor;
    ptimer_state *ptimer;
    MemoryRegion iomem;
    qemu_irq irq;
    Clock *cpuclk;
};

#endif

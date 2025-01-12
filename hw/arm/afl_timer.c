#include "qemu/osdep.h"
#include "hw/arm/afl_timer.h"
#include "hw/irq.h"
#include "hw/sysbus.h"
#include "hw/qdev-clock.h"
#include "qemu/timer.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "qapi/error.h"

static void afl_timer_callback(void *opaque)
{
    AFLTimerState *s = (AFLTimerState *)opaque;

    qemu_irq_pulse(s->irq);
}

static uint64_t afl_timer_read(void *opaque, hwaddr offset,
                                  unsigned size)
{
    AFLTimerState *s = (AFLTimerState *)opaque;


    switch (offset) {
        case AFL_TIMER_CONTROL_OFFSET:
            return s->control;

        case AFL_TIMER_RELOAD_OFFSET:
            return ptimer_get_limit(s->ptimer);

        case AFL_TIMER_TICK_OFFSET:
            return ptimer_get_count(s->ptimer);

        case AFL_TIMER_DIVISOR_OFFSET:
            return s->divisor;

        default:
            qemu_log_mask(LOG_GUEST_ERROR,
                        "AFL Timer: Bad read offset 0x%" HWADDR_PRIx "\n", offset);
            break;
    }

    return 0;
}

static void afl_timer_write(void *opaque, hwaddr offset,
                               uint64_t val, unsigned size)
{
    AFLTimerState *s = (AFLTimerState *)opaque;
    uint32_t value = (uint32_t)val;

    switch (offset) {
        case AFL_TIMER_CONTROL_OFFSET:
            s->control = value;

            ptimer_transaction_begin(s->ptimer);
            if (s->control & AFL_TIMER_CONTROL_ENABLE_MASK) {
                ptimer_run(s->ptimer, 0);
            } else {
                ptimer_stop(s->ptimer);
            }
            ptimer_transaction_commit(s->ptimer);
            break;

        case AFL_TIMER_RELOAD_OFFSET:
            ptimer_transaction_begin(s->ptimer);
            ptimer_set_limit(s->ptimer, value, 0);
            ptimer_transaction_commit(s->ptimer);
            break;

        case AFL_TIMER_TICK_OFFSET:
            ptimer_transaction_begin(s->ptimer);
            if (ptimer_get_limit(s->ptimer) == 0)
                ptimer_stop(s->ptimer);

            ptimer_set_count(s->ptimer, 0);
            ptimer_transaction_commit(s->ptimer);
            break;

        case AFL_TIMER_DIVISOR_OFFSET:
            s->divisor = value;
            ptimer_set_period_from_clock(s->ptimer, s->cpuclk, s->divisor + 1);
            break;

        default:
            qemu_log_mask(LOG_GUEST_ERROR,
                        "AFL Timer: Bad write offset 0x%" HWADDR_PRIx "\n", offset);
        }
}

static const MemoryRegionOps afl_timer_ops = {
    .read = afl_timer_read,
    .write = afl_timer_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
};

static void afl_timer_cpuclk_update(void *opaque, ClockEvent event)
{
    AFLTimerState *s = AFL_TIMER(opaque);

    ptimer_transaction_begin(s->ptimer);
    ptimer_set_period_from_clock(s->ptimer, s->cpuclk, 1);
    ptimer_transaction_commit(s->ptimer);
}

static void afl_timer_reset(DeviceState *dev)
{
    AFLTimerState *s = AFL_TIMER(dev);

    ptimer_transaction_begin(s->ptimer);
    s->control = 0;

    ptimer_stop(s->ptimer);
    ptimer_set_count(s->ptimer, 0);
    ptimer_set_limit(s->ptimer, 0, 0);
    ptimer_set_period_from_clock(s->ptimer, s->cpuclk, 1);
    ptimer_transaction_commit(s->ptimer);
}

static void afl_timer_instance_init(Object *obj)
{
    SysBusDevice *sbd = SYS_BUS_DEVICE(obj);
    AFLTimerState *s = AFL_TIMER(obj);

    memory_region_init_io(&s->iomem, obj, &afl_timer_ops, s, "afl timer", AFL_TIMER_SIZE);
    sysbus_init_mmio(sbd, &s->iomem);
    sysbus_init_irq(sbd, &s->irq);

    s->cpuclk = qdev_init_clock_in(DEVICE(obj), "cpuclk",
                                   afl_timer_cpuclk_update, s, ClockUpdate);
}

static void afl_timer_realize(DeviceState *dev, Error **errp)
{
    AFLTimerState *s = AFL_TIMER(dev);
    s->ptimer = ptimer_init(afl_timer_callback, s, PTIMER_POLICY_LEGACY);

    if (!clock_has_source(s->cpuclk)) {
        error_setg(errp, "afl timer: cpuclk must be connected");
        return;
    }
}

static void afl_timer_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->reset = afl_timer_reset;
    dc->realize = afl_timer_realize;
}

static const TypeInfo afl_timer_info = {
    .name = TYPE_AFL_TIMER,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_init = afl_timer_instance_init,
    .instance_size = sizeof(AFLTimerState),
    .class_init = afl_timer_class_init,
};

static void afl_timer_register_types(void)
{
    type_register_static(&afl_timer_info);
}

type_init(afl_timer_register_types)

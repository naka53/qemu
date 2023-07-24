#include "qemu/osdep.h"
#include "hw/misc/afl_uart.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "migration/vmstate.h"

static void afl_uart_reset(DeviceState *dev)
{
    AFLUartState *s = AFL_UART(dev);

    s->uart_tx_data = 0x00000000;
    s->uart_tx_status = 0x0000001F;
    s->uart_tx_mask = 0x00000000;
    s->uart_rx_data = 0x00000000;
    s->uart_rx_status = 0x00000001;
    s->uart_rx_mask = 0x00000000;
    s->uart_rx_timeout = 0x00000000;
    s->uart_configuration = 0x00000000;
    s->uart_divider = 0x00000000;
    s->uart_enable = 0x00000000;
}

static uint64_t afl_uart_read(void *opaque, hwaddr addr,
                                     unsigned int size)
{
    AFLUartState *s = opaque;

    switch (addr) {
    case UART_TX_DATA:
        return s->uart_tx_data;
    case UART_TX_STATUS:
        return s->uart_tx_status;
    case UART_TX_MASK:
        return s->uart_tx_mask;
    case UART_RX_DATA:
        s->uart_rx_data = getchar();
        return s->uart_rx_data;
    case UART_RX_STATUS:
        return s->uart_rx_status;
    case UART_RX_MASK:
        return s->uart_rx_mask;
    case UART_RX_TIMEOUT:
        return s->uart_rx_timeout;
    case UART_CONFIGURATION:
        return s->uart_configuration;
    case UART_DIVIDER:
        return s->uart_divider;
    case UART_ENABLE:
        return s->uart_enable;
    }

    return 0;
}

static void afl_uart_write(void *opaque, hwaddr addr,
                       uint64_t val64, unsigned int size)
{
    AFLUartState *s = opaque;
    uint32_t value = val64;

    switch (addr) {
    case UART_TX_DATA:
        s->uart_tx_data = value;
        putchar(s->uart_tx_data);
        return;
    case UART_TX_STATUS:
        s->uart_tx_status = value;
        return;
    case UART_TX_MASK:
        s->uart_tx_mask = value;
        return;
    case UART_RX_DATA:
        s->uart_rx_data = value;
        return;
    case UART_RX_STATUS:
        s->uart_rx_status = value;
        return;
    case UART_RX_MASK:
        s->uart_rx_mask = value;
        return;
    case UART_RX_TIMEOUT:
        s->uart_rx_timeout = value;
        return;
    case UART_CONFIGURATION:
        s->uart_configuration = value;
        return;
    case UART_DIVIDER:
        s->uart_divider = value;
        return;
    case UART_ENABLE:
        s->uart_enable = value;
        return;
    }
}

static const MemoryRegionOps afl_uart_ops = {
    .read = afl_uart_read,
    .write = afl_uart_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static void afl_uart_init(Object *obj)
{
    AFLUartState *s = AFL_UART(obj);

    memory_region_init_io(&s->iomem, obj, &afl_uart_ops, s,
                          TYPE_AFL_UART, 0x1000);
    sysbus_init_mmio(SYS_BUS_DEVICE(obj), &s->iomem);
}

static const VMStateDescription vmstate_afl_uart = {
    .name = "AFL UART state",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (VMStateField[]) {
            VMSTATE_UINT32(uart_tx_data, AFLUartState),
            VMSTATE_UINT32(uart_tx_status, AFLUartState),
            VMSTATE_UINT32(uart_tx_mask, AFLUartState),
            VMSTATE_UINT32(uart_rx_data, AFLUartState),
            VMSTATE_UINT32(uart_rx_status, AFLUartState),
            VMSTATE_UINT32(uart_rx_mask, AFLUartState),
            VMSTATE_UINT32(uart_rx_timeout, AFLUartState),
            VMSTATE_UINT32(uart_configuration, AFLUartState),
            VMSTATE_UINT32(uart_divider, AFLUartState),
            VMSTATE_UINT32(uart_enable, AFLUartState),
            VMSTATE_END_OF_LIST()
        }
};

static void afl_uart_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->reset = afl_uart_reset;
    dc->vmsd = &vmstate_afl_uart;
}

static const TypeInfo afl_uart_info = {
    .name          = TYPE_AFL_UART,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(AFLUartState),
    .instance_init = afl_uart_init,
    .class_init    = afl_uart_class_init,
};

static void afl_uart_register_types(void)
{
    type_register_static(&afl_uart_info);
}

type_init(afl_uart_register_types)
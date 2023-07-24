#ifndef HW_AFL_UART_H
#define HW_AFL_UART_H

#include "hw/sysbus.h"
#include "qom/object.h"

#define UART_TX_DATA        0x00
#define UART_TX_STATUS      0x04
#define UART_TX_MASK        0x08
#define UART_RX_DATA        0x10
#define UART_RX_STATUS      0x14
#define UART_RX_MASK        0x18
#define UART_RX_TIMEOUT     0x1C
#define UART_CONFIGURATION  0x20
#define UART_DIVIDER        0x24
#define UART_ENABLE         0x2C

#define TYPE_AFL_UART "afl-uart"
OBJECT_DECLARE_SIMPLE_TYPE(AFLUartState, AFL_UART)

struct AFLUartState {
    /* <private> */
    SysBusDevice parent_obj;

    /* <public> */
    MemoryRegion iomem;

    uint32_t uart_tx_data;
    uint32_t uart_tx_status;
    uint32_t uart_tx_mask;
    uint32_t uart_rx_data;
    uint32_t uart_rx_status;
    uint32_t uart_rx_mask;
    uint32_t uart_rx_timeout;
    uint32_t uart_configuration;
    uint32_t uart_divider;
    uint32_t uart_enable;
};

#endif /* HW_AFL_UART_H */
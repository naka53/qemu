#ifndef __AFL_SOC_H__
#define __AFL_SOC_H__

#include "hw/arm/armv7m.h"
#include "qom/object.h"
#include "hw/clock.h"

#define TYPE_AFL_SOC "afl-soc"
OBJECT_DECLARE_SIMPLE_TYPE(AFLMachineState, AFL_SOC)

#define AFL_ROM_BASE_ADDR      0x00000000
#define AFL_ROM_SIZE           0x10000
#define AFL_SRAM_BASE_ADDR     0x20000000
#define AFL_SRAM_SIZE          0x10000

#define AFL_IRQ_NUMBER         1

#define CPUCLK_FRQ (180 * 1000 * 1000)

struct AFLMachineState {
   SysBusDevice parent_obj;

   ARMv7MState armv7m;

   MemoryRegion sram;
   MemoryRegion rom;

   Clock *cpuclk;
};

// __AFL_SOC_H__
#endif
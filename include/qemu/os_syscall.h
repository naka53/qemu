#ifndef __OS_SYSCALL_H__
#define __OS_SYSCALL_H__

#include <stdint.h>
#include <stddef.h>

typedef enum
{           
   OS_EPERM                         =   1
} os_ret_t;

typedef enum
{
   OS_SYSCALL_FORK                  =  0
} os_syscall_id_t;

typedef struct
{
   uint32_t             nargs;
   uint32_t             arg1;
   uint32_t             arg2;
   uint32_t             arg3;
   uint32_t             arg4;
   uint32_t             arg5;
} os_syscall_args_t;

#endif
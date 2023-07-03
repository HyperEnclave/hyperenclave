/* An implementation of the rand function */

.equ RDRAND_RETRY_TIMES,    10

.macro DECLARE_LOCAL_FUNC name
    .globl \name
    .hidden \name
    .type \name, @function
\name:
.endm

/* 
 * -------------------------------------
 * extern "C" uint32_t do_rdrand(uint32_t *rand);
 * return value:
 *	non-zero: rdrand succeeded
 *	zero: rdrand failed
 * -------------------------------------
 */
DECLARE_LOCAL_FUNC do_rdrand
   mov $RDRAND_RETRY_TIMES, %ecx
.Lrdrand_retry:
    .byte 0x0F, 0xC7, 0xF0	    /* rdrand %eax */
    jc .Lrdrand_return
    dec %ecx
    jnz .Lrdrand_retry
    xor %rax, %rax
    ret
.Lrdrand_return:
    mov %rdi, %rcx
    movl %eax, (%rcx)
    mov $1, %rax
    ret

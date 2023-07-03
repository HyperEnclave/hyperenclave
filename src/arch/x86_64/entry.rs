// Copyright (C) 2023 Ant Group CO., Ltd. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::percpu::PerCpu;

unsafe extern "sysv64" fn switch_stack(cpu_id: usize, linux_sp: usize) -> i32 {
    let cpu_data = PerCpu::from_id(cpu_id);
    let hv_sp = cpu_data.stack_top();
    let mut ret;
    asm!("
        mov rcx, rsp
        mov rsp, {0}
        push rcx
        call {1}
        pop rsp",
        in(reg) hv_sp,
        sym crate::entry,
        in("rdi") cpu_id,
        in("rsi") linux_sp,
        lateout("rax") ret,
    );
    ret
}

#[naked]
#[no_mangle]
pub unsafe extern "C" fn arch_entry(_cpu_id: usize) -> i32 {
    asm!("
        // rip is pushed
        cli
        push rbp
        push rbx
        push r12
        push r13
        push r14
        push r15

        mov rsi, rsp
        call {0}

        pop r15
        pop r14
        pop r13
        pop r12
        pop rbx
        pop rbp
        ret
        // rip will pop when return",
        sym switch_stack,
        options(noreturn),
    );
}

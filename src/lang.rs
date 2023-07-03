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

use core::alloc::Layout;
use core::panic::PanicInfo;

use crate::error::HvResult;
use crate::percpu::{CpuState, PerCpu};

#[allow(dead_code)]
fn try_handle_panic(cpu_data: &mut PerCpu) -> HvResult {
    let ret_code = if cpu_data.state != CpuState::HvDisabled && cpu_data.vcpu.in_hypercall() {
        hv_err!(EIO).code() as usize
    } else {
        0
    };
    match cpu_data.state {
        CpuState::HvEnabled => cpu_data.deactivate_vmm(ret_code)?,
        CpuState::EnclaveRunning => {
            cpu_data.enclave_exit(0)?;
            cpu_data.deactivate_vmm(ret_code)?;
        }
        _ => return hv_result_err!(EIO, "Hypervisor is not enabled!"),
    }
    Ok(())
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    let cpu_data = PerCpu::from_local_base_mut();
    error!("\n{}\nCurrent Cpu: {:#x?}", info, cpu_data);
    // Marks the panic CPU abnormal, and stop itself
    crate::logging::set_vmm_state(cpu_data.cpu_id, 0);
    loop {}
}

#[lang = "oom"]
fn oom(_: Layout) -> ! {
    panic!("out of memory");
}

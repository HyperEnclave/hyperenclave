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

use crate::ffi::HEADER_PTR;
use crate::logging::HEFeature;
use crate::memory::HostVirtAddr;
use crate::percpu::PER_CPU_SIZE;

/// Max numbuer of convertible memory regions
const MAX_CONV_MEM_REGIONS: usize = 32;
/// Max numbuer of initialized EPC regions
const MAX_INIT_EPC_REGIONS: usize = MAX_CONV_MEM_REGIONS;

#[derive(Debug, Clone, Copy)]
pub struct MemRange {
    pub start: usize,
    pub size: usize,
}

#[repr(C)]
#[derive(Debug)]
pub struct HvHeader {
    pub signature: [u8; 8],
    pub core_size: usize,
    pub percpu_size: usize,
    pub entry: usize,
    pub max_cpus: u32,
    pub online_cpus: u32,
    pub arm_linux_hyp_vectors: u64,
    pub arm_linux_hyp_abi: u32,
    pub tpm_type: u32,
    pub tpm_mmio_size: u32,
    pub tpm_mmio_pa: usize,

    pub safe_print_seq_start_pa: u64,
    pub percpu_offset_pa: u64,
    pub vmm_states_pa: u64,
    pub feature_mask: HEFeature,

    /// The size of hypervisor's heap (in bytes), must 4kB aligned.
    pub hv_heap_size: HostVirtAddr,

    /// Array of convertible memory regions.
    pub conv_mem_ranges: [MemRange; MAX_CONV_MEM_REGIONS],
    /// Number of convertible memory regions in 'conv_mem_ranges'.
    pub nr_conv_mem: u32,
    /// Array of initialized EPC regions.
    pub init_epc_ranges: [MemRange; MAX_INIT_EPC_REGIONS],
    /// Number of initialized EPC regions in 'init_epc_ranges'.
    pub nr_init_epc: u32,
}

impl HvHeader {
    pub fn get<'a>() -> &'a Self {
        unsafe { &*HEADER_PTR }
    }
}

#[repr(C)]
struct HvHeaderStuff {
    signature: [u8; 8],
    core_size: unsafe extern "C" fn(),
    percpu_size: usize,
    entry: unsafe extern "C" fn(),
    max_cpus: u32,
    online_cpus: u32,
    arm_linux_hyp_vectors: u64,
    arm_linux_hyp_abi: u32,
    tpm_type: u32,
    tpm_mmio_size: u32,
    tpm_mmio_pa: u64,
    safe_print_seq_start_pa: u64,
    percpu_offset_pa: u64,
    vmm_states_pa: u64,
    feature_mask: HEFeature,
    hv_heap_size: HostVirtAddr,
    conv_mem_ranges: [MemRange; MAX_CONV_MEM_REGIONS],
    nr_conv_mem: u32,
    init_epc_ranges: [MemRange; MAX_INIT_EPC_REGIONS],
    nr_init_epc: u32,
}

extern "C" {
    fn __entry_offset();
    fn __core_size();
}

#[used]
#[link_section = ".header"]
static HEADER_STUFF: HvHeaderStuff = HvHeaderStuff {
    signature: *b"HYPERENC",
    core_size: __core_size,
    percpu_size: PER_CPU_SIZE,
    entry: __entry_offset,
    max_cpus: 0,
    online_cpus: 0,
    arm_linux_hyp_vectors: 0,
    arm_linux_hyp_abi: 0,
    tpm_type: 0,
    tpm_mmio_size: 0,
    tpm_mmio_pa: 0,
    safe_print_seq_start_pa: 0,
    percpu_offset_pa: 0,
    vmm_states_pa: 0,
    feature_mask: HEFeature::empty(),
    hv_heap_size: 0,
    conv_mem_ranges: [MemRange { start: 0, size: 0 }; MAX_CONV_MEM_REGIONS],
    nr_conv_mem: 0,
    init_epc_ranges: [MemRange { start: 0, size: 0 }; MAX_INIT_EPC_REGIONS],
    nr_init_epc: 0,
};

static_assertions::const_assert_eq!(
    core::mem::size_of::<HvHeaderStuff>(),
    core::mem::size_of::<HvHeader>()
);

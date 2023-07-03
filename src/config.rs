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

use core::fmt::Debug;
use core::{mem::size_of, slice};

use crate::consts::HV_BASE;
use crate::header::HvHeader;
use crate::memory::MemFlags;
use crate::percpu::PER_CPU_SIZE;

const HV_MAX_IOMMU_UNITS: usize = 16;
const HV_MAX_RMRR_RANGE: usize = 4;

#[derive(Debug)]
#[repr(C, packed)]
pub struct HvMemoryRegion {
    pub phys_start: u64,
    pub virt_start: u64,
    pub size: u64,
    pub flags: MemFlags,
}

#[derive(Debug)]
#[repr(C, packed)]
pub struct HvIommuInfo {
    pub base: u64,
    pub size: u32,
}

#[derive(Debug)]
#[repr(C, packed)]
pub struct HvRmrrRange {
    pub base: u64,
    pub limit: u64,
}

#[cfg(target_arch = "x86_64")]
#[derive(Debug)]
#[repr(C, packed)]
struct ArchPlatformInfo {
    iommu_units: [HvIommuInfo; HV_MAX_IOMMU_UNITS],
    rmrr_ranges: [HvRmrrRange; HV_MAX_RMRR_RANGE],
}

#[derive(Debug)]
#[repr(C, packed)]
struct PlatformInfo {
    arch: ArchPlatformInfo,
}

/// General descriptor of the system.
#[derive(Debug)]
#[repr(C, packed)]
pub struct HvSystemConfig {
    pub hypervisor_memory: HvMemoryRegion,
    platform_info: PlatformInfo,
    num_memory_regions: u32,
    // ConfigLayout placed here.
}

/// A dummy layout with all variant-size fields empty.
#[derive(Debug)]
#[repr(C, packed)]
struct ConfigLayout {
    mem_regions: [HvMemoryRegion; 0],
}

impl HvSystemConfig {
    pub fn get<'a>() -> &'a Self {
        let header = HvHeader::get();
        let core_and_percpu_size =
            header.core_size as usize + header.max_cpus as usize * PER_CPU_SIZE;
        unsafe { &*((HV_BASE + core_and_percpu_size) as *const Self) }
    }

    fn config_ptr<T>(&self) -> *const T {
        unsafe { (self as *const HvSystemConfig).add(1) as _ }
    }

    pub const fn size(&self) -> usize {
        size_of::<Self>() + self.num_memory_regions as usize * size_of::<HvMemoryRegion>()
    }

    pub fn iommu_units(&self) -> &[HvIommuInfo] {
        let mut n = 0;
        while n < HV_MAX_IOMMU_UNITS && self.platform_info.arch.iommu_units[n].base != 0 {
            n += 1;
        }
        &self.platform_info.arch.iommu_units[..n]
    }
    pub fn rmrr_ranges(&self) -> &[HvRmrrRange] {
        let mut n = 0;
        while n < HV_MAX_RMRR_RANGE && self.platform_info.arch.rmrr_ranges[n].limit != 0 {
            n += 1;
        }
        &self.platform_info.arch.rmrr_ranges[..n]
    }

    pub fn mem_regions(&self) -> &[HvMemoryRegion] {
        unsafe { slice::from_raw_parts(self.config_ptr(), self.num_memory_regions as usize) }
    }
}

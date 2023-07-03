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

use crate::arch::{vmm::IoPageTable, HostPageTable, NestedPageTable};
use crate::config::HvSystemConfig;
use crate::consts::{HV_BASE, PER_CPU_SIZE};
use crate::error::HvResult;
use crate::header::HvHeader;
use crate::intervaltree::IntervalTree;
use crate::memory::addr::{phys_to_virt, GuestPhysAddr, HostPhysAddr, HostVirtAddr};
use crate::memory::cmr::NR_INIT_EPC_RANGES;
use crate::memory::{MemFlags, MemoryRegion, MemorySet};

#[derive(Debug)]
pub struct Cell {
    /// Guest physical memory set.
    pub gpm: MemorySet<NestedPageTable>,
    /// Host virtual memory set.
    pub hvm: MemorySet<HostPageTable>,
    /// DMA memory set.
    pub dma_regions: MemorySet<IoPageTable>,
    /// Normal world region which can be accessed by hypervisor.
    normal_world_mem_region: IntervalTree,
}

impl Cell {
    fn new_root() -> HvResult<Self> {
        let header = HvHeader::get();
        let sys_config = HvSystemConfig::get();

        let hv_phys_start = sys_config.hypervisor_memory.phys_start as usize;
        let hv_phys_size = sys_config.hypervisor_memory.size as usize;
        let mut gpm = MemorySet::new();
        let mut hvm = MemorySet::new();
        let mut dma_regions = MemorySet::new();
        let mut normal_world_mem_region = IntervalTree::new();

        // Init guest physical memory set, create hypervisor page table.
        //
        // map hypervisor memory to empty in gpm
        // It returns the plaintext view of the empty page
        // if untrusted world dump trusted memory
        gpm.insert(MemoryRegion::new_with_empty_mapper(
            hv_phys_start,
            hv_phys_size,
            MemFlags::READ | MemFlags::ENCRYPTED,
        ))?;
        // preventing guest vm read out the encrypted view of EPC
        // from high addr with c-bit = 1
        // expected behavior: return plaintext view of the empty page
        #[cfg(feature = "sme")]
        gpm.insert(MemoryRegion::new_with_empty_mapper(
            crate::memory::addr::phys_encrypted(hv_phys_start),
            hv_phys_size,
            MemFlags::READ | MemFlags::ENCRYPTED,
        ))?;
        // map epc memory to empty page in gpm
        for epc_range in &header.init_epc_ranges[..*NR_INIT_EPC_RANGES] {
            let epc_start_hpa = epc_range.start as HostPhysAddr;
            let epc_size = epc_range.size;
            info!(
                "map epc to empty page in gpm, epc_range: [{:#x}, {:#x}], {:#x}",
                epc_start_hpa,
                epc_start_hpa + epc_size - 1,
                epc_size
            );
            gpm.insert(MemoryRegion::new_with_empty_mapper(
                epc_start_hpa,
                epc_size,
                MemFlags::READ | MemFlags::ENCRYPTED,
            ))?;
            #[cfg(feature = "sme")]
            gpm.insert(MemoryRegion::new_with_empty_mapper(
                crate::memory::addr::phys_encrypted(epc_start_hpa),
                epc_size,
                MemFlags::READ | MemFlags::ENCRYPTED,
            ))?;
        }

        // all physical memory regions
        for region in sys_config.mem_regions() {
            let r = MemoryRegion::new_with_offset_mapper(
                region.virt_start as GuestPhysAddr,
                region.phys_start as HostPhysAddr,
                region.size as usize,
                region.flags - MemFlags::ENCRYPTED, // guest should not read decrypted data
            );
            if region.flags.contains(MemFlags::DMA) {
                dma_regions.insert(r.clone())?;
            } else {
                for rmrr_range in sys_config.rmrr_ranges() {
                    //if region contains rmrr_range
                    if region.phys_start <= rmrr_range.base
                        && rmrr_range.limit <= region.phys_start + region.size
                    {
                        dma_regions.insert(r.clone())?;
                        break;
                    }
                }
            }
            gpm.insert(r)?;
        }

        // Init host virtual memory set, create host page table.
        let core_and_percpu_size =
            header.core_size as usize + header.max_cpus as usize * PER_CPU_SIZE;
        // hypervisor core
        hvm.insert(MemoryRegion::new_with_offset_mapper(
            HV_BASE,
            hv_phys_start,
            header.core_size,
            MemFlags::READ | MemFlags::WRITE | MemFlags::EXECUTE | MemFlags::ENCRYPTED,
        ))?;
        // configurations & hypervisor free memory
        hvm.insert(MemoryRegion::new_with_offset_mapper(
            HV_BASE + core_and_percpu_size,
            hv_phys_start + core_and_percpu_size,
            hv_phys_size - core_and_percpu_size,
            MemFlags::READ | MemFlags::WRITE | MemFlags::ENCRYPTED,
        ))?;
        // guest RAM
        hvm.insert(MemoryRegion::new_with_offset_mapper(
            header.tpm_mmio_pa,
            header.tpm_mmio_pa,
            header.tpm_mmio_size as usize,
            MemFlags::READ | MemFlags::WRITE,
        ))?;
        println!("tpm mmio is mapped va={:#x}", header.tpm_mmio_pa);
        for region in sys_config.mem_regions() {
            if region.flags.contains(MemFlags::DMA) {
                let hv_virt_start = phys_to_virt(region.virt_start as GuestPhysAddr);
                if hv_virt_start < region.virt_start as GuestPhysAddr {
                    return hv_result_err!(
                        EINVAL,
                        format!(
                            "Guest physical address {:#x} is too large",
                            region.virt_start
                        )
                    );
                }
                hvm.insert(MemoryRegion::new_with_offset_mapper(
                    hv_virt_start,
                    region.phys_start as HostPhysAddr,
                    region.size as usize,
                    MemFlags::READ | MemFlags::WRITE,
                ))?;
                // Support hardware encrypt when swap out EPC page to guest RAM
                #[cfg(feature = "sme")]
                hvm.insert(MemoryRegion::new_with_offset_mapper(
                    region.virt_start as HostVirtAddr,
                    region.phys_start as HostPhysAddr,
                    region.size as usize,
                    MemFlags::READ | MemFlags::WRITE | MemFlags::ENCRYPTED,
                ))?;
                normal_world_mem_region.insert(
                    (region.phys_start as usize)..(region.phys_start + region.size) as usize,
                )?;
            }
        }
        // EPC memory
        {
            debug!("NR_INIT_EPC_RANGES: {}", *NR_INIT_EPC_RANGES);
            for epc_range in &header.init_epc_ranges[..*NR_INIT_EPC_RANGES] {
                let epc_start_hpa = epc_range.start as HostPhysAddr;
                let epc_start_hva = phys_to_virt(epc_start_hpa) as HostVirtAddr;
                let epc_size = epc_range.size;
                debug!(
                    "epc_range: [{:#x}, {:#x}], {:#x}",
                    epc_start_hpa,
                    epc_start_hpa + epc_size - 1,
                    epc_size
                );
                hvm.insert(MemoryRegion::new_with_offset_mapper(
                    epc_start_hva,
                    epc_start_hpa,
                    epc_size,
                    MemFlags::READ | MemFlags::WRITE | MemFlags::ENCRYPTED,
                ))?;
            }
        }
        // IOMMU
        for iommu in sys_config.iommu_units() {
            let paddr = iommu.base as HostPhysAddr;
            hvm.insert(MemoryRegion::new_with_offset_mapper(
                phys_to_virt(paddr),
                paddr,
                iommu.size as usize,
                MemFlags::READ | MemFlags::WRITE,
            ))?;
        }

        Ok(Self {
            gpm,
            hvm,
            dma_regions,
            normal_world_mem_region,
        })
    }

    /// Whether [gpaddr, gpaddr + 4kB) is accessible by hypervisor.
    pub fn is_valid_normal_world_gpaddr(&self, gpaddr: GuestPhysAddr) -> bool {
        self.normal_world_mem_region.contains(&gpaddr)
    }
}

lazy_static! {
    pub static ref ROOT_CELL: Cell = Cell::new_root().unwrap();
}

pub fn init() -> HvResult {
    crate::arch::vmm::check_hypervisor_feature()?;

    lazy_static::initialize(&ROOT_CELL);

    info!("Root cell init end.");
    debug!("{:#x?}", &*ROOT_CELL);
    Ok(())
}

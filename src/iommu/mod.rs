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

use alloc::vec::Vec;
use spin::Once;

use crate::arch::vmm::{IoPageTable, Iommu};
use crate::cell::ROOT_CELL;
use crate::config::HvSystemConfig;
use crate::error::HvResult;

pub use crate::config::HvIommuInfo as IommuInfo;

pub trait GenericIommu {
    fn set_io_page_table(&self, pt: &IoPageTable) -> HvResult;
    fn set_enabled(&self, enabled: bool) -> HvResult;
}

static IOMMU_LIST: Once<Vec<Iommu>> = Once::new();
//IOMMU_LIST initialized & allocate memory only once, dealloc when hypervisor_disable, no memory leak here

pub fn init() -> HvResult {
    info!("Init IOMMU...");

    let sys_config = HvSystemConfig::get();
    let iommu_units = sys_config.iommu_units();
    let mut list = Vec::with_capacity(iommu_units.len());
    for info in iommu_units {
        info!("Setup IOMMU: {:#x?}", info);
        let iommu = Iommu::new(info)?;
        iommu.set_io_page_table(ROOT_CELL.dma_regions.page_table())?;
        iommu.set_enabled(true)?;
        list.push(iommu);
    }
    IOMMU_LIST.call_once(|| list);

    Ok(())
}

pub fn disable() -> HvResult {
    info!("Disable IOMMU...");
    for iommu in IOMMU_LIST.get().ok_or(hv_err!(EINVAL))? {
        info!("try disable one iommu...");
        iommu.set_enabled(false)?;
        info!("disable one iommu finished");
    }
    info!("Disable IOMMU finished");
    Ok(())
}

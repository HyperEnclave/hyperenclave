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

#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
#![cfg_attr(test, allow(dead_code))]
#![feature(asm)]
#![feature(lang_items)]
#![feature(global_asm)]
#![feature(concat_idents)]
#![feature(naked_functions)]
#![allow(unaligned_references)]

#[macro_use]
extern crate alloc;
#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;

#[macro_use]
mod logging;
#[macro_use]
mod error;
#[macro_use]
mod hypercall;

mod cell;
mod config;
mod consts;
mod cpumask;
mod enclave;
mod ffi;
mod header;
mod intervaltree;
mod iommu;
mod memory;
mod percpu;
mod stats;

#[cfg(not(test))]
mod lang;

#[cfg(target_arch = "x86_64")]
#[path = "arch/x86_64/mod.rs"]
mod arch;

use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

use config::HvSystemConfig;
use enclave::reclaim;
use error::HvResult;
use header::HvHeader;
use hypercall::tc;
use percpu::PerCpu;

static ENTERED_CPUS: AtomicUsize = AtomicUsize::new(0);
static INITED_CPUS: AtomicUsize = AtomicUsize::new(0);
static INIT_EARLY_OK: AtomicUsize = AtomicUsize::new(0);
static INIT_LATE_OK: AtomicUsize = AtomicUsize::new(0);
static ERROR_NUM: AtomicI32 = AtomicI32::new(0);

fn has_err() -> bool {
    ERROR_NUM.load(Ordering::Acquire) != 0
}

fn wait_for_other_completed(counter: &AtomicUsize, max_value: usize) -> HvResult {
    while !has_err() && counter.load(Ordering::Acquire) < max_value {
        core::hint::spin_loop();
    }
    if has_err() {
        // Here replace hv_result_err!(num, msg) with error!(msg) + hv_result_err!(num)
        // to avoid using heap memory before heap init
        error!("Other cpu init failed!");
        hv_result_err!(EBUSY)
    } else {
        Ok(())
    }
}

fn primary_init_early() -> HvResult {
    logging::init();
    info!("Primary CPU init early...");
    cpumask::check_max_cpus()?;

    let system_config = HvSystemConfig::get();
    println!(
        "\n\
        Initializing hypervisor...\n\
        build_mode = {}\n\
        log_level = {}\n\
        arch = {}\n\
        vendor = {}\n\
        stats = {}\n\
        sme = {}\n\
        epc = {}\n\
        ",
        option_env!("MODE").unwrap_or(""),
        option_env!("LOG").unwrap_or(""),
        option_env!("ARCH").unwrap_or(""),
        option_env!("VENDOR").unwrap_or(""),
        option_env!("STATS").unwrap_or("off"),
        option_env!("SME").unwrap_or("off"),
        option_env!("EPC").unwrap_or("epc48"),
    );

    info!("Hypervisor header: {:#x?}", HvHeader::get());
    debug!("System config: {:#x?}", system_config);

    reclaim::init();
    memory::init()?;
    cell::init()?;

    INIT_EARLY_OK.store(1, Ordering::Release);
    Ok(())
}

fn primary_init_late() -> HvResult {
    info!("Primary CPU init late...");

    logging::hhbox_init()?;

    iommu::init()?;
    if !tc::tc_init() {
        println!("HyperEnclave: tpm or cyrpto module initialization failed");
        return hv_result_err!(EIO);
    }

    INIT_LATE_OK.store(1, Ordering::Release);
    Ok(())
}

fn main(cpu_id: usize, linux_sp: usize) -> HvResult {
    let cpu_data = PerCpu::from_id_mut(cpu_id);
    let online_cpus = HvHeader::get().online_cpus as usize;
    let is_primary = ENTERED_CPUS.fetch_add(1, Ordering::SeqCst) == 0;
    wait_for_other_completed(&ENTERED_CPUS, online_cpus)?;
    println!(
        "{} CPU {} entered.",
        if is_primary { "Primary" } else { "Secondary" },
        cpu_id
    );

    if is_primary {
        primary_init_early()?;
    } else {
        wait_for_other_completed(&INIT_EARLY_OK, 1)?;
    }

    cpu_data.init(cpu_id, linux_sp, &cell::ROOT_CELL)?;
    println!("CPU {} init OK.", cpu_id);
    INITED_CPUS.fetch_add(1, Ordering::SeqCst);
    wait_for_other_completed(&INITED_CPUS, online_cpus)?;

    if is_primary {
        primary_init_late()?;
    } else {
        wait_for_other_completed(&INIT_LATE_OK, 1)?;
    }

    cpu_data.activate_vmm()
}

fn restore_states(cpu_id: usize) {
    let cpu_data = PerCpu::from_id_mut(cpu_id);
    if cpu_data.state != percpu::CpuState::HvEnabled {
        return;
    }

    let _ = iommu::disable();
    cpu_data.return_to_linux();
}

extern "sysv64" fn entry(cpu_id: usize, linux_sp: usize) -> i32 {
    let mut code = 0;
    if let Err(e) = main(cpu_id, linux_sp) {
        error!("{:?}", e);
        ERROR_NUM.store(e.code(), Ordering::Release);
        code = e.code();
    }
    restore_states(cpu_id);
    println!("CPU {} return back to driver with code {}.", cpu_id, code);
    code
}

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

use {
    crate::cpumask::{CpuMask, CPU_MASK_LEN},
    crate::error::HvResult,
    crate::header::HvHeader,
    crate::memory::{self, addr},
    crate::percpu::PerCpu,
    crate::{hv_err, hv_result_err},
    alloc::vec::Vec,
    bitflags::bitflags,
    core::fmt,
    core::sync::atomic::{AtomicUsize, Ordering},
    log::{self, Level, LevelFilter, Log, Metadata, Record},
    spin::mutex::SpinMutex,
};

pub fn init() {
    log::set_logger(&SimpleLogger).unwrap();
    log::set_max_level(match option_env!("LOG") {
        Some("error") => LevelFilter::Error,
        Some("warn") => LevelFilter::Warn,
        Some("info") => LevelFilter::Info,
        Some("debug") => LevelFilter::Debug,
        Some("trace") => LevelFilter::Trace,
        _ => LevelFilter::Off,
    });
}

#[cfg(not(test))]
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ({
        $crate::logging::print(format_args!($($arg)*));
    });
}

#[cfg(not(test))]
#[macro_export]
macro_rules! println {
    ($fmt:expr) => (print!(concat!($fmt, "\n")));
    ($fmt:expr, $($arg:tt)*) => (print!(concat!($fmt, "\n"), $($arg)*));
}

/// Add escape sequence to print with color in Linux console
macro_rules! with_color {
    ($args: ident, $color_code: ident) => {{
        format_args!("\u{1B}[{}m{}\u{1B}[0m", $color_code as u8, $args)
    }};
}

fn print_in_color(args: fmt::Arguments, color_code: u8) {
    if INIT_HHBOX_LOG_OK.load(Ordering::Acquire) == 1 {
        log_store(&format!("[{}] {}", PerCpu::from_local_base().cpu_id, args)[..]);
    }
    crate::arch::serial::putfmt(with_color!(args, color_code));
}

#[allow(dead_code)]
pub fn print(args: fmt::Arguments) {
    if INIT_HHBOX_LOG_OK.load(Ordering::Acquire) == 1 {
        log_store(&format!("[{}] {}", PerCpu::from_local_base().cpu_id, args)[..]);
    }
    crate::arch::serial::putfmt(args);
}

struct SimpleLogger;

impl Log for SimpleLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }
    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        print_in_color(
            format_args!(
                "[{}][{}] {}\n",
                record.level(),
                crate::arch::cpu::id(),
                record.args(),
            ),
            level_to_color_code(record.level()),
        );
    }
    fn flush(&self) {}
}

fn level_to_color_code(level: Level) -> u8 {
    match level {
        Level::Error => 31, // Red
        Level::Warn => 93,  // BrightYellow
        Level::Info => 34,  // Blue
        Level::Debug => 32, // Green
        Level::Trace => 90, // BrightBlack
    }
}

const STRUCT_LOGBUF_LEN: usize = 8192;
const BUF_LEN: usize = 8160;
const BUF_OFFSET: usize = 32;

#[repr(C)]
struct PrintkSafeSeqBuf {
    len: i32,
    message_lost: i32,
    irq_work: [u8; 24],
    buffer: [u8; BUF_LEN],
}

bitflags! {
    /// HyperEnclave features.
    pub struct HEFeature: u64 {
        const HHBOX_LOG        = 1 << 0;
        const HHBOX_CRASH      = 1 << 1;
    }
}

static INIT_HHBOX_LOG_OK: AtomicUsize = AtomicUsize::new(0);
static INIT_HHBOX_CRASH_OK: AtomicUsize = AtomicUsize::new(0);

pub fn hhbox_init() -> HvResult {
    let header = HvHeader::get();

    println!("max cpus: {}", header.max_cpus);
    info!("HyperEnclave features: {:?}", header.feature_mask);
    if header.feature_mask.contains(HEFeature::HHBOX_LOG) {
        if VEC_PERCPU_VA.is_empty() {
            return hv_result_err!(EFAULT, "Invalid safe_print_seq addr");
        }
        INIT_HHBOX_LOG_OK.store(1, Ordering::Release);
        println!("Init HHBox log feature ok");
    }

    if header.feature_mask.contains(HEFeature::HHBOX_CRASH) {
        if *VMM_STATES_VA == 0 {
            return hv_result_err!(EFAULT, "Invalid vmm_states addr");
        }
        INIT_HHBOX_CRASH_OK.store(1, Ordering::Release);
        println!("Init HHBox crash feature ok");
    }

    Ok(())
}

pub fn hhbox_disable() {
    INIT_HHBOX_LOG_OK.store(0, Ordering::Release);
    INIT_HHBOX_CRASH_OK.store(0, Ordering::Release);
}

/// Record log to the linux percpu buffer safe_print_seq
/// Avaliable after cpus inited
pub fn log_store(s: &str) {
    let cpuid = PerCpu::from_local_base().cpu_id;
    let safe_print_seq = (*VEC_PERCPU_VA)[cpuid] as *mut PrintkSafeSeqBuf;
    let s_len = s.bytes().len();
    let s_bytes = s.as_bytes();

    let mut len;
    let msg_text;
    unsafe {
        len = (*safe_print_seq).len as usize;
        if len >= BUF_LEN - 1 {
            (*safe_print_seq).len = 0;
            (*safe_print_seq).message_lost += 1;
            len = 0;
        }
        msg_text = (safe_print_seq as *mut u8).offset((len + BUF_OFFSET) as isize);
    }
    let log_len = if BUF_LEN - len - 1 < s_len {
        BUF_LEN - len - 1
    } else {
        s_len
    };
    unsafe {
        for i in 0..log_len {
            *msg_text.offset(i as isize) = s_bytes[i];
        }
        (*safe_print_seq).len += log_len as i32;
    }
}

pub fn set_vmm_state(cpuid: usize, state: i32) {
    if INIT_HHBOX_CRASH_OK.load(Ordering::Acquire) == 1 {
        static VMM_STATE_LOCK: SpinMutex<()> = SpinMutex::new(());
        let vmm_states = unsafe { &mut *((*VMM_STATES_VA) as *mut CpuMask) };
        let _lock = VMM_STATE_LOCK.lock();

        if state == 1 {
            vmm_states.set_cpu(cpuid);
        } else if state == 0 {
            vmm_states.clear_cpu(cpuid);
        }
    }
}

lazy_static! {
    static ref NR_CPU_IDS: usize = HvHeader::get().max_cpus as usize;
    static ref VEC_PERCPU_VA: Vec<usize> = {
        let mut vec = Vec::new();
        let percpu_offset_pa = HvHeader::get().percpu_offset_pa as usize;
        let percpu_offset: &[usize] = unsafe {
            core::slice::from_raw_parts(
                addr::phys_to_virt(percpu_offset_pa) as *const usize,
                *NR_CPU_IDS,
            )
        };

        let safe_print_seq_start_pa = HvHeader::get().safe_print_seq_start_pa as usize;
        for i in 0..*NR_CPU_IDS {
            let pa = safe_print_seq_start_pa + percpu_offset[i] - percpu_offset[0];
            if memory::is_normal_memory(pa, STRUCT_LOGBUF_LEN).is_err() {
                return vec;
            }
        }

        let safe_print_seq_start_va = addr::phys_to_virt(safe_print_seq_start_pa);
        for i in 0..*NR_CPU_IDS {
            vec.push(safe_print_seq_start_va + percpu_offset[i] - percpu_offset[0]);
        }
        vec
    };
    static ref VMM_STATES_VA: usize = {
        let vmm_states_pa = HvHeader::get().vmm_states_pa as usize;
        if memory::is_normal_memory(vmm_states_pa, CPU_MASK_LEN).is_err() {
            return 0;
        }
        let vmm_states_va = addr::phys_to_virt(vmm_states_pa);
        vmm_states_va
    };
}

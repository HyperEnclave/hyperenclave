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

#[macro_use]
mod context;
mod cpuid;
mod enclave;
mod entry;
mod exception;
mod page_table;
mod segmentation;
mod tables;
mod xsave;

pub mod cpu;
pub mod serial;
pub mod vmm;

pub use context::{GuestRegisters, LinuxContext};
pub use enclave::{EnclaveExceptionInfo, EnclavePFErrorCode, EnclaveThreadState};
pub use exception::{ExceptionInfo, ExceptionType, PageFaultErrorCode};
pub use page_table::PageTable as HostPageTable;
pub use page_table::PageTable as GuestPageTable;
pub use page_table::PageTableImmut as GuestPageTableImmut;
pub use page_table::{EnclaveGuestPageTableUnlocked, PTEntry};
pub use vmm::{EnclaveNestedPageTableUnlocked, NPTEntry, NestedPageTable};
pub use xsave::XsaveRegion;

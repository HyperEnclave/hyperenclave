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

use crate::cpumask::CpuMask;

#[derive(Debug)]
pub struct TLBFlushTrackingState {
    /// Indicates if the process of TLB Flush track is active.
    tracking: bool,
    /// Indicates if there exists stale TLB for EPC page write back.
    write_back_tracking_done: bool,
    /// Indicates if there exists stale TLB for EPC page accept
    accept_tracking_done: bool,
    /// The number of logic processors that are currently executing the code of the enclave.
    active_threads: u16,
    /// The number of logic processors that were executing the enclave’s code when the ETRACK instruction was issued.
    tracked_threads: u16,
    /// Keep track of the logic processors that have exited the current enclave after the ETRACK instruction was issued.
    lp_mask: CpuMask,
}

impl TLBFlushTrackingState {
    pub fn active_thread_num(&self) -> u16 {
        self.active_threads
    }

    pub fn is_in_tracking(&self) -> bool {
        self.tracking
    }

    pub fn is_write_back_tracking_done(&self) -> bool {
        self.write_back_tracking_done
    }

    pub fn is_accept_tracking_done(&self) -> bool {
        self.accept_tracking_done
    }

    pub fn require_track_for_write_back(&mut self) {
        self.tracking = false;
        self.write_back_tracking_done = false;
    }

    pub fn require_track_for_accept(&mut self) {
        self.tracking = false;
        self.accept_tracking_done = false;
    }

    pub fn activate(&mut self) -> bool {
        if self.tracking {
            return false;
        }
        if self.active_threads == 0 {
            self.write_back_tracking_done = true;
            self.accept_tracking_done = true;
            return true;
        }
        self.tracking = true;
        self.tracked_threads = self.active_threads;
        self.lp_mask.clear();

        true
    }

    pub fn update(&mut self, is_enter: bool, cpuid: usize) {
        if is_enter {
            self.active_threads += 1;

            if self.is_in_tracking() {
                self.lp_mask.set_cpu(cpuid);
            }
        } else {
            self.active_threads -= 1;

            if self.is_in_tracking() {
                let already_counted = self.lp_mask.test_cpu(cpuid);
                if already_counted == 0 {
                    self.lp_mask.set_cpu(cpuid);
                    self.tracked_threads -= 1;
                    if self.tracked_threads == 0 {
                        self.write_back_tracking_done = true;
                        self.accept_tracking_done = true;
                        self.tracking = false;
                    }
                }
            }
        }
    }
}

impl Default for TLBFlushTrackingState {
    fn default() -> Self {
        Self {
            tracking: false,
            // There is no stale TLB for EPC page write back in init state
            write_back_tracking_done: true,
            // There is no stale TLB for EPC page accept in init state
            accept_tracking_done: true,
            active_threads: 0,
            tracked_threads: 0,
            lp_mask: CpuMask::default(),
        }
    }
}

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

use crate::error::HvResult;
use alloc::collections::btree_map::BTreeMap;
use alloc::vec::Vec;
use core::ops::Range;

#[derive(Debug)]
pub struct IntervalTree {
    tree: BTreeMap<usize, Range<usize>>,
}

pub fn overlap(left: &Range<usize>, right: &Range<usize>) -> Option<Range<usize>> {
    let overlap_start = left.start.max(right.start);
    let overlap_end = left.end.min(right.end);
    if overlap_start >= overlap_end {
        None
    } else {
        Some(overlap_start..overlap_end)
    }
}

impl IntervalTree {
    pub fn new() -> Self {
        Self {
            tree: BTreeMap::new(),
        }
    }

    /// Insert a value into the tree for a given range.
    pub fn insert(&mut self, range: Range<usize>) -> HvResult {
        // checking to see if any overlapping occurs
        let nodes = self.tree.range(..range.end);
        if let Some(node) = nodes.last() {
            if overlap(node.1, &range).is_some() {
                return hv_result_err!(EINVAL, "Insert overlap");
            }
        }
        self.tree.insert(range.start, range);
        Ok(())
    }

    /// Remove a value from the tree for a given range.
    /// It only allows to remove the entire range which completely matches the input range.
    pub fn remove(&mut self, range: &Range<usize>) -> HvResult {
        if let Some(var) = self.tree.remove(&(range.start)) {
            if &var == range {
                Ok(())
            } else {
                self.tree.insert(range.start, var);
                hv_result_err!(EINVAL, "Range does not match")
            }
        } else {
            hv_result_err!(EINVAL, "Range does not exist")
        }
    }

    /// Returns true if there is a range that contains the point argument.
    pub fn contains(&self, point: &usize) -> bool {
        let nodes = self.tree.range(..=point);
        if let Some(node) = nodes.last() {
            if node.1.contains(point) {
                return true;
            }
        }
        false
    }

    pub fn contains_range(&self, range: Range<usize>) -> bool {
        let nodes = self.tree.range(..=range.start);
        if let Some(node) = nodes.last() {
            if node.1.start <= range.start && node.1.end >= range.end {
                return true;
            }
        }
        false
    }

    /// Returns a vec of range which overlap with a given range.
    /// For example, if the tree contains [[1000..5000], [8000..11000]], and the given range
    /// is (4000..9000), you'll get back [[4000..5000], [8000..9000]]
    pub fn get_overlap(&self, range: &Range<usize>) -> HvResult<Vec<Range<usize>>> {
        // We might have to look at the element immediately preceeding range.start
        let the_range = {
            let start = range.start;
            self.tree
                .range(..=start)
                .last()
                .map_or(start, |node| node.1.start)..range.end
        };
        let nodes = self.tree.range(the_range);

        let result = nodes.filter_map(|(_, var)| overlap(range, var)).collect();

        Ok(result)
    }
}

mod tests {
    #[test]
    fn test_btree_element_size() {
        use core::ops::Range;
        assert_eq!(core::mem::size_of::<(usize, Range<usize>)>(), 24);
    }
}

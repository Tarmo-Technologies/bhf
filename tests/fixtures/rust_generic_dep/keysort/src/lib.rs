// SPDX-License-Identifier: Apache-2.0
//
// A generic sort over slices: each crate that calls it instantiates core's
// stable sort for its own element type and comparator.

use std::cmp::Ordering;

pub trait KeySort {
    type Item;

    fn sort_keyed<F>(&mut self, compare: F)
    where
        F: Fn(&Self::Item, &Self::Item) -> Ordering;
}

impl<T: Clone> KeySort for [T] {
    type Item = T;

    fn sort_keyed<F>(&mut self, compare: F)
    where
        F: Fn(&T, &T) -> Ordering,
    {
        if self.len() <= 16 {
            self.sort_by(|a, b| compare(a, b));
            return;
        }
        let mid = self.len() / 2;
        self[..mid].sort_by(|a, b| compare(a, b));
        self[mid..].sort_by(|a, b| compare(a, b));
        self.sort_by(|a, b| compare(a, b));
    }
}

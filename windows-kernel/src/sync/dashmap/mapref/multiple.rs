/*
MIT License

Copyright (c) 2019 Acrimon

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
use alloc::sync::Arc;
use core::hash::BuildHasher;
use core::hash::Hash;
use core::ops::{Deref, DerefMut};

use crate::sync::scc::hash_set::RandomState;

use super::super::lock::{RwLockReadGuard, RwLockWriteGuard};
use super::super::HashMap;

pub struct RefMulti<'a, K, V, S = RandomState> {
    _guard: Arc<RwLockReadGuard<'a, HashMap<K, V, S>>>,
    k: *const K,
    v: *const V,
}

unsafe impl<'a, K: Eq + Hash + Sync, V: Sync, S: BuildHasher> Send for RefMulti<'a, K, V, S> {}

unsafe impl<'a, K: Eq + Hash + Sync, V: Sync, S: BuildHasher> Sync for RefMulti<'a, K, V, S> {}

impl<'a, K: Eq + Hash, V, S: BuildHasher> RefMulti<'a, K, V, S> {
    pub(crate) unsafe fn new(
        guard: Arc<RwLockReadGuard<'a, HashMap<K, V, S>>>,
        k: *const K,
        v: *const V,
    ) -> Self {
        Self {
            _guard: guard,
            k,
            v,
        }
    }

    pub fn key(&self) -> &K {
        self.pair().0
    }

    pub fn value(&self) -> &V {
        self.pair().1
    }

    pub fn pair(&self) -> (&K, &V) {
        unsafe { (&*self.k, &*self.v) }
    }
}

impl<'a, K: Eq + Hash, V, S: BuildHasher> Deref for RefMulti<'a, K, V, S> {
    type Target = V;

    fn deref(&self) -> &V {
        self.value()
    }
}

pub struct RefMutMulti<'a, K, V, S = RandomState> {
    _guard: Arc<RwLockWriteGuard<'a, HashMap<K, V, S>>>,
    k: *const K,
    v: *mut V,
}

unsafe impl<'a, K: Eq + Hash + Sync, V: Sync, S: BuildHasher> Send for RefMutMulti<'a, K, V, S> {}

unsafe impl<'a, K: Eq + Hash + Sync, V: Sync, S: BuildHasher> Sync for RefMutMulti<'a, K, V, S> {}

impl<'a, K: Eq + Hash, V, S: BuildHasher> RefMutMulti<'a, K, V, S> {
    pub(crate) unsafe fn new(
        guard: Arc<RwLockWriteGuard<'a, HashMap<K, V, S>>>,
        k: *const K,
        v: *mut V,
    ) -> Self {
        Self {
            _guard: guard,
            k,
            v,
        }
    }

    pub fn key(&self) -> &K {
        self.pair().0
    }

    pub fn value(&self) -> &V {
        self.pair().1
    }

    pub fn value_mut(&mut self) -> &mut V {
        self.pair_mut().1
    }

    pub fn pair(&self) -> (&K, &V) {
        unsafe { (&*self.k, &*self.v) }
    }

    pub fn pair_mut(&mut self) -> (&K, &mut V) {
        unsafe { (&*self.k, &mut *self.v) }
    }
}

impl<'a, K: Eq + Hash, V, S: BuildHasher> Deref for RefMutMulti<'a, K, V, S> {
    type Target = V;

    fn deref(&self) -> &V {
        self.value()
    }
}

impl<'a, K: Eq + Hash, V, S: BuildHasher> DerefMut for RefMutMulti<'a, K, V, S> {
    fn deref_mut(&mut self) -> &mut V {
        self.value_mut()
    }
}

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

use core::hash::{BuildHasher, Hash};
use core::mem;
use core::ptr;

use crate::sync::scc::hash_set::RandomState;

use super::super::lock::RwLockWriteGuard;
use super::super::util;
use super::super::util::SharedValue;
use super::super::HashMap;
use super::one::RefMut;

pub enum Entry<'a, K, V, S = RandomState> {
    Occupied(OccupiedEntry<'a, K, V, S>),
    Vacant(VacantEntry<'a, K, V, S>),
}

impl<'a, K: Eq + Hash, V, S: BuildHasher> Entry<'a, K, V, S> {
    /// Apply a function to the stored value if it exists.
    pub fn and_modify(self, f: impl FnOnce(&mut V)) -> Self {
        match self {
            Entry::Occupied(mut entry) => {
                f(entry.get_mut());

                Entry::Occupied(entry)
            }

            Entry::Vacant(entry) => Entry::Vacant(entry),
        }
    }

    /// Get the key of the entry.
    pub fn key(&self) -> &K {
        match *self {
            Entry::Occupied(ref entry) => entry.key(),
            Entry::Vacant(ref entry) => entry.key(),
        }
    }

    /// Into the key of the entry.
    pub fn into_key(self) -> K {
        match self {
            Entry::Occupied(entry) => entry.into_key(),
            Entry::Vacant(entry) => entry.into_key(),
        }
    }

    /// Return a mutable reference to the element if it exists,
    /// otherwise insert the default and return a mutable reference to that.
    pub fn or_default(self) -> RefMut<'a, K, V, S>
    where
        V: Default,
    {
        match self {
            Entry::Occupied(entry) => entry.into_ref(),
            Entry::Vacant(entry) => entry.insert(V::default()),
        }
    }

    /// Return a mutable reference to the element if it exists,
    /// otherwise a provided value and return a mutable reference to that.
    pub fn or_insert(self, value: V) -> RefMut<'a, K, V, S> {
        match self {
            Entry::Occupied(entry) => entry.into_ref(),
            Entry::Vacant(entry) => entry.insert(value),
        }
    }

    /// Return a mutable reference to the element if it exists,
    /// otherwise insert the result of a provided function and return a mutable reference to that.
    pub fn or_insert_with(self, value: impl FnOnce() -> V) -> RefMut<'a, K, V, S> {
        match self {
            Entry::Occupied(entry) => entry.into_ref(),
            Entry::Vacant(entry) => entry.insert(value()),
        }
    }

    pub fn or_try_insert_with<E>(
        self,
        value: impl FnOnce() -> Result<V, E>,
    ) -> Result<RefMut<'a, K, V, S>, E> {
        match self {
            Entry::Occupied(entry) => Ok(entry.into_ref()),
            Entry::Vacant(entry) => Ok(entry.insert(value()?)),
        }
    }

    /// Sets the value of the entry, and returns a reference to the inserted value.
    pub fn insert(self, value: V) -> RefMut<'a, K, V, S> {
        match self {
            Entry::Occupied(mut entry) => {
                entry.insert(value);
                entry.into_ref()
            }
            Entry::Vacant(entry) => entry.insert(value),
        }
    }

    /// Sets the value of the entry, and returns an OccupiedEntry.
    ///
    /// If you are not interested in the occupied entry,
    /// consider [`insert`] as it doesn't need to clone the key.
    ///
    /// [`insert`]: Entry::insert
    pub fn insert_entry(self, value: V) -> OccupiedEntry<'a, K, V, S>
    where
        K: Clone,
    {
        match self {
            Entry::Occupied(mut entry) => {
                entry.insert(value);
                entry
            }
            Entry::Vacant(entry) => entry.insert_entry(value),
        }
    }
}

pub struct VacantEntry<'a, K, V, S = RandomState> {
    shard: RwLockWriteGuard<'a, HashMap<K, V, S>>,
    key: K,
}

unsafe impl<'a, K: Eq + Hash + Sync, V: Sync, S: BuildHasher> Send for VacantEntry<'a, K, V, S> {}

unsafe impl<'a, K: Eq + Hash + Sync, V: Sync, S: BuildHasher> Sync for VacantEntry<'a, K, V, S> {}

impl<'a, K: Eq + Hash, V, S: BuildHasher> VacantEntry<'a, K, V, S> {
    pub(crate) unsafe fn new(shard: RwLockWriteGuard<'a, HashMap<K, V, S>>, key: K) -> Self {
        Self { shard, key }
    }

    pub fn insert(mut self, value: V) -> RefMut<'a, K, V, S> {
        unsafe {
            let c: K = ptr::read(&self.key);

            self.shard.insert(self.key, SharedValue::new(value));

            let (k, v) = self.shard.get_key_value(&c).unwrap();

            let k = util::change_lifetime_const(k);

            let v = &mut *v.as_ptr();

            let r = RefMut::new(self.shard, k, v);

            mem::forget(c);

            r
        }
    }

    /// Sets the value of the entry with the VacantEntry’s key, and returns an OccupiedEntry.
    pub fn insert_entry(mut self, value: V) -> OccupiedEntry<'a, K, V, S>
    where
        K: Clone,
    {
        unsafe {
            self.shard.insert(self.key.clone(), SharedValue::new(value));

            let (k, v) = self.shard.get_key_value(&self.key).unwrap();

            let kptr: *const K = k;
            let vptr: *mut V = v.as_ptr();
            OccupiedEntry::new(self.shard, self.key, (kptr, vptr))
        }
    }

    pub fn into_key(self) -> K {
        self.key
    }

    pub fn key(&self) -> &K {
        &self.key
    }
}

pub struct OccupiedEntry<'a, K, V, S = RandomState> {
    shard: RwLockWriteGuard<'a, HashMap<K, V, S>>,
    elem: (*const K, *mut V),
    key: K,
}

unsafe impl<'a, K: Eq + Hash + Sync, V: Sync, S: BuildHasher> Send for OccupiedEntry<'a, K, V, S> {}

unsafe impl<'a, K: Eq + Hash + Sync, V: Sync, S: BuildHasher> Sync for OccupiedEntry<'a, K, V, S> {}

impl<'a, K: Eq + Hash, V, S: BuildHasher> OccupiedEntry<'a, K, V, S> {
    pub(crate) unsafe fn new(
        shard: RwLockWriteGuard<'a, HashMap<K, V, S>>,
        key: K,
        elem: (*const K, *mut V),
    ) -> Self {
        Self { shard, elem, key }
    }

    pub fn get(&self) -> &V {
        unsafe { &*self.elem.1 }
    }

    pub fn get_mut(&mut self) -> &mut V {
        unsafe { &mut *self.elem.1 }
    }

    pub fn insert(&mut self, value: V) -> V {
        mem::replace(self.get_mut(), value)
    }

    pub fn into_ref(self) -> RefMut<'a, K, V, S> {
        unsafe { RefMut::new(self.shard, self.elem.0, self.elem.1) }
    }

    pub fn into_key(self) -> K {
        self.key
    }

    pub fn key(&self) -> &K {
        unsafe { &*self.elem.0 }
    }

    pub fn remove(mut self) -> V {
        let key = unsafe { &*self.elem.0 };
        self.shard.remove(key).unwrap().into_inner()
    }

    pub fn remove_entry(mut self) -> (K, V) {
        let key = unsafe { &*self.elem.0 };
        let (k, v) = self.shard.remove_entry(key).unwrap();
        (k, v.into_inner())
    }

    pub fn replace_entry(mut self, value: V) -> (K, V) {
        let nk = self.key;
        let key = unsafe { &*self.elem.0 };
        let (k, v) = self.shard.remove_entry(key).unwrap();
        self.shard.insert(nk, SharedValue::new(value));
        (k, v.into_inner())
    }
}

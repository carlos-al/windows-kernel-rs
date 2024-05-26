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
use core::ops::Deref;

use crate::sync::scc::hash_set::RandomState;

use super::super::mapref;

pub struct Ref<'a, K, S = RandomState> {
    inner: mapref::one::Ref<'a, K, (), S>,
}

impl<'a, K: Eq + Hash, S: BuildHasher> Ref<'a, K, S> {
    pub(crate) fn new(inner: mapref::one::Ref<'a, K, (), S>) -> Self {
        Self { inner }
    }

    pub fn key(&self) -> &K {
        self.inner.key()
    }
}

impl<'a, K: Eq + Hash, S: BuildHasher> Deref for Ref<'a, K, S> {
    type Target = K;

    fn deref(&self) -> &K {
        self.key()
    }
}

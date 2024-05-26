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

use super::setref::multiple::RefMulti;
use super::t::Map;

pub struct OwningIter<K, S> {
    inner: super::iter::OwningIter<K, (), S>,
}

impl<K: Eq + Hash, S: BuildHasher + Clone> OwningIter<K, S> {
    pub(crate) fn new(inner: super::iter::OwningIter<K, (), S>) -> Self {
        Self { inner }
    }
}

impl<K: Eq + Hash, S: BuildHasher + Clone> Iterator for OwningIter<K, S> {
    type Item = K;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|(k, _)| k)
    }
}

unsafe impl<K, S> Send for OwningIter<K, S>
where
    K: Eq + Hash + Send,
    S: BuildHasher + Clone + Send,
{
}

unsafe impl<K, S> Sync for OwningIter<K, S>
where
    K: Eq + Hash + Sync,
    S: BuildHasher + Clone + Sync,
{
}

pub struct Iter<'a, K, S, M> {
    inner: super::iter::Iter<'a, K, (), S, M>,
}

unsafe impl<'a, 'i, K, S, M> Send for Iter<'i, K, S, M>
where
    K: 'a + Eq + Hash + Send,
    S: 'a + BuildHasher + Clone,
    M: Map<'a, K, (), S>,
{
}

unsafe impl<'a, 'i, K, S, M> Sync for Iter<'i, K, S, M>
where
    K: 'a + Eq + Hash + Sync,
    S: 'a + BuildHasher + Clone,
    M: Map<'a, K, (), S>,
{
}

impl<'a, K: Eq + Hash, S: 'a + BuildHasher + Clone, M: Map<'a, K, (), S>> Iter<'a, K, S, M> {
    pub(crate) fn new(inner: super::iter::Iter<'a, K, (), S, M>) -> Self {
        Self { inner }
    }
}

impl<'a, K: Eq + Hash, S: 'a + BuildHasher + Clone, M: Map<'a, K, (), S>> Iterator
    for Iter<'a, K, S, M>
{
    type Item = RefMulti<'a, K, S>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(RefMulti::new)
    }
}

//--- This file has been modified, differing from the original github repo wvwwvwwv/scalable-concurrent-containers ---//
use core::borrow::Borrow;
use core::cmp::Ordering;
use core::fmt::{self, Debug};
use core::mem::{needs_drop, MaybeUninit};
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering::{AcqRel, Acquire, Relaxed, Release};

use crate::sync::scc::ebr::{AtomicShared, Guard, Shared};
use crate::sync::scc::LinkedList;

/// [`Leaf`] is an ordered array of key-value pairs.
///
/// A constructed key-value pair entry is never dropped until the entire [`Leaf`] instance is
/// dropped.
pub struct Leaf<K, V>
where
    K: 'static + Clone + Ord,
    V: 'static + Clone,
{
    /// The metadata containing information about the [`Leaf`] and individual entries.
    ///
    /// The state of each entry is as follows.
    /// * `0`: `uninit`.
    /// * `1-ARRAY_SIZE`: `rank`.
    /// * `ARRAY_SIZE + 1`: `removed`.
    ///
    /// The entry state transitions as follows.
    /// * `uninit -> removed -> rank -> removed`.
    metadata: AtomicUsize,

    /// The array of key-value pairs.
    entry_array: EntryArray<K, V>,

    /// A pointer that points to the next adjacent [`Leaf`].
    link: AtomicShared<Leaf<K, V>>,
}

/// The number of entries and number of state bits per entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Dimension {
    pub num_entries: usize,
    pub num_bits_per_entry: usize,
}

/// The result of insertion.
pub enum InsertResult<K, V> {
    /// Insertion succeeded.
    Success,

    /// Duplicate key found.
    Duplicate(K, V),

    /// No vacant slot for the key.
    Full(K, V),

    /// The [`Leaf`] is frozen.
    ///
    /// It is not a terminal state that a frozen [`Leaf`] can be unfrozen.
    Frozen(K, V),

    /// Insertion failed as the [`Leaf`] has retired.
    ///
    /// It is a terminal state.
    Retired(K, V),

    /// The operation can be retried.
    Retry(K, V),
}

/// The result of removal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoveResult {
    /// Remove succeeded.
    Success,

    /// Remove succeeded and cleanup required.
    Cleanup,

    /// Remove succeeded and the [`Leaf`] has retired without usable entries left.
    Retired,

    /// Remove failed.
    Fail,

    /// The [`Leaf`] is frozen.
    Frozen,
}

impl<K, V> Leaf<K, V>
where
    K: 'static + Clone + Ord,
    V: 'static + Clone,
{
    /// Creates a new [`Leaf`].
    #[inline]
    pub(super) const fn new() -> Leaf<K, V> {
        #[allow(clippy::uninit_assumed_init)]
        Leaf {
            metadata: AtomicUsize::new(0),
            entry_array: unsafe { MaybeUninit::uninit().assume_init() },
            link: AtomicShared::null(),
        }
    }

    /// Thaws the [`Leaf`].
    #[inline]
    pub(super) fn thaw(&self) -> bool {
        self.metadata
            .fetch_update(Relaxed, Relaxed, |p| {
                if Dimension::frozen(p) {
                    Some(Dimension::thaw(p))
                } else {
                    None
                }
            })
            .is_ok()
    }

    /// Returns `true` if the [`Leaf`] has retired.
    #[inline]
    pub(super) fn is_retired(&self) -> bool {
        Dimension::retired(self.metadata.load(Relaxed))
    }

    /// Returns a reference to the max key.
    #[inline]
    pub(super) fn max_key(&self) -> Option<&K> {
        let mut mutable_metadata = self.metadata.load(Acquire);
        let mut max_rank = 0;
        let mut max_index = DIMENSION.num_entries;
        for i in 0..DIMENSION.num_entries {
            if mutable_metadata == 0 {
                break;
            }
            let rank = mutable_metadata % (1_usize << DIMENSION.num_bits_per_entry);
            if rank > max_rank && rank != DIMENSION.removed_rank() {
                max_rank = rank;
                max_index = i;
            }
            mutable_metadata >>= DIMENSION.num_bits_per_entry;
        }
        if max_index != DIMENSION.num_entries {
            return Some(self.key_at(max_index));
        }
        None
    }

    /// Inserts a key value pair.
    #[inline]
    pub(super) fn insert(&self, key: K, val: V) -> InsertResult<K, V> {
        let mut metadata = self.metadata.load(Acquire);
        'after_read_metadata: loop {
            if Dimension::retired(metadata) {
                return InsertResult::Retired(key, val);
            } else if Dimension::frozen(metadata) {
                return InsertResult::Frozen(key, val);
            }

            let mut mutable_metadata = metadata;
            for i in 0..DIMENSION.num_entries {
                let rank = mutable_metadata % (1_usize << DIMENSION.num_bits_per_entry);
                if rank == Dimension::uninit_rank() {
                    let interim_metadata = DIMENSION.augment(metadata, i, DIMENSION.removed_rank());

                    // Reserve the slot.
                    //
                    // It doesn't have to be a release-store.
                    if let Err(actual) =
                        self.metadata
                            .compare_exchange(metadata, interim_metadata, Acquire, Acquire)
                    {
                        metadata = actual;
                        continue 'after_read_metadata;
                    }

                    self.write(i, key, val);
                    return self.post_insert(i, interim_metadata);
                }
                mutable_metadata >>= DIMENSION.num_bits_per_entry;
            }

            if self.search_slot(&key, metadata).is_some() {
                return InsertResult::Duplicate(key, val);
            }
            return InsertResult::Full(key, val);
        }
    }

    /// Inserts a key value pair at the specified position without checking the metadata.
    ///
    /// `rank` is calculated as `index + 1`.
    #[inline]
    pub(super) fn insert_unchecked(&self, key: K, val: V, index: usize) {
        debug_assert!(index < DIMENSION.num_entries);
        let metadata = self.metadata.load(Relaxed);
        let new_metadata = DIMENSION.augment(metadata, index, index + 1);
        self.write(index, key, val);
        self.metadata.store(new_metadata, Release);
    }

    /// Removes the key if the condition is met.
    #[inline]
    pub(super) fn remove_if<Q, F: FnMut(&V) -> bool>(
        &self,
        key: &Q,
        condition: &mut F,
    ) -> RemoveResult
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        let mut metadata = self.metadata.load(Acquire);
        if Dimension::frozen(metadata) {
            return RemoveResult::Frozen;
        }
        let mut min_max_rank = DIMENSION.removed_rank();
        let mut max_min_rank = 0;
        let mut mutable_metadata = metadata;
        for i in 0..DIMENSION.num_entries {
            if mutable_metadata == 0 {
                break;
            }
            let rank = mutable_metadata % (1_usize << DIMENSION.num_bits_per_entry);
            if rank < min_max_rank && rank > max_min_rank {
                match self.compare(i, key) {
                    Ordering::Less => {
                        if max_min_rank < rank {
                            max_min_rank = rank;
                        }
                    }
                    Ordering::Greater => {
                        if min_max_rank > rank {
                            min_max_rank = rank;
                        }
                    }
                    Ordering::Equal => {
                        // Found the key.
                        loop {
                            if !condition(self.value_at(i)) {
                                // The given condition is not met.
                                return RemoveResult::Fail;
                            }
                            let mut empty = true;
                            mutable_metadata = metadata;
                            for j in 0..DIMENSION.num_entries {
                                if mutable_metadata == 0 {
                                    break;
                                }
                                if i != j {
                                    let rank = mutable_metadata
                                        % (1_usize << DIMENSION.num_bits_per_entry);
                                    if rank != Dimension::uninit_rank()
                                        && rank != DIMENSION.removed_rank()
                                    {
                                        empty = false;
                                        break;
                                    }
                                }
                                mutable_metadata >>= DIMENSION.num_bits_per_entry;
                            }

                            let mut new_metadata = metadata | DIMENSION.rank_mask(i);
                            if empty {
                                new_metadata = Dimension::retire(new_metadata);
                            }
                            match self.metadata.compare_exchange(
                                metadata,
                                new_metadata,
                                Release,
                                Relaxed,
                            ) {
                                Ok(_) => {
                                    if empty {
                                        return RemoveResult::Retired;
                                    }
                                    return RemoveResult::Success;
                                }
                                Err(actual) => {
                                    if DIMENSION.rank(actual, i) == DIMENSION.removed_rank() {
                                        return RemoveResult::Fail;
                                    }
                                    if Dimension::frozen(actual) {
                                        return RemoveResult::Frozen;
                                    }
                                    metadata = actual;
                                }
                            }
                        }
                    }
                };
            }
            mutable_metadata >>= DIMENSION.num_bits_per_entry;
        }

        RemoveResult::Fail
    }

    /// Returns a value associated with the key.
    #[inline]
    pub(super) fn search<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        let metadata = self.metadata.load(Acquire);
        self.search_slot(key, metadata).map(|i| self.value_at(i))
    }

    /// Returns the index of the key-value pair that is smaller than the given key.
    #[inline]
    pub(super) fn max_less<Q>(&self, mut mutable_metadata: usize, key: &Q) -> usize
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        let mut min_max_rank = DIMENSION.removed_rank();
        let mut max_min_rank = 0;
        let mut max_min_index = DIMENSION.num_entries;
        for i in 0..DIMENSION.num_entries {
            if mutable_metadata == 0 {
                break;
            }
            let rank = mutable_metadata % (1_usize << DIMENSION.num_bits_per_entry);
            if rank < min_max_rank && rank > max_min_rank {
                match self.compare(i, key) {
                    Ordering::Less => {
                        if max_min_rank < rank {
                            max_min_rank = rank;
                            max_min_index = i;
                        }
                    }
                    Ordering::Greater => {
                        if min_max_rank > rank {
                            min_max_rank = rank;
                        }
                    }
                    Ordering::Equal => {
                        min_max_rank = rank;
                    }
                }
            }
            mutable_metadata >>= DIMENSION.num_bits_per_entry;
        }
        max_min_index
    }

    /// Returns the minimum entry among those that are not `Ordering::Less` than the given key.
    ///
    /// It additionally returns the current version of its metadata in order for the caller to
    /// validate the sanity of the result.
    #[inline]
    pub(super) fn min_greater_equal<Q>(&self, key: &Q) -> (Option<(&K, &V)>, usize)
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        let metadata = self.metadata.load(Acquire);
        let mut min_max_rank = DIMENSION.removed_rank();
        let mut max_min_rank = 0;
        let mut min_max_index = DIMENSION.num_entries;
        let mut mutable_metadata = metadata;
        for i in 0..DIMENSION.num_entries {
            if mutable_metadata == 0 {
                break;
            }
            let rank = mutable_metadata % (1_usize << DIMENSION.num_bits_per_entry);
            if rank < min_max_rank && rank > max_min_rank {
                let k = self.key_at(i);
                match k.borrow().cmp(key) {
                    Ordering::Less => {
                        if max_min_rank < rank {
                            max_min_rank = rank;
                        }
                    }
                    Ordering::Greater => {
                        if min_max_rank > rank {
                            min_max_rank = rank;
                            min_max_index = i;
                        }
                    }
                    Ordering::Equal => {
                        return (Some((k, self.value_at(i))), metadata);
                    }
                }
            }
            mutable_metadata >>= DIMENSION.num_bits_per_entry;
        }
        if min_max_index != DIMENSION.num_entries {
            return (
                Some((self.key_at(min_max_index), self.value_at(min_max_index))),
                metadata,
            );
        }
        (None, metadata)
    }

    /// Compares the given metadata value with the current one.
    #[inline]
    pub(super) fn validate(&self, metadata: usize) -> bool {
        // `Relaxed` is sufficient as long as the caller has read-acquired its contents.
        self.metadata.load(Relaxed) == metadata
    }

    /// Freezes the [`Leaf`] temporarily.
    ///
    /// A frozen [`Leaf`] cannot store more entries, and on-going insertion is canceled.
    #[inline]
    pub(super) fn freeze(&self) -> bool {
        self.metadata
            .fetch_update(AcqRel, Acquire, |p| {
                if Dimension::frozen(p) {
                    None
                } else {
                    Some(Dimension::freeze(p))
                }
            })
            .is_ok()
    }

    /// Freezes the [`Leaf`] and distribute entries to two new leaves.
    #[inline]
    pub(super) fn freeze_and_distribute(
        &self,
        low_key_leaf: &mut Option<Shared<Leaf<K, V>>>,
        high_key_leaf: &mut Option<Shared<Leaf<K, V>>>,
    ) {
        let metadata = unsafe {
            self.metadata
                .fetch_update(AcqRel, Acquire, |p| {
                    if Dimension::frozen(p) {
                        None
                    } else {
                        Some(Dimension::freeze(p))
                    }
                })
                .unwrap_unchecked()
        };

        let boundary = Self::optimal_boundary(metadata);
        let scanner = Scanner {
            leaf: self,
            metadata,
            entry_index: DIMENSION.num_entries,
        };
        for (i, (k, v)) in scanner.enumerate() {
            if i < boundary {
                low_key_leaf
                    .get_or_insert_with(|| Shared::new(Leaf::new()))
                    .insert_unchecked(k.clone(), v.clone(), i);
            } else {
                high_key_leaf
                    .get_or_insert_with(|| Shared::new(Leaf::new()))
                    .insert_unchecked(k.clone(), v.clone(), i - boundary);
            };
        }
    }

    /// Returns the recommended number of entries that the left-side node shall store when a
    /// [`Leaf`] is split.
    ///
    /// Returns a number in `[1, len(leaf))` that represents the recommended number of entries in
    /// the left-side node. The number is calculated as, for each adjacent slots,
    /// - Initial `score = len(leaf)`.
    /// - Rank increased: `score -= 1`.
    /// - Rank decreased: `score += 1`.
    /// - Clamp `score` in `[len(leaf) / 2 + 1, len(leaf) / 2 + len(leaf) - 1)`.
    /// - Take `score - len(leaf) / 2`.
    ///
    /// For instance, when the length of a [`Leaf`] is 7,
    /// - Returns 6 for `rank = [1, 2, 3, 4, 5, 6, 7]`.
    /// - Returns 1 for `rank = [7, 6, 5, 4, 3, 2, 1]`.
    #[inline]
    pub(super) fn optimal_boundary(mut mutable_metadata: usize) -> usize {
        let mut boundary: usize = DIMENSION.num_entries;
        let mut prev_rank = 1;
        for _ in 0..DIMENSION.num_entries {
            let rank = mutable_metadata % (1_usize << DIMENSION.num_bits_per_entry);
            if rank != 0 && rank != DIMENSION.removed_rank() {
                if prev_rank < rank {
                    boundary += 1;
                } else {
                    boundary -= 1;
                }
                prev_rank = rank;
            }
            mutable_metadata >>= DIMENSION.num_bits_per_entry;
        }
        boundary.clamp(
            DIMENSION.num_entries / 2 + 1,
            DIMENSION.num_entries + DIMENSION.num_entries / 2 - 1,
        ) - DIMENSION.num_entries / 2
    }

    /// Searches for a slot in which the key is stored.
    fn search_slot<Q>(&self, key: &Q, mut mutable_metadata: usize) -> Option<usize>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        let mut min_max_rank = DIMENSION.removed_rank();
        let mut max_min_rank = 0;
        for i in 0..DIMENSION.num_entries {
            if mutable_metadata == 0 {
                break;
            }
            let rank = mutable_metadata % (1_usize << DIMENSION.num_bits_per_entry);
            if rank < min_max_rank && rank > max_min_rank {
                match self.compare(i, key) {
                    Ordering::Less => {
                        if max_min_rank < rank {
                            max_min_rank = rank;
                        }
                    }
                    Ordering::Greater => {
                        if min_max_rank > rank {
                            min_max_rank = rank;
                        }
                    }
                    Ordering::Equal => {
                        return Some(i);
                    }
                }
            }
            mutable_metadata >>= DIMENSION.num_bits_per_entry;
        }
        None
    }

    /// Post-processing after reserving a free slot.
    fn post_insert(&self, free_slot_index: usize, mut prev_metadata: usize) -> InsertResult<K, V> {
        let key = self.key_at(free_slot_index);
        loop {
            let mut min_max_rank = DIMENSION.removed_rank();
            let mut max_min_rank = 0;
            let mut new_metadata = prev_metadata;
            let mut mutable_metadata = prev_metadata;
            for i in 0..DIMENSION.num_entries {
                if mutable_metadata == 0 {
                    break;
                }
                let rank = mutable_metadata % (1_usize << DIMENSION.num_bits_per_entry);
                if rank < min_max_rank && rank > max_min_rank {
                    match self.compare(i, key) {
                        Ordering::Less => {
                            if max_min_rank < rank {
                                max_min_rank = rank;
                            }
                        }
                        Ordering::Greater => {
                            if min_max_rank > rank {
                                min_max_rank = rank;
                            }
                            new_metadata = DIMENSION.augment(new_metadata, i, rank + 1);
                        }
                        Ordering::Equal => {
                            // Duplicate key.
                            return self.rollback(free_slot_index);
                        }
                    }
                } else if rank != DIMENSION.removed_rank() && rank > min_max_rank {
                    new_metadata = DIMENSION.augment(new_metadata, i, rank + 1);
                }
                mutable_metadata >>= DIMENSION.num_bits_per_entry;
            }

            // Make the newly inserted value reachable.
            let final_metadata = DIMENSION.augment(new_metadata, free_slot_index, max_min_rank + 1);
            if let Err(actual) =
                self.metadata
                    .compare_exchange(prev_metadata, final_metadata, AcqRel, Acquire)
            {
                if Dimension::frozen(actual) || Dimension::retired(actual) {
                    return self.rollback(free_slot_index);
                }
                prev_metadata = actual;
                continue;
            }

            return InsertResult::Success;
        }
    }

    fn rollback(&self, index: usize) -> InsertResult<K, V> {
        let (key, val) = self.take(index);
        let result = self
            .metadata
            .fetch_and(!DIMENSION.rank_mask(index), Relaxed)
            & (!DIMENSION.rank_mask(index));
        if Dimension::retired(result) {
            InsertResult::Retired(key, val)
        } else if Dimension::frozen(result) {
            InsertResult::Frozen(key, val)
        } else {
            InsertResult::Duplicate(key, val)
        }
    }

    fn compare<Q>(&self, index: usize, key: &Q) -> Ordering
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.key_at(index).borrow().cmp(key)
    }

    fn take(&self, index: usize) -> (K, V) {
        unsafe {
            (
                self.entry_array.0[index].as_ptr().read(),
                self.entry_array.1[index].as_ptr().read(),
            )
        }
    }

    fn write(&self, index: usize, key: K, val: V) {
        unsafe {
            (self.entry_array.0[index].as_ptr().cast_mut()).write(key);
            (self.entry_array.1[index].as_ptr().cast_mut()).write(val);
        }
    }

    const fn key_at(&self, index: usize) -> &K {
        unsafe { &*self.entry_array.0[index].as_ptr() }
    }

    const fn value_at(&self, index: usize) -> &V {
        unsafe { &*self.entry_array.1[index].as_ptr() }
    }

    /// Returns the index of the corresponding entry of the next higher ranked entry.
    fn next(index: usize, mut mutable_metadata: usize) -> usize {
        debug_assert_ne!(index, usize::MAX);
        let current_entry_rank = if index == DIMENSION.num_entries {
            0
        } else {
            DIMENSION.rank(mutable_metadata, index)
        };
        let mut next_index = DIMENSION.num_entries;
        if current_entry_rank < DIMENSION.num_entries {
            let mut next_rank = DIMENSION.removed_rank();
            for i in 0..DIMENSION.num_entries {
                if mutable_metadata == 0 {
                    break;
                }
                if i != index {
                    let rank = mutable_metadata % (1_usize << DIMENSION.num_bits_per_entry);
                    if rank != Dimension::uninit_rank() && rank < next_rank {
                        if rank == current_entry_rank + 1 {
                            return i;
                        } else if rank > current_entry_rank {
                            next_rank = rank;
                            next_index = i;
                        }
                    }
                }
                mutable_metadata >>= DIMENSION.num_bits_per_entry;
            }
        }
        next_index
    }
}

impl<K, V> Drop for Leaf<K, V>
where
    K: 'static + Clone + Ord,
    V: 'static + Clone,
{
    #[inline]
    fn drop(&mut self) {
        if needs_drop::<(K, V)>() {
            let mut mutable_metadata = self.metadata.load(Acquire);
            for i in 0..DIMENSION.num_entries {
                if mutable_metadata == 0 {
                    break;
                }
                if mutable_metadata % (1_usize << DIMENSION.num_bits_per_entry)
                    != Dimension::uninit_rank()
                {
                    self.take(i);
                }
                mutable_metadata >>= DIMENSION.num_bits_per_entry;
            }
        }
    }
}

/// [`LinkedList`] implementation for [`Leaf`].
impl<K, V> LinkedList for Leaf<K, V>
where
    K: 'static + Clone + Ord,
    V: 'static + Clone,
{
    #[inline]
    fn link_ref(&self) -> &AtomicShared<Leaf<K, V>> {
        &self.link
    }
}

impl Dimension {
    /// Checks if the [`Leaf`] is frozen.
    const fn frozen(metadata: usize) -> bool {
        metadata & (1_usize << (usize::BITS - 2)) != 0
    }

    /// Makes the metadata represent a frozen state.
    const fn freeze(metadata: usize) -> usize {
        metadata | (1_usize << (usize::BITS - 2))
    }

    /// Updates the metadata to represent a non-frozen state.
    const fn thaw(metadata: usize) -> usize {
        metadata & (!(1_usize << (usize::BITS - 2)))
    }

    /// Checks if the [`Leaf`] is retired.
    const fn retired(metadata: usize) -> bool {
        metadata & (1_usize << (usize::BITS - 1)) != 0
    }

    /// Makes the metadata represent a retired state.
    const fn retire(metadata: usize) -> usize {
        metadata | (1_usize << (usize::BITS - 1))
    }

    /// Returns a bit mask for an entry.
    const fn rank_mask(&self, index: usize) -> usize {
        ((1_usize << self.num_bits_per_entry) - 1) << (index * self.num_bits_per_entry)
    }

    /// Returns the rank of an entry.
    const fn rank(&self, metadata: usize, index: usize) -> usize {
        (metadata >> (index * self.num_bits_per_entry)) % (1_usize << self.num_bits_per_entry)
    }

    /// Returns the uninitialized rank value which is smaller than all the valid rank values.
    const fn uninit_rank() -> usize {
        0
    }

    /// Returns the removed rank value which is greater than all the valid rank values.
    const fn removed_rank(&self) -> usize {
        (1_usize << self.num_bits_per_entry) - 1
    }

    /// Augments the rank to the given metadata.
    const fn augment(&self, metadata: usize, index: usize, rank: usize) -> usize {
        (metadata & (!self.rank_mask(index))) | (rank << (index * self.num_bits_per_entry))
    }
}

/// The maximum number of entries and the number of metadata bits per entry in a [`Leaf`].
///
/// * `M`: The maximum number of entries.
/// * `B`: The minimum number of bits to express the state of an entry.
/// * `2`: The number of special states of an entry: uninitialized, removed.
/// * `2`: The number of special states of a [`Leaf`]: frozen, retired.
/// * `U`: `usize::BITS`.
/// * `Eq1 = M + 2 <= 2^B`: `B` bits represent at least `M + 2` states.
/// * `Eq2 = B * M + 2 <= U`: `M entries + 2` special state.
/// * `Eq3 = Ceil(Log2(M + 2)) * M + 2 <= U`: derived from `Eq1` and `Eq2`.
///
/// Therefore, when `U = 64 => M = 14 / B = 4`, and `U = 32 => M = 7 / B = 4`.
pub const DIMENSION: Dimension = match usize::BITS / 8 {
    1 => Dimension {
        num_entries: 2,
        num_bits_per_entry: 2,
    },
    2 => Dimension {
        num_entries: 4,
        num_bits_per_entry: 3,
    },
    4 => Dimension {
        num_entries: 7,
        num_bits_per_entry: 4,
    },
    8 => Dimension {
        num_entries: 14,
        num_bits_per_entry: 4,
    },
    _ => Dimension {
        num_entries: 25,
        num_bits_per_entry: 5,
    },
};

/// Each constructed entry in an `EntryArray` is never dropped until the [`Leaf`] is dropped.
pub type EntryArray<K, V> = (
    [MaybeUninit<K>; DIMENSION.num_entries],
    [MaybeUninit<V>; DIMENSION.num_entries],
);

/// Leaf scanner.
pub struct Scanner<'l, K, V>
where
    K: 'static + Clone + Ord,
    V: 'static + Clone,
{
    leaf: &'l Leaf<K, V>,
    metadata: usize,
    entry_index: usize,
}

impl<'l, K, V> Scanner<'l, K, V>
where
    K: 'static + Clone + Ord,
    V: 'static + Clone,
{
    /// Creates a new [`Scanner`].
    #[inline]
    pub(super) fn new(leaf: &'l Leaf<K, V>) -> Scanner<'l, K, V> {
        Scanner {
            leaf,
            metadata: leaf.metadata.load(Acquire),
            entry_index: DIMENSION.num_entries,
        }
    }
    /// Returns a [`Scanner`] pointing to the max-less entry if there is one.
    #[inline]
    pub(super) fn max_less<Q>(leaf: &'l Leaf<K, V>, key: &Q) -> Option<Scanner<'l, K, V>>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        let metadata = leaf.metadata.load(Acquire);
        let index = leaf.max_less(metadata, key);
        if index == DIMENSION.num_entries {
            None
        } else {
            Some(Scanner {
                leaf,
                metadata,
                entry_index: index,
            })
        }
    }

    /// Returns the metadata that the [`Scanner`] is currently using.
    #[inline]
    pub(super) const fn metadata(&self) -> usize {
        self.metadata
    }

    /// Returns a reference to the entry that the scanner is currently pointing to
    #[inline]
    pub(super) const fn get(&self) -> Option<(&'l K, &'l V)> {
        if self.entry_index >= DIMENSION.num_entries {
            return None;
        }
        Some((
            self.leaf.key_at(self.entry_index),
            self.leaf.value_at(self.entry_index),
        ))
    }

    /// Returns a reference to the max key.
    #[inline]
    pub(super) fn max_key(&self) -> Option<&'l K> {
        self.leaf.max_key()
    }

    /// Traverses the linked list.
    #[inline]
    pub(super) fn jump<'g, Q>(
        &self,
        min_allowed_key: Option<&Q>,
        guard: &'g Guard,
    ) -> Option<Scanner<'g, K, V>>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        let mut next_leaf_ptr = self.leaf.next_ptr(Acquire, guard);
        while let Some(next_leaf_ref) = next_leaf_ptr.as_ref() {
            let mut leaf_scanner = Scanner::new(next_leaf_ref);
            if let Some(key) = min_allowed_key {
                if !self.leaf.is_clear(Relaxed) {
                    // Data race resolution: compare keys if the current leaf has been deleted.
                    //
                    // There is a chance that the current leaf has been deleted, and smaller
                    // keys have been inserted into the next leaf.
                    while let Some(entry) = leaf_scanner.next() {
                        if key.cmp(entry.0.borrow()) == Ordering::Less {
                            return Some(leaf_scanner);
                        }
                    }
                    next_leaf_ptr = next_leaf_ref.next_ptr(Acquire, guard);
                    continue;
                }
            }
            if leaf_scanner.next().is_some() {
                return Some(leaf_scanner);
            }
            next_leaf_ptr = next_leaf_ref.next_ptr(Acquire, guard);
        }
        None
    }

    fn proceed(&mut self) {
        if self.entry_index == usize::MAX {
            return;
        }
        let index = Leaf::<K, V>::next(self.entry_index, self.metadata);
        if index == DIMENSION.num_entries {
            // Fuse the iterator.
            self.entry_index = usize::MAX;
        } else {
            self.entry_index = index;
        }
    }
}

impl<'l, K, V> Debug for Scanner<'l, K, V>
where
    K: 'static + Clone + Ord,
    V: 'static + Clone,
{
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Scanner")
            .field("metadata", &self.metadata)
            .field("entry_index", &self.entry_index)
            .finish()
    }
}

impl<'l, K, V> Iterator for Scanner<'l, K, V>
where
    K: Clone + Ord,
    V: Clone,
{
    type Item = (&'l K, &'l V);

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.proceed();
        self.get()
    }
}

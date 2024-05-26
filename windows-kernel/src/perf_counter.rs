use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;

use windows_kernel_sys::base::_LARGE_INTEGER;
use windows_kernel_sys::ntoskrnl::{KeQueryPerformanceCounter, KeQuerySystemTimePrecise};

use crate::time::Instant;

const NANOS_PER_SEC: u64 = 1_000_000_000;
const INTERVALS_PER_SEC: u64 = NANOS_PER_SEC / 100;

pub struct PerformanceCounterInstant {
    ts: u64,
}

impl PerformanceCounterInstant {
    pub fn now() -> Self {
        Self { ts: query() }
    }

    // Per microsoft docs, the margin of error for cross-thread time comparisons
    // using QueryPerformanceCounter is 1 "tick" -- defined as 1/frequency().
    // Reference: https://docs.microsoft.com/en-us/windows/desktop/SysInfo
    //                   /acquiring-high-resolution-time-stamps
    pub fn epsilon() -> Duration {
        let epsilon = NANOS_PER_SEC / (frequency() as u64);
        Duration::from_nanos(epsilon)
    }
}

impl From<PerformanceCounterInstant> for Instant {
    fn from(other: PerformanceCounterInstant) -> Self {
        let freq = frequency();
        let instant_nsec = mul_div_u64(other.ts as u64, NANOS_PER_SEC, freq);
        Self {
            t: Duration::from_nanos(instant_nsec),
        }
    }
}

fn frequency() -> u64 {
    // Either the cached result of `QueryPerformanceFrequency` or `0` for
    // uninitialized. Storing this as a single `AtomicU64` allows us to use
    // `Relaxed` operations, as we are only interested in the effects on a
    // single memory location.
    static FREQUENCY: AtomicU64 = AtomicU64::new(0);

    let cached = FREQUENCY.load(Ordering::Relaxed);
    // If a previous thread has filled in this global state, use that.
    if cached != 0 {
        return cached;
    }
    // ... otherwise learn for ourselves ...
    let mut frequency = _LARGE_INTEGER { QuadPart: 0 };
    unsafe {
        KeQueryPerformanceCounter(&mut frequency);
    }

    unsafe {
        FREQUENCY.store(frequency.QuadPart as u64, Ordering::Relaxed);
    }
    unsafe { frequency.QuadPart as u64 }
}

fn query() -> u64 {
    let mut qpc_value = _LARGE_INTEGER { QuadPart: 0 };
    unsafe { KeQuerySystemTimePrecise(&mut qpc_value) };
    unsafe { qpc_value.QuadPart as u64 }
}

pub fn mul_div_u64(value: u64, numer: u64, denom: u64) -> u64 {
    let q = value / denom;
    let r = value % denom;
    // Decompose value as (value/denom*denom + value%denom),
    // substitute into (value*numer)/denom and simplify.
    // r < denom, so (denom*numer) is the upper bound of (r*numer)
    q * numer + r * numer / denom
}

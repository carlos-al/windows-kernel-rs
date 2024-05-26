use core::time::Duration;

use crate::perf_counter::PerformanceCounterInstant;

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Hash)]
pub struct Instant {
    // This duration is relative to an arbitrary microsecond epoch
    // from the winapi KeQueryPerformanceCounter function.
    pub(crate) t: Duration,
}

impl Instant {
    pub fn now() -> Instant {
        // High precision timing on windows operates in "Performance Counter"
        // units, as returned by the WINAPI KeQueryPerformanceCounter function.
        // These relate to seconds by a factor of QueryPerformanceFrequency.
        // In order to keep unit conversions out of normal interval math, we
        // measure in QPC units and immediately convert to nanoseconds.
        PerformanceCounterInstant::now().into()
    }

    pub fn checked_sub_instant(&self, other: &Instant) -> Option<Duration> {
        // On windows there's a threshold below which we consider two timestamps
        // equivalent due to measurement error. For more details + doc link,
        // check the docs on epsilon.
        let epsilon = PerformanceCounterInstant::epsilon();
        if other.t > self.t && other.t - self.t <= epsilon {
            Some(Duration::new(0, 0))
        } else {
            self.t.checked_sub(other.t)
        }
    }

    pub fn checked_add_duration(&self, other: &Duration) -> Option<Instant> {
        Some(Instant {
            t: self.t.checked_add(*other)?,
        })
    }

    pub fn checked_sub_duration(&self, other: &Duration) -> Option<Instant> {
        Some(Instant {
            t: self.t.checked_sub(*other)?,
        })
    }
}

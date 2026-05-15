// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

use std::ops::{Deref, DerefMut};

/// A thin `parking_lot::Mutex` wrapper that preserves the existing call sites'
/// lock-purpose argument without keeping a separate feature-gated implementation.
#[derive(Debug)]
pub(crate) struct Mutex<T> {
    inner: parking_lot::Mutex<T>,
}

impl<T> Mutex<T> {
    pub(crate) fn new(value: T) -> Self {
        Self {
            inner: parking_lot::Mutex::new(value),
        }
    }

    /// Acquires the lock for a certain purpose.
    pub(crate) fn lock(&self, purpose: &'static str) -> MutexGuard<'_, T> {
        let _ = purpose;
        MutexGuard {
            guard: self.inner.lock(),
        }
    }
}

pub(crate) struct MutexGuard<'a, T> {
    guard: parking_lot::MutexGuard<'a, T>,
}

impl<T> Deref for MutexGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.guard.deref()
    }
}

impl<T> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.guard.deref_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stores_initial_value() {
        let mutex = Mutex::new(42);
        let guard = mutex.lock("read initial value");
        assert_eq!(*guard, 42);
    }

    #[test]
    fn guard_supports_mutation_via_deref_mut() {
        let mutex = Mutex::new(vec![1, 2]);
        {
            let mut guard = mutex.lock("push value");
            guard.push(3);
        }

        assert_eq!(*mutex.lock("read mutated value"), vec![1, 2, 3]);
    }

    #[test]
    fn lock_purpose_is_observational_only() {
        let mutex = Mutex::new("value".to_string());
        assert_eq!(&*mutex.lock("first purpose"), "value");
        assert_eq!(&*mutex.lock("second purpose"), "value");
    }

    #[test]
    fn debug_output_includes_mutex_wrapper_name() {
        let mutex = Mutex::new(7_u8);
        let debug = format!("{mutex:?}");
        assert!(debug.contains("Mutex"));
    }
}

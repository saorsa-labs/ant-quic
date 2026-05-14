// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Read-only path handles for observing per-path connection state.

use std::{
    fmt,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use crate::{connection::PathStats, high_level::WeakConnectionHandle};

/// Identifier for a QUIC connection path.
///
/// The current read-only skeleton exposes only the primary single-path route.
/// Future multipath support will allocate additional IDs.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PathId(u64);

impl PathId {
    /// The primary single-path route used before multipath is negotiated.
    pub const PRIMARY: Self = Self(0);

    /// Return the numeric path identifier.
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl From<u64> for PathId {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<PathId> for u64 {
    fn from(value: PathId) -> Self {
        value.0
    }
}

impl fmt::Display for PathId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::PathStats;

    // ── PathId tests ──

    #[test]
    fn path_id_primary_is_zero() {
        assert_eq!(PathId::PRIMARY.get(), 0);
    }

    #[test]
    fn path_id_from_u64() {
        let id: PathId = 42u64.into();
        assert_eq!(id.get(), 42);
    }

    #[test]
    fn path_id_into_u64() {
        let id = PathId::PRIMARY;
        let val: u64 = id.into();
        assert_eq!(val, 0);
    }

    #[test]
    fn path_id_default_is_zero() {
        let id = PathId::default();
        assert_eq!(id.get(), 0);
        assert_eq!(id, PathId::PRIMARY);
    }

    #[test]
    fn path_id_equality() {
        assert_eq!(PathId::from(1u64), PathId::from(1u64));
        assert_ne!(PathId::from(1u64), PathId::from(2u64));
    }

    #[test]
    fn path_id_ordering() {
        assert!(PathId::from(0u64) < PathId::from(1u64));
        assert!(PathId::from(1u64) > PathId::from(0u64));
    }

    #[test]
    fn path_id_display() {
        assert_eq!(format!("{}", PathId::PRIMARY), "0");
        assert_eq!(format!("{}", PathId::from(42u64)), "42");
    }

    #[test]
    fn path_id_debug() {
        let debug = format!("{:?}", PathId::from(42u64));
        assert!(debug.contains("42"));
    }

    #[test]
    fn path_id_clone() {
        let a = PathId::from(5u64);
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn path_id_hash() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let a = PathId::from(10u64);
        let b = PathId::from(10u64);
        let mut ha = DefaultHasher::new();
        let mut hb = DefaultHasher::new();
        a.hash(&mut ha);
        b.hash(&mut hb);
        assert_eq!(ha.finish(), hb.finish());
    }

    // ── PathSnapshot tests ──

    #[test]
    fn path_snapshot_default() {
        let stats = PathStats::default();
        // PathSnapshot is pub(crate), test via construction
        let snapshot = PathSnapshot {
            stats,
            remote_address: "127.0.0.1:9000".parse().unwrap(),
            observed_external_addr: None,
        };
        assert_eq!(snapshot.remote_address.port(), 9000);
        assert!(snapshot.observed_external_addr.is_none());
    }

    #[test]
    fn path_snapshot_with_external_addr() {
        let stats = PathStats::default();
        let snapshot = PathSnapshot {
            stats,
            remote_address: "192.168.1.1:9000".parse().unwrap(),
            observed_external_addr: Some("10.0.0.1:9001".parse().unwrap()),
        };
        assert!(snapshot.observed_external_addr.is_some());
        assert_eq!(
            snapshot.observed_external_addr.unwrap().to_string(),
            "10.0.0.1:9001"
        );
    }

    #[test]
    fn path_snapshot_clone_copy() {
        let stats = PathStats::default();
        let s1 = PathSnapshot {
            stats,
            remote_address: "127.0.0.1:80".parse().unwrap(),
            observed_external_addr: None,
        };
        let s2 = s1;
        assert_eq!(s1.remote_address, s2.remote_address);
    }

    // ── RetainedPathSnapshot tests ──

    #[test]
    fn retained_path_snapshot_store_and_load() {
        let stats = PathStats::default();
        let snapshot = PathSnapshot {
            stats,
            remote_address: "127.0.0.1:9000".parse().unwrap(),
            observed_external_addr: None,
        };
        let retained = RetainedPathSnapshot::new(snapshot);
        let loaded = retained.load();
        assert_eq!(loaded.remote_address.port(), 9000);
    }

    #[test]
    fn retained_path_snapshot_overwrite() {
        let stats = PathStats::default();
        let snapshot1 = PathSnapshot {
            stats,
            remote_address: "127.0.0.1:1".parse().unwrap(),
            observed_external_addr: None,
        };
        let retained = RetainedPathSnapshot::new(snapshot1);

        let snapshot2 = PathSnapshot {
            stats: PathStats::default(),
            remote_address: "127.0.0.1:2".parse().unwrap(),
            observed_external_addr: None,
        };
        retained.store(snapshot2);

        let loaded = retained.load();
        assert_eq!(loaded.remote_address.port(), 2);
    }

    #[test]
    fn retained_path_snapshot_clone() {
        let stats = PathStats::default();
        let snapshot = PathSnapshot {
            stats,
            remote_address: "10.0.0.1:8000".parse().unwrap(),
            observed_external_addr: None,
        };
        let retained = RetainedPathSnapshot::new(snapshot);
        let cloned = retained.clone();
        assert_eq!(retained.load().remote_address, cloned.load().remote_address);
    }

    #[test]
    fn retained_path_snapshot_concurrent_independence() {
        let stats = PathStats::default();
        let snapshot = PathSnapshot {
            stats,
            remote_address: "127.0.0.1:9000".parse().unwrap(),
            observed_external_addr: None,
        };
        let retained = RetainedPathSnapshot::new(snapshot);
        let cloned = retained.clone();

        // Update one, the other should still see the old value
        let new_snapshot = PathSnapshot {
            stats: PathStats::default(),
            remote_address: "127.0.0.1:9999".parse().unwrap(),
            observed_external_addr: None,
        };
        retained.store(new_snapshot);

        assert_eq!(retained.load().remote_address.port(), 9999);
        assert_eq!(cloned.load().remote_address.port(), 9999); // shared Arc
    }
}

/// Snapshot of read-only path state.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PathSnapshot {
    pub(crate) stats: PathStats,
    pub(crate) remote_address: SocketAddr,
    pub(crate) observed_external_addr: Option<SocketAddr>,
}

#[derive(Debug, Clone)]
struct RetainedPathSnapshot(Arc<Mutex<PathSnapshot>>);

impl RetainedPathSnapshot {
    fn new(snapshot: PathSnapshot) -> Self {
        Self(Arc::new(Mutex::new(snapshot)))
    }

    fn load(&self) -> PathSnapshot {
        match self.0.lock() {
            Ok(snapshot) => *snapshot,
            Err(poisoned) => *poisoned.into_inner(),
        }
    }

    fn store(&self, snapshot: PathSnapshot) {
        match self.0.lock() {
            Ok(mut retained) => *retained = snapshot,
            Err(poisoned) => *poisoned.into_inner() = snapshot,
        }
    }
}

/// Read-only handle to a QUIC connection path.
///
/// `Path` does not keep the underlying connection alive. Accessors read live
/// state while the connection exists and fall back to the retained snapshot
/// after the connection/path has gone away.
#[derive(Debug, Clone)]
pub struct Path {
    conn_handle: WeakConnectionHandle,
    id: PathId,
    retained: RetainedPathSnapshot,
}

impl Path {
    pub(crate) fn new(
        conn_handle: WeakConnectionHandle,
        id: PathId,
        snapshot: PathSnapshot,
    ) -> Self {
        Self {
            conn_handle,
            id,
            retained: RetainedPathSnapshot::new(snapshot),
        }
    }

    fn live_snapshot(&self) -> Option<PathSnapshot> {
        self.conn_handle
            .upgrade()
            .and_then(|conn| conn.path_snapshot(self.id))
    }

    fn snapshot(&self) -> PathSnapshot {
        if let Some(snapshot) = self.live_snapshot() {
            self.retained.store(snapshot);
            snapshot
        } else {
            self.retained.load()
        }
    }

    /// Return this path's identifier.
    pub fn id(&self) -> PathId {
        self.id
    }

    /// Return the latest readable statistics for this path.
    pub fn stats(&self) -> PathStats {
        self.snapshot().stats
    }

    /// Return the peer UDP address associated with this path.
    pub fn remote_address(&self) -> SocketAddr {
        self.snapshot().remote_address
    }

    /// Return the external/reflexive address observed for this path.
    pub fn observed_external_addr(&self) -> Option<SocketAddr> {
        self.snapshot().observed_external_addr
    }

    /// Downgrade this path to a weak handle.
    pub fn weak_handle(&self) -> WeakPathHandle {
        WeakPathHandle {
            conn_handle: self.conn_handle.clone(),
            id: self.id,
            retained: self.retained.clone(),
        }
    }
}

impl Drop for Path {
    fn drop(&mut self) {
        if let Some(snapshot) = self.live_snapshot() {
            self.retained.store(snapshot);
        }
    }
}

/// Weak read-only handle to a QUIC connection path.
///
/// The handle can expose retained path state after the connection/path has
/// closed without keeping the connection alive.
#[derive(Debug, Clone)]
pub struct WeakPathHandle {
    conn_handle: WeakConnectionHandle,
    id: PathId,
    retained: RetainedPathSnapshot,
}

impl WeakPathHandle {
    fn live_snapshot(&self) -> Option<PathSnapshot> {
        self.conn_handle
            .upgrade()
            .and_then(|conn| conn.path_snapshot(self.id))
    }

    fn snapshot(&self) -> PathSnapshot {
        if let Some(snapshot) = self.live_snapshot() {
            self.retained.store(snapshot);
            snapshot
        } else {
            self.retained.load()
        }
    }

    /// Return this path's identifier.
    pub fn id(&self) -> PathId {
        self.id
    }

    /// Upgrade to a live path handle if the path's connection is still alive.
    pub fn upgrade(&self) -> Option<Path> {
        if !self.conn_handle.is_alive() {
            return None;
        }

        let snapshot = self.live_snapshot()?;
        Some(Path {
            conn_handle: self.conn_handle.clone(),
            id: self.id,
            retained: RetainedPathSnapshot::new(snapshot),
        })
    }

    /// Return true while the underlying path's connection is still alive.
    pub fn is_alive(&self) -> bool {
        self.conn_handle.is_alive() && self.live_snapshot().is_some()
    }

    /// Return the latest readable statistics for this path.
    pub fn stats(&self) -> PathStats {
        self.snapshot().stats
    }

    /// Return the retained or live peer UDP address associated with this path.
    pub fn remote_address(&self) -> SocketAddr {
        self.snapshot().remote_address
    }

    /// Return the retained or live external/reflexive address for this path.
    pub fn observed_external_addr(&self) -> Option<SocketAddr> {
        self.snapshot().observed_external_addr
    }
}

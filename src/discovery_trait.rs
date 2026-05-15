// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Discovery trait for stream composition
//!
//! Provides a trait-based abstraction for address discovery that allows
//! composing multiple discovery sources into a unified stream.
//!
//! This is inspired by iroh's `Discovery` trait and `ConcurrentDiscovery`.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::stream::Stream;
use tokio::sync::mpsc;

use crate::nat_traversal_api::PeerId;

/// Information about a discovered address
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredAddress {
    /// The discovered socket address
    pub addr: SocketAddr,
    /// Source of the discovery
    pub source: DiscoverySource,
    /// Priority of this address (higher = better)
    pub priority: u32,
    /// Time-to-live for this discovery
    pub ttl: Option<Duration>,
}

/// Source of address discovery
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiscoverySource {
    /// Discovered from local network interfaces
    LocalInterface,
    /// Discovered via peer exchange
    PeerExchange,
    /// Observed by a remote peer
    Observed,
    /// From configuration or known peers
    Config,
    /// Manual/explicit discovery
    Manual,
    /// From DNS resolution
    Dns,
}

impl DiscoverySource {
    /// Get base priority for this source
    pub fn base_priority(&self) -> u32 {
        match self {
            Self::Observed => 100, // Highest - verified by peer
            Self::LocalInterface => 90,
            Self::PeerExchange => 80,
            Self::Config => 70,
            Self::Dns => 60,
            Self::Manual => 50,
        }
    }
}

/// Result of a discovery operation
pub type DiscoveryResult = Result<DiscoveredAddress, DiscoveryError>;

/// Error from discovery operations
#[derive(Debug, Clone)]
pub struct DiscoveryError {
    /// Error message
    pub message: String,
    /// Source that failed
    pub source: Option<DiscoverySource>,
    /// Whether this error is retryable
    pub retryable: bool,
}

impl std::fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Discovery error: {}", self.message)
    }
}

impl std::error::Error for DiscoveryError {}

/// Trait for address discovery sources
///
/// Implementations provide a stream of discovered addresses
/// that can be composed with other discovery sources.
pub trait Discovery: Send + Sync + 'static {
    /// Discover addresses for a given peer
    ///
    /// Returns a stream of discovered addresses. The stream may
    /// continue indefinitely or terminate when discovery is complete.
    fn discover(
        &self,
        peer_id: &PeerId,
    ) -> Pin<Box<dyn Stream<Item = DiscoveryResult> + Send + 'static>>;

    /// Get the name of this discovery source (for logging)
    fn name(&self) -> &'static str;
}

/// Combines multiple discovery sources into a concurrent stream
#[derive(Default)]
pub struct ConcurrentDiscovery {
    sources: Vec<Arc<dyn Discovery>>,
}

impl ConcurrentDiscovery {
    /// Create a new concurrent discovery with no sources
    pub fn new() -> Self {
        Self {
            sources: Vec::new(),
        }
    }

    /// Add a discovery source
    pub fn add_source<D: Discovery>(&mut self, source: D) {
        self.sources.push(Arc::new(source));
    }

    /// Add a boxed discovery source
    pub fn add_boxed_source(&mut self, source: Arc<dyn Discovery>) {
        self.sources.push(source);
    }

    /// Create a builder for fluent construction
    pub fn builder() -> ConcurrentDiscoveryBuilder {
        ConcurrentDiscoveryBuilder::new()
    }

    /// Discover addresses from all sources concurrently
    pub fn discover(&self, peer_id: &PeerId) -> ConcurrentDiscoveryStream {
        let mut streams = Vec::new();

        for source in &self.sources {
            streams.push(source.discover(peer_id));
        }

        ConcurrentDiscoveryStream::new(streams)
    }

    /// Number of discovery sources
    pub fn source_count(&self) -> usize {
        self.sources.len()
    }
}

/// Builder for ConcurrentDiscovery
#[derive(Default)]
pub struct ConcurrentDiscoveryBuilder {
    sources: Vec<Arc<dyn Discovery>>,
}

impl ConcurrentDiscoveryBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            sources: Vec::new(),
        }
    }

    /// Add a discovery source
    pub fn with_source<D: Discovery>(mut self, source: D) -> Self {
        self.sources.push(Arc::new(source));
        self
    }

    /// Build the concurrent discovery
    pub fn build(self) -> ConcurrentDiscovery {
        ConcurrentDiscovery {
            sources: self.sources,
        }
    }
}

/// Stream that polls multiple discovery sources concurrently
pub struct ConcurrentDiscoveryStream {
    streams: Vec<Pin<Box<dyn Stream<Item = DiscoveryResult> + Send + 'static>>>,
    completed: Vec<bool>,
}

impl ConcurrentDiscoveryStream {
    fn new(streams: Vec<Pin<Box<dyn Stream<Item = DiscoveryResult> + Send + 'static>>>) -> Self {
        let completed = vec![false; streams.len()];
        Self { streams, completed }
    }
}

impl Stream for ConcurrentDiscoveryStream {
    type Item = DiscoveryResult;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;

        // Check if all streams are done
        if this.completed.iter().all(|&c| c) {
            return Poll::Ready(None);
        }

        // Poll each stream, returning the first ready result
        for i in 0..this.streams.len() {
            if this.completed[i] {
                continue;
            }

            match this.streams[i].as_mut().poll_next(cx) {
                Poll::Ready(Some(result)) => {
                    return Poll::Ready(Some(result));
                }
                Poll::Ready(None) => {
                    this.completed[i] = true;
                }
                Poll::Pending => {}
            }
        }

        // Check again if all completed during this poll
        if this.completed.iter().all(|&c| c) {
            Poll::Ready(None)
        } else {
            Poll::Pending
        }
    }
}

/// A simple discovery source that yields addresses from a channel
pub struct ChannelDiscovery {
    name: &'static str,
    sender: mpsc::Sender<DiscoveredAddress>,
    receiver: Arc<tokio::sync::Mutex<mpsc::Receiver<DiscoveredAddress>>>,
}

impl ChannelDiscovery {
    /// Create a new channel-based discovery
    pub fn new(name: &'static str, buffer_size: usize) -> Self {
        let (sender, receiver) = mpsc::channel(buffer_size);
        Self {
            name,
            sender,
            receiver: Arc::new(tokio::sync::Mutex::new(receiver)),
        }
    }

    /// Get a sender to push discovered addresses
    pub fn sender(&self) -> mpsc::Sender<DiscoveredAddress> {
        self.sender.clone()
    }

    /// Push a discovered address
    pub async fn push(
        &self,
        addr: DiscoveredAddress,
    ) -> Result<(), mpsc::error::SendError<DiscoveredAddress>> {
        self.sender.send(addr).await
    }
}

impl Discovery for ChannelDiscovery {
    fn discover(
        &self,
        _peer_id: &PeerId,
    ) -> Pin<Box<dyn Stream<Item = DiscoveryResult> + Send + 'static>> {
        let receiver = self.receiver.clone();

        Box::pin(futures_util::stream::unfold(
            receiver,
            |receiver| async move {
                let mut guard = receiver.lock().await;
                guard.recv().await.map(|addr| (Ok(addr), receiver.clone()))
            },
        ))
    }

    fn name(&self) -> &'static str {
        self.name
    }
}

/// Discovery source from static/configured addresses
pub struct StaticDiscovery {
    addresses: Vec<DiscoveredAddress>,
}

impl StaticDiscovery {
    /// Create a new static discovery with the given addresses
    pub fn new(addresses: Vec<DiscoveredAddress>) -> Self {
        Self { addresses }
    }

    /// Create from socket addresses with default settings
    pub fn from_addrs(addrs: Vec<SocketAddr>) -> Self {
        let addresses = addrs
            .into_iter()
            .map(|addr| DiscoveredAddress {
                addr,
                source: DiscoverySource::Config,
                priority: DiscoverySource::Config.base_priority(),
                ttl: None,
            })
            .collect();
        Self { addresses }
    }
}

impl Discovery for StaticDiscovery {
    fn discover(
        &self,
        _peer_id: &PeerId,
    ) -> Pin<Box<dyn Stream<Item = DiscoveryResult> + Send + 'static>> {
        let addresses = self.addresses.clone();
        Box::pin(futures_util::stream::iter(addresses.into_iter().map(Ok)))
    }

    fn name(&self) -> &'static str {
        "static"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::StreamExt;

    fn test_addr(port: u16) -> SocketAddr {
        format!("192.168.1.1:{}", port).parse().unwrap()
    }

    fn test_peer_id() -> PeerId {
        PeerId([0u8; 32])
    }

    fn test_discovered_addr(
        port: u16,
        source: DiscoverySource,
        priority: u32,
    ) -> DiscoveredAddress {
        DiscoveredAddress {
            addr: test_addr(port),
            source,
            priority,
            ttl: None,
        }
    }

    // DiscoverySource tests

    #[test]
    fn test_discovery_source_priority_values() {
        assert_eq!(DiscoverySource::Observed.base_priority(), 100);
        assert_eq!(DiscoverySource::LocalInterface.base_priority(), 90);
        assert_eq!(DiscoverySource::PeerExchange.base_priority(), 80);
        assert_eq!(DiscoverySource::Config.base_priority(), 70);
        assert_eq!(DiscoverySource::Dns.base_priority(), 60);
        assert_eq!(DiscoverySource::Manual.base_priority(), 50);
    }

    #[test]
    fn test_discovery_source_order() {
        assert!(
            DiscoverySource::Observed.base_priority()
                > DiscoverySource::LocalInterface.base_priority()
        );
        assert!(
            DiscoverySource::LocalInterface.base_priority()
                > DiscoverySource::PeerExchange.base_priority()
        );
        assert!(
            DiscoverySource::PeerExchange.base_priority() > DiscoverySource::Config.base_priority()
        );
        assert!(DiscoverySource::Config.base_priority() > DiscoverySource::Dns.base_priority());
        assert!(DiscoverySource::Dns.base_priority() > DiscoverySource::Manual.base_priority());
    }

    #[test]
    fn test_discovery_source_equality() {
        assert_eq!(DiscoverySource::Observed, DiscoverySource::Observed);
        assert_ne!(DiscoverySource::Observed, DiscoverySource::Config);
    }

    #[test]
    fn test_discovery_source_clone_copy() {
        let a = DiscoverySource::Observed;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn test_discovery_source_debug() {
        assert_eq!(format!("{:?}", DiscoverySource::Observed), "Observed");
        assert_eq!(format!("{:?}", DiscoverySource::Dns), "Dns");
    }

    // DiscoveredAddress tests

    #[test]
    fn test_discovered_address_clone() {
        let addr = test_discovered_addr(5000, DiscoverySource::Observed, 100);
        let cloned = addr.clone();
        assert_eq!(addr, cloned);
    }

    #[test]
    fn test_discovered_address_debug() {
        let addr = test_discovered_addr(8080, DiscoverySource::Config, 70);
        let debug = format!("{addr:?}");
        assert!(debug.contains("8080"));
        assert!(debug.contains("Config"));
    }

    #[test]
    fn test_discovered_address_equality() {
        let a = test_discovered_addr(5000, DiscoverySource::Config, 70);
        let b = test_discovered_addr(5000, DiscoverySource::Config, 70);
        let c = test_discovered_addr(5001, DiscoverySource::Config, 70);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_discovered_address_different_sources_not_equal() {
        let a = test_discovered_addr(5000, DiscoverySource::Config, 70);
        let b = test_discovered_addr(5000, DiscoverySource::Observed, 100);
        assert_ne!(a, b);
    }

    // DiscoveryError tests

    #[test]
    fn test_discovery_error_display() {
        let err = DiscoveryError {
            message: "test error".to_string(),
            source: Some(DiscoverySource::Dns),
            retryable: true,
        };
        let display = err.to_string();
        assert!(display.contains("test error"));
        assert!(display.contains("Discovery error"));
    }

    #[test]
    fn test_discovery_error_clone() {
        let err = DiscoveryError {
            message: "err".to_string(),
            source: None,
            retryable: false,
        };
        let cloned = err.clone();
        assert_eq!(err.message, cloned.message);
        assert_eq!(err.source, cloned.source);
        assert_eq!(err.retryable, cloned.retryable);
    }

    #[test]
    fn test_discovery_error_debug() {
        let err = DiscoveryError {
            message: "debug me".to_string(),
            source: Some(DiscoverySource::Config),
            retryable: true,
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("debug me"));
        assert!(debug.contains("Config"));
    }

    #[test]
    fn test_discovery_error_retryable_flag() {
        let err_retryable = DiscoveryError {
            message: "retry".to_string(),
            source: None,
            retryable: true,
        };
        let err_not = DiscoveryError {
            message: "fatal".to_string(),
            source: None,
            retryable: false,
        };
        assert!(err_retryable.retryable);
        assert!(!err_not.retryable);
    }

    #[test]
    fn test_discovery_error_with_source() {
        let err = DiscoveryError {
            message: "dns failed".to_string(),
            source: Some(DiscoverySource::Dns),
            retryable: true,
        };
        assert_eq!(err.source, Some(DiscoverySource::Dns));
    }

    // StaticDiscovery tests

    #[test]
    fn test_static_discovery_name() {
        let discovery = StaticDiscovery::from_addrs(vec![]);
        assert_eq!(discovery.name(), "static");
    }

    #[tokio::test]
    async fn test_static_discovery() {
        let addrs = vec![test_addr(5000), test_addr(5001)];
        let discovery = StaticDiscovery::from_addrs(addrs.clone());
        let mut stream = discovery.discover(&test_peer_id());
        let first = stream.next().await.unwrap().unwrap();
        assert_eq!(first.addr, addrs[0]);
        let second = stream.next().await.unwrap().unwrap();
        assert_eq!(second.addr, addrs[1]);
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn test_static_discovery_empty() {
        let discovery = StaticDiscovery::from_addrs(vec![]);
        let mut stream = discovery.discover(&test_peer_id());
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn test_static_discovery_new() {
        let addr = test_discovered_addr(9000, DiscoverySource::Config, 70);
        let discovery = StaticDiscovery::new(vec![addr.clone()]);
        assert_eq!(discovery.name(), "static");
        let mut stream = discovery.discover(&test_peer_id());
        let result = stream.next().await.unwrap().unwrap();
        assert_eq!(result.addr, addr.addr);
    }

    // ConcurrentDiscovery tests

    #[test]
    fn test_concurrent_discovery_new_empty() {
        let discovery = ConcurrentDiscovery::new();
        assert_eq!(discovery.source_count(), 0);
    }

    #[test]
    fn test_concurrent_discovery_default() {
        let discovery = ConcurrentDiscovery::default();
        assert_eq!(discovery.source_count(), 0);
    }

    #[test]
    fn test_concurrent_discovery_add_source() {
        let mut discovery = ConcurrentDiscovery::new();
        assert_eq!(discovery.source_count(), 0);
        discovery.add_source(StaticDiscovery::from_addrs(vec![test_addr(5000)]));
        assert_eq!(discovery.source_count(), 1);
    }

    #[test]
    fn test_concurrent_discovery_multiple_sources() {
        let mut discovery = ConcurrentDiscovery::new();
        discovery.add_source(StaticDiscovery::from_addrs(vec![test_addr(5000)]));
        discovery.add_source(StaticDiscovery::from_addrs(vec![test_addr(6000)]));
        assert_eq!(discovery.source_count(), 2);
    }

    #[test]
    fn test_concurrent_discovery_add_boxed_source() {
        let mut discovery = ConcurrentDiscovery::new();
        let source: Arc<dyn Discovery> = Arc::new(StaticDiscovery::from_addrs(vec![]));
        discovery.add_boxed_source(source);
        assert_eq!(discovery.source_count(), 1);
    }

    #[tokio::test]
    async fn test_concurrent_discovery_with_two_sources() {
        let addrs1 = vec![test_addr(5000)];
        let addrs2 = vec![test_addr(6000)];

        let discovery = ConcurrentDiscovery::builder()
            .with_source(StaticDiscovery::from_addrs(addrs1))
            .with_source(StaticDiscovery::from_addrs(addrs2))
            .build();

        assert_eq!(discovery.source_count(), 2);
        let mut stream = discovery.discover(&test_peer_id());
        let mut found_ports = vec![];
        while let Some(result) = stream.next().await {
            found_ports.push(result.unwrap().addr.port());
        }
        assert!(found_ports.contains(&5000));
        assert!(found_ports.contains(&6000));
    }

    #[tokio::test]
    async fn test_empty_concurrent_discovery() {
        let discovery = ConcurrentDiscovery::new();
        let mut stream = discovery.discover(&test_peer_id());
        assert!(stream.next().await.is_none());
    }

    // ConcurrentDiscoveryBuilder tests

    #[test]
    fn test_builder_empty() {
        let discovery = ConcurrentDiscoveryBuilder::new().build();
        assert_eq!(discovery.source_count(), 0);
    }

    #[test]
    fn test_builder_pattern() {
        let discovery = ConcurrentDiscoveryBuilder::new()
            .with_source(StaticDiscovery::from_addrs(vec![test_addr(5000)]))
            .with_source(StaticDiscovery::from_addrs(vec![test_addr(6000)]))
            .build();
        assert_eq!(discovery.source_count(), 2);
    }

    #[test]
    fn test_builder_single_source() {
        let discovery = ConcurrentDiscoveryBuilder::new()
            .with_source(StaticDiscovery::from_addrs(vec![test_addr(5000)]))
            .build();
        assert_eq!(discovery.source_count(), 1);
    }

    // ChannelDiscovery tests

    #[tokio::test]
    async fn test_channel_discovery() {
        let discovery = ChannelDiscovery::new("test", 10);
        let sender = discovery.sender();
        tokio::spawn(async move {
            sender
                .send(test_discovered_addr(7000, DiscoverySource::Observed, 100))
                .await
                .unwrap();
        });
        let mut stream = discovery.discover(&test_peer_id());
        let result = tokio::time::timeout(Duration::from_millis(100), stream.next()).await;
        assert!(result.is_ok());
        let addr = result.unwrap().unwrap().unwrap();
        assert_eq!(addr.addr.port(), 7000);
    }

    #[test]
    fn test_channel_discovery_name() {
        let discovery = ChannelDiscovery::new("custom-name", 5);
        assert_eq!(discovery.name(), "custom-name");
    }

    #[test]
    fn test_channel_discovery_sender_is_cloneable() {
        let discovery = ChannelDiscovery::new("clone-test", 5);
        let sender1 = discovery.sender();
        let sender2 = discovery.sender();
        // Both senders should be usable
        drop(sender1);
        drop(sender2);
    }
}

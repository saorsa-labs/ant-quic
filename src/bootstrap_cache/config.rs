// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Bootstrap cache configuration.

use std::path::PathBuf;
use std::time::Duration;

/// Configuration for the bootstrap cache
#[derive(Debug, Clone)]
pub struct BootstrapCacheConfig {
    /// Directory for cache files
    pub cache_dir: PathBuf,

    /// Maximum number of peers to cache (default: 30,000 per ADR-007)
    pub max_peers: usize,

    /// Epsilon for exploration rate (default: 0.1 = 10%)
    /// Higher values = more exploration of unknown peers
    pub epsilon: f64,

    /// Time after which peers are considered stale (default: 7 days)
    pub stale_threshold: Duration,

    /// Freshness window for peer-verified direct reachability evidence.
    pub reachability_ttl: Duration,

    /// Interval between background save operations (default: 5 minutes)
    pub save_interval: Duration,

    /// Interval between quality score recalculations (default: 1 hour)
    pub quality_update_interval: Duration,

    /// Interval between stale peer cleanup (default: 6 hours)
    pub cleanup_interval: Duration,

    /// Minimum peers required before saving (prevents empty cache overwrite)
    pub min_peers_to_save: usize,

    /// Enable file locking for multi-process safety
    pub enable_file_locking: bool,

    /// Quality score weights
    pub weights: QualityWeights,
}

/// Weights for quality score calculation
#[derive(Debug, Clone)]
pub struct QualityWeights {
    /// Weight for success rate component (default: 0.4)
    pub success_rate: f64,
    /// Weight for RTT component (default: 0.25)
    pub rtt: f64,
    /// Weight for age/freshness component (default: 0.15)
    pub freshness: f64,
    /// Weight for capability bonuses (default: 0.2)
    pub capabilities: f64,
}

impl Default for BootstrapCacheConfig {
    fn default() -> Self {
        Self {
            cache_dir: default_cache_dir(),
            max_peers: 30_000,
            epsilon: 0.1,
            stale_threshold: Duration::from_secs(7 * 24 * 3600), // 7 days
            reachability_ttl: crate::reachability::DIRECT_REACHABILITY_TTL,
            save_interval: Duration::from_secs(5 * 60), // 5 minutes
            quality_update_interval: Duration::from_secs(3600), // 1 hour
            cleanup_interval: Duration::from_secs(6 * 3600), // 6 hours
            min_peers_to_save: 10,
            enable_file_locking: true,
            weights: QualityWeights::default(),
        }
    }
}

impl Default for QualityWeights {
    fn default() -> Self {
        Self {
            success_rate: 0.4,
            rtt: 0.25,
            freshness: 0.15,
            capabilities: 0.2,
        }
    }
}

impl BootstrapCacheConfig {
    /// Create a new configuration builder
    pub fn builder() -> BootstrapCacheConfigBuilder {
        BootstrapCacheConfigBuilder::default()
    }
}

/// Builder for BootstrapCacheConfig
#[derive(Default)]
pub struct BootstrapCacheConfigBuilder {
    config: BootstrapCacheConfig,
}

impl BootstrapCacheConfigBuilder {
    /// Set the cache directory
    pub fn cache_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.config.cache_dir = dir.into();
        self
    }

    /// Set maximum number of peers
    pub fn max_peers(mut self, max: usize) -> Self {
        self.config.max_peers = max;
        self
    }

    /// Set epsilon for exploration rate (clamped to 0.0-1.0)
    pub fn epsilon(mut self, epsilon: f64) -> Self {
        self.config.epsilon = epsilon.clamp(0.0, 1.0);
        self
    }

    /// Set freshness window for peer-verified direct reachability evidence.
    pub fn reachability_ttl(mut self, ttl: Duration) -> Self {
        self.config.reachability_ttl = ttl;
        self
    }

    /// Set stale threshold duration
    pub fn stale_threshold(mut self, duration: Duration) -> Self {
        self.config.stale_threshold = duration;
        self
    }

    /// Set save interval
    pub fn save_interval(mut self, duration: Duration) -> Self {
        self.config.save_interval = duration;
        self
    }

    /// Set quality update interval
    pub fn quality_update_interval(mut self, duration: Duration) -> Self {
        self.config.quality_update_interval = duration;
        self
    }

    /// Set cleanup interval
    pub fn cleanup_interval(mut self, duration: Duration) -> Self {
        self.config.cleanup_interval = duration;
        self
    }

    /// Set minimum peers required to save
    pub fn min_peers_to_save(mut self, min: usize) -> Self {
        self.config.min_peers_to_save = min;
        self
    }

    /// Enable or disable file locking
    pub fn enable_file_locking(mut self, enable: bool) -> Self {
        self.config.enable_file_locking = enable;
        self
    }

    /// Set quality weights
    pub fn weights(mut self, weights: QualityWeights) -> Self {
        self.config.weights = weights;
        self
    }

    /// Build the configuration
    pub fn build(self) -> BootstrapCacheConfig {
        self.config
    }
}

fn default_cache_dir() -> PathBuf {
    // Prefer TMPDIR for sandbox compatibility (Claude Code sets this to /tmp/claude)
    if let Ok(tmpdir) = std::env::var("TMPDIR") {
        return PathBuf::from(tmpdir).join("ant-quic-cache");
    }

    // Try platform-specific cache directory, fallback to current directory
    if let Some(cache_dir) = dirs::cache_dir() {
        cache_dir.join("ant-quic")
    } else if let Some(home) = dirs::home_dir() {
        home.join(".cache").join("ant-quic")
    } else {
        PathBuf::from(".ant-quic-cache")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = BootstrapCacheConfig::default();
        assert_eq!(config.max_peers, 30_000);
        assert!((config.epsilon - 0.1).abs() < f64::EPSILON);
        assert_eq!(config.stale_threshold, Duration::from_secs(7 * 24 * 3600));
    }

    #[test]
    fn test_builder() {
        let config = BootstrapCacheConfig::builder()
            .max_peers(10_000)
            .epsilon(0.2)
            .cache_dir("/tmp/test")
            .build();

        assert_eq!(config.max_peers, 10_000);
        assert!((config.epsilon - 0.2).abs() < f64::EPSILON);
        assert_eq!(config.cache_dir, PathBuf::from("/tmp/test"));
    }

    #[test]
    fn test_epsilon_clamping() {
        let config = BootstrapCacheConfig::builder().epsilon(1.5).build();
        assert!((config.epsilon - 1.0).abs() < f64::EPSILON);

        let config = BootstrapCacheConfig::builder().epsilon(-0.5).build();
        assert!(config.epsilon.abs() < f64::EPSILON);
    }

    #[test]
    fn default_config_sets_all_intervals_and_flags() {
        let config = BootstrapCacheConfig::default();
        assert_eq!(
            config.reachability_ttl,
            crate::reachability::DIRECT_REACHABILITY_TTL
        );
        assert_eq!(config.save_interval, Duration::from_secs(5 * 60));
        assert_eq!(config.quality_update_interval, Duration::from_secs(3600));
        assert_eq!(config.cleanup_interval, Duration::from_secs(6 * 3600));
        assert_eq!(config.min_peers_to_save, 10);
        assert!(config.enable_file_locking);
        assert!(
            config.cache_dir.ends_with("ant-quic-cache") || config.cache_dir.ends_with("ant-quic")
        );
    }

    #[test]
    fn quality_weights_default_sum_to_one() {
        let weights = QualityWeights::default();
        assert!((weights.success_rate - 0.4).abs() < f64::EPSILON);
        assert!((weights.rtt - 0.25).abs() < f64::EPSILON);
        assert!((weights.freshness - 0.15).abs() < f64::EPSILON);
        assert!((weights.capabilities - 0.2).abs() < f64::EPSILON);
        let total = weights.success_rate + weights.rtt + weights.freshness + weights.capabilities;
        assert!((total - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn builder_sets_all_duration_fields() {
        let config = BootstrapCacheConfig::builder()
            .stale_threshold(Duration::from_secs(1))
            .reachability_ttl(Duration::from_secs(2))
            .save_interval(Duration::from_secs(3))
            .quality_update_interval(Duration::from_secs(4))
            .cleanup_interval(Duration::from_secs(5))
            .build();

        assert_eq!(config.stale_threshold, Duration::from_secs(1));
        assert_eq!(config.reachability_ttl, Duration::from_secs(2));
        assert_eq!(config.save_interval, Duration::from_secs(3));
        assert_eq!(config.quality_update_interval, Duration::from_secs(4));
        assert_eq!(config.cleanup_interval, Duration::from_secs(5));
    }

    #[test]
    fn builder_sets_save_threshold_and_locking() {
        let config = BootstrapCacheConfig::builder()
            .min_peers_to_save(0)
            .enable_file_locking(false)
            .build();

        assert_eq!(config.min_peers_to_save, 0);
        assert!(!config.enable_file_locking);
    }

    #[test]
    fn builder_replaces_quality_weights() {
        let weights = QualityWeights {
            success_rate: 1.0,
            rtt: 2.0,
            freshness: 3.0,
            capabilities: 4.0,
        };
        let config = BootstrapCacheConfig::builder()
            .weights(weights.clone())
            .build();

        assert!((config.weights.success_rate - weights.success_rate).abs() < f64::EPSILON);
        assert!((config.weights.rtt - weights.rtt).abs() < f64::EPSILON);
        assert!((config.weights.freshness - weights.freshness).abs() < f64::EPSILON);
        assert!((config.weights.capabilities - weights.capabilities).abs() < f64::EPSILON);
    }

    #[test]
    fn config_clone_preserves_custom_values() {
        let config = BootstrapCacheConfig::builder()
            .cache_dir("relative/cache")
            .max_peers(42)
            .epsilon(0.75)
            .min_peers_to_save(3)
            .enable_file_locking(false)
            .build();
        let cloned = config.clone();

        assert_eq!(cloned.cache_dir, PathBuf::from("relative/cache"));
        assert_eq!(cloned.max_peers, 42);
        assert!((cloned.epsilon - 0.75).abs() < f64::EPSILON);
        assert_eq!(cloned.min_peers_to_save, 3);
        assert!(!cloned.enable_file_locking);
    }
}

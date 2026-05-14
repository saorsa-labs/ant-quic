// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Storing tokens sent from servers in NEW_TOKEN frames and using them in subsequent connections

use std::{
    collections::{HashMap, VecDeque, hash_map},
    sync::{Arc, Mutex},
};

use bytes::Bytes;
use lru_slab::LruSlab;
use tracing::{error, trace};

use crate::token::TokenStore;

/// `TokenStore` implementation that stores up to `N` tokens per server name for up to a
/// limited number of server names, in-memory
#[derive(Debug)]
pub(crate) struct TokenMemoryCache(Mutex<State>);

impl TokenMemoryCache {
    /// Construct empty
    pub(crate) fn new(max_server_names: u32, max_tokens_per_server: usize) -> Self {
        Self(Mutex::new(State::new(
            max_server_names,
            max_tokens_per_server,
        )))
    }
}

impl TokenStore for TokenMemoryCache {
    fn insert(&self, server_name: &str, token: Bytes) {
        trace!(%server_name, "storing token");
        let mut state = match self.0.lock() {
            Ok(state) => state,
            Err(e) => {
                error!("Token cache mutex poisoned: {}", e);
                return;
            }
        };
        state.store(server_name, token);
    }

    fn take(&self, server_name: &str) -> Option<Bytes> {
        let mut state = match self.0.lock() {
            Ok(state) => state,
            Err(e) => {
                error!("Token cache mutex poisoned: {}", e);
                return None;
            }
        };
        let token = state.take(server_name);
        trace!(%server_name, found=%token.is_some(), "taking token");
        token
    }
}

/// Defaults to a maximum of 256 servers and 2 tokens per server
impl Default for TokenMemoryCache {
    fn default() -> Self {
        Self::new(256, 2)
    }
}

/// Lockable inner state of `TokenMemoryCache`
#[derive(Debug)]
struct State {
    max_server_names: u32,
    max_tokens_per_server: usize,
    // map from server name to index in lru
    lookup: HashMap<Arc<str>, u32>,
    lru: LruSlab<CacheEntry>,
}

impl State {
    fn new(max_server_names: u32, max_tokens_per_server: usize) -> Self {
        Self {
            max_server_names,
            max_tokens_per_server,
            lookup: HashMap::new(),
            lru: LruSlab::default(),
        }
    }

    fn store(&mut self, server_name: &str, token: Bytes) {
        if self.max_server_names == 0 {
            // the rest of this method assumes that we can always insert a new entry so long as
            // we're willing to evict a pre-existing entry. thus, an entry limit of 0 is an edge
            // case we must short-circuit on now.
            return;
        }
        if self.max_tokens_per_server == 0 {
            // similarly to above, the rest of this method assumes that we can always push a new
            // token to a queue so long as we're willing to evict a pre-existing token, so we
            // short-circuit on the edge case of a token limit of 0.
            return;
        }

        let server_name = Arc::<str>::from(server_name);
        match self.lookup.entry(server_name.clone()) {
            hash_map::Entry::Occupied(hmap_entry) => {
                // key already exists, push the new token to its token queue
                let tokens = &mut self.lru.get_mut(*hmap_entry.get()).tokens;
                if tokens.len() >= self.max_tokens_per_server {
                    debug_assert!(tokens.len() == self.max_tokens_per_server);
                    if tokens.pop_front().is_none() {
                        debug_assert!(!tokens.is_empty());
                    }
                }
                tokens.push_back(token);
            }
            hash_map::Entry::Vacant(hmap_entry) => {
                // key does not yet exist, create a new one, evicting the oldest if necessary
                let removed_key = if self.lru.len() >= self.max_server_names {
                    // max_server_names is > 0, so there should be at least one entry
                    if let Some(lru_key) = self.lru.lru() {
                        Some(self.lru.remove(lru_key).server_name)
                    } else {
                        debug_assert!(false, "LRU should have at least one element");
                        return;
                    }
                } else {
                    None
                };

                hmap_entry.insert(self.lru.insert(CacheEntry::new(server_name, token)));

                // for borrowing reasons, we must defer removing the evicted hmap entry to here
                if let Some(removed_slot) = removed_key {
                    let removed = self.lookup.remove(&removed_slot);
                    debug_assert!(removed.is_some());
                }
            }
        };
    }

    fn take(&mut self, server_name: &str) -> Option<Bytes> {
        let slab_key = *self.lookup.get(server_name)?;

        // pop from entry's token queue
        let entry = self.lru.get_mut(slab_key);
        // unwrap safety: we never leave tokens empty
        let token = match entry.tokens.pop_front() {
            Some(token) => token,
            None => {
                debug_assert!(!entry.tokens.is_empty());
                return None;
            }
        };

        if entry.tokens.is_empty() {
            // token stack emptied, remove entry
            self.lru.remove(slab_key);
            self.lookup.remove(server_name);
        }

        Some(token)
    }
}

/// Cache entry within `TokenMemoryCache`'s LRU slab
#[derive(Debug)]
struct CacheEntry {
    server_name: Arc<str>,
    // invariant: tokens is never empty
    tokens: VecDeque<Bytes>,
}

impl CacheEntry {
    /// Construct with a single token
    fn new(server_name: Arc<str>, token: Bytes) -> Self {
        let mut tokens = VecDeque::new();
        tokens.push_back(token);
        Self {
            server_name,
            tokens,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;
    use rand::prelude::*;
    use rand_pcg::Pcg32;

    fn new_rng() -> impl Rng {
        Pcg32::from_seed(0xdeadbeefdeadbeefdeadbeefdeadbeefu128.to_le_bytes())
    }

    // CacheEntry tests

    #[test]
    fn cache_entry_new_has_one_token() {
        let entry = CacheEntry::new(Arc::from("test.com"), Bytes::from("token1"));
        assert_eq!(entry.server_name.as_ref(), "test.com");
        assert_eq!(entry.tokens.len(), 1);
    }

    // State tests

    #[test]
    fn state_store_new_server_creates_entry() {
        let mut state = State::new(10, 3);
        state.store("example.com", Bytes::from("abc"));
        assert!(state.lookup.contains_key("example.com"));
        let token = state.take("example.com");
        assert_eq!(token, Some(Bytes::from("abc")));
    }

    #[test]
    fn state_store_multiple_tokens_per_server() {
        let mut state = State::new(10, 3);
        state.store("srv", Bytes::from("t1"));
        state.store("srv", Bytes::from("t2"));
        state.store("srv", Bytes::from("t3"));
        assert_eq!(state.take("srv"), Some(Bytes::from("t1")));
        assert_eq!(state.take("srv"), Some(Bytes::from("t2")));
        assert_eq!(state.take("srv"), Some(Bytes::from("t3")));
        assert_eq!(state.take("srv"), None);
    }

    #[test]
    fn state_store_evicts_oldest_token_when_queue_full() {
        let mut state = State::new(10, 2);
        state.store("srv", Bytes::from("t1"));
        state.store("srv", Bytes::from("t2"));
        state.store("srv", Bytes::from("t3"));
        // t1 should be evicted, only t2 and t3 remain
        assert_eq!(state.take("srv"), Some(Bytes::from("t2")));
        assert_eq!(state.take("srv"), Some(Bytes::from("t3")));
        assert_eq!(state.take("srv"), None);
    }

    #[test]
    fn state_store_evicts_lru_server_when_max_servers_reached() {
        let mut state = State::new(2, 2);
        state.store("srv1", Bytes::from("a"));
        state.store("srv2", Bytes::from("b"));
        state.store("srv3", Bytes::from("c"));
        // srv1 should be evicted (LRU), srv2 and srv3 remain
        assert_eq!(state.take("srv1"), None);
        assert_eq!(state.take("srv2"), Some(Bytes::from("b")));
        assert_eq!(state.take("srv3"), Some(Bytes::from("c")));
    }

    #[test]
    fn state_store_zero_max_servers_does_nothing() {
        let mut state = State::new(0, 2);
        state.store("srv", Bytes::from("token"));
        assert!(state.lookup.is_empty());
        assert_eq!(state.take("srv"), None);
    }

    #[test]
    fn state_store_zero_queue_length_does_nothing() {
        let mut state = State::new(10, 0);
        state.store("srv", Bytes::from("token"));
        assert_eq!(state.take("srv"), None);
    }

    #[test]
    fn state_take_unknown_server_returns_none() {
        let mut state = State::new(10, 2);
        assert_eq!(state.take("unknown"), None);
    }

    #[test]
    fn state_take_removes_server_when_queue_emptied() {
        let mut state = State::new(10, 2);
        state.store("srv", Bytes::from("only"));
        assert!(state.lookup.contains_key("srv"));
        assert_eq!(state.take("srv"), Some(Bytes::from("only")));
        assert!(!state.lookup.contains_key("srv"));
    }

    #[test]
    fn state_store_updates_lru_order_on_existing_server() {
        let mut state = State::new(2, 2);
        state.store("srv1", Bytes::from("a"));
        state.store("srv2", Bytes::from("b"));
        // Access srv1 by storing another token (makes it recently used)
        state.store("srv1", Bytes::from("a2"));
        // Now store srv3 — should evict srv2 (oldest LRU), not srv1
        state.store("srv3", Bytes::from("c"));
        assert_eq!(state.take("srv1"), Some(Bytes::from("a")));
        assert_eq!(state.take("srv2"), None);
        assert_eq!(state.take("srv3"), Some(Bytes::from("c")));
    }

    #[test]
    fn state_multiple_servers_independent_queues() {
        let mut state = State::new(10, 3);
        state.store("srv1", Bytes::from("1a"));
        state.store("srv2", Bytes::from("2a"));
        state.store("srv1", Bytes::from("1b"));
        assert_eq!(state.take("srv1"), Some(Bytes::from("1a")));
        assert_eq!(state.take("srv2"), Some(Bytes::from("2a")));
        assert_eq!(state.take("srv1"), Some(Bytes::from("1b")));
    }

    #[test]
    fn state_store_different_tokens_same_server_fifo() {
        let mut state = State::new(10, 5);
        for i in 0..5 {
            state.store("srv", Bytes::from(vec![i]));
        }
        for i in 0..5 {
            let token = state.take("srv").unwrap();
            assert_eq!(token[0], i as u8);
        }
    }

    #[test]
    fn cache_entry_clone_arc() {
        let name = Arc::<str>::from("server.example.com");
        let entry = CacheEntry::new(name.clone(), Bytes::from("tok"));
        assert!(Arc::ptr_eq(&entry.server_name, &name));
    }

    // Existing integration tests preserved below

    #[test]
    fn cache_test() {
        let mut rng = new_rng();
        const N: usize = 2;

        for _ in 0..10 {
            let mut cache_1: Vec<(u32, VecDeque<Bytes>)> = Vec::new();
            let cache_2 = TokenMemoryCache::new(20, 2);

            for i in 0..200 {
                let server_name = rng.r#gen::<u32>() % 10;
                if rng.gen_bool(0.666) {
                    let token = Bytes::from(vec![i]);
                    if let Some((j, _)) = cache_1
                        .iter()
                        .enumerate()
                        .find(|&(_, &(server_name_2, _))| server_name_2 == server_name)
                    {
                        let (_, mut queue) = cache_1.remove(j);
                        queue.push_back(token.clone());
                        if queue.len() > N {
                            queue.pop_front();
                        }
                        cache_1.push((server_name, queue));
                    } else {
                        let mut queue = VecDeque::new();
                        queue.push_back(token.clone());
                        cache_1.push((server_name, queue));
                        if cache_1.len() > 20 {
                            cache_1.remove(0);
                        }
                    }
                    cache_2.insert(&server_name.to_string(), token);
                } else {
                    let expecting = cache_1
                        .iter()
                        .enumerate()
                        .find(|&(_, &(server_name_2, _))| server_name_2 == server_name)
                        .map(|(j, _)| j)
                        .map(|j| {
                            let (_, mut queue) = cache_1.remove(j);
                            let token = queue.pop_front().unwrap();
                            if !queue.is_empty() {
                                cache_1.push((server_name, queue));
                            }
                            token
                        });
                    assert_eq!(cache_2.take(&server_name.to_string()), expecting);
                }
            }
        }
    }

    #[test]
    fn zero_max_server_names() {
        let cache = TokenMemoryCache::new(0, 2);
        for i in 0..10 {
            cache.insert(&i.to_string(), Bytes::from(vec![i]));
            for j in 0..10 {
                assert!(cache.take(&j.to_string()).is_none());
            }
        }
    }

    #[test]
    fn zero_queue_length() {
        let cache = TokenMemoryCache::new(256, 0);
        for i in 0..10 {
            cache.insert(&i.to_string(), Bytes::from(vec![i]));
            for j in 0..10 {
                assert!(cache.take(&j.to_string()).is_none());
            }
        }
    }
}

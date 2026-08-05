//! A map over a `Vec` of `(key, value)` pairs, looked up by linear scan.
//!
//! The runtime collections here hold a handful of entries (interfaces, sessions, proxies), where
//! a scan over contiguous pairs beats a `HashMap`'s hashing and heap layout.

use std::borrow::Borrow;

/// A `Vec<(K, V)>` with a map API. `insert` replaces the value of an existing key, so keys stay
/// unique. Lookups borrow the key form ([`Borrow`]), so a `LinearMap<String, _>` is queried with
/// a `&str`.
#[derive(Debug)]
pub(crate) struct LinearMap<K, V>(Vec<(K, V)>);

impl<K: PartialEq, V> LinearMap<K, V> {
    pub(crate) fn new() -> Self {
        Self(Vec::new())
    }

    pub(crate) fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: PartialEq + ?Sized,
    {
        self.0
            .iter()
            .find(|(k, _)| k.borrow() == key)
            .map(|(_, v)| v)
    }

    fn get_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: PartialEq + ?Sized,
    {
        self.0
            .iter_mut()
            .find(|(k, _)| k.borrow() == key)
            .map(|(_, v)| v)
    }

    /// Returns the replaced value when `key` was already present.
    pub(crate) fn insert(&mut self, key: K, value: V) -> Option<V> {
        if let Some(slot) = self.get_mut(&key) {
            return Some(std::mem::replace(slot, value));
        }
        self.0.push((key, value));
        None
    }
}

impl<K: PartialEq, V> Default for LinearMap<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_finds_what_insert_put() {
        let mut map = LinearMap::new();
        assert_eq!(map.insert("a".to_owned(), 1), None);
        assert_eq!(map.insert("b".to_owned(), 2), None);
        assert_eq!(map.get("a"), Some(&1));
        assert_eq!(map.get("b"), Some(&2));
        assert_eq!(map.get("c"), None);
    }

    #[test]
    fn insert_replaces_an_existing_key_and_returns_the_old_value() {
        let mut map = LinearMap::new();
        map.insert(7u32, "old");
        assert_eq!(map.insert(7, "new"), Some("old"));
        assert_eq!(map.get(&7), Some(&"new"));
    }
}

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

    pub(crate) fn get_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
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

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.0.iter().map(|(k, v)| (k, v))
    }

    /// Remove `key`'s entry, returning its value. `swap_remove` underneath, so iteration order is
    /// not insertion order once anything was removed.
    pub(crate) fn remove<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: PartialEq + ?Sized,
    {
        let pos = self.0.iter().position(|(k, _)| k.borrow() == key)?;
        Some(self.0.swap_remove(pos).1)
    }

    pub(crate) fn retain(&mut self, mut keep: impl FnMut(&K, &mut V) -> bool) {
        self.0.retain_mut(|(k, v)| keep(k, v));
    }

    pub(crate) fn clear(&mut self) {
        self.0.clear();
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

    #[test]
    fn get_mut_edits_in_place() {
        let mut map = LinearMap::new();
        map.insert(1u32, false);
        *map.get_mut(&1).unwrap() |= true;
        assert_eq!(map.get(&1), Some(&true));
        assert_eq!(map.get_mut(&2), None);
    }

    #[test]
    fn iter_yields_every_pair() {
        let mut map = LinearMap::new();
        assert!(map.is_empty());
        map.insert(1u32, "one");
        map.insert(2, "two");
        assert!(!map.is_empty());
        let mut pairs: Vec<_> = map.iter().map(|(k, v)| (*k, *v)).collect();
        pairs.sort_unstable();
        assert_eq!(pairs, [(1, "one"), (2, "two")]);
    }

    #[test]
    fn remove_takes_the_entry_out() {
        let mut map = LinearMap::new();
        map.insert(1u32, "one");
        map.insert(2, "two");
        assert_eq!(map.remove(&1), Some("one"));
        assert_eq!(map.remove(&1), None);
        assert_eq!(map.get(&1), None);
        assert_eq!(map.get(&2), Some(&"two"));
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn retain_filters_by_key_and_value() {
        let mut map = LinearMap::new();
        for i in 0..4u32 {
            map.insert(i, i * 10);
        }
        map.retain(|k, v| *k % 2 == 0 && *v < 30);
        assert_eq!(map.len(), 2);
        assert_eq!(map.get(&0), Some(&0));
        assert_eq!(map.get(&1), None);
        assert_eq!(map.get(&2), Some(&20));
        assert_eq!(map.get(&3), None);
    }

    #[test]
    fn clear_empties_the_map() {
        let mut map = LinearMap::new();
        map.insert(1u32, ());
        map.clear();
        assert!(map.is_empty());
        assert_eq!(map.get(&1), None);
    }
}

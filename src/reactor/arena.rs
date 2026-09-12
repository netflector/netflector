//! A generational-index arena. [`remove`](Arena::remove) bumps the slot's generation,
//! so a key to the old occupant resolves to `None` instead of aliasing the next one.

/// A handle into an [`Arena`]; stale once its value is removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Key {
    index: u32,
    generation: u32,
}

impl Key {
    /// Pack into a `u64` (a kernel token); [`from_u64`](Key::from_u64) reverses it.
    #[must_use]
    pub(crate) fn to_u64(self) -> u64 {
        (u64::from(self.index) << 32) | u64::from(self.generation)
    }

    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub(crate) fn from_u64(packed: u64) -> Self {
        Self {
            index: (packed >> 32) as u32,
            generation: packed as u32,
        }
    }
}

struct Slot<T> {
    generation: u32,
    value: Option<T>,
}

pub(crate) struct Arena<T> {
    slots: Vec<Slot<T>>,
    free: Vec<u32>,
}

impl<T> Arena<T> {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            slots: Vec::new(),
            free: Vec::new(),
        }
    }

    /// # Panics
    /// If the `u32` index space is exhausted.
    pub(crate) fn insert(&mut self, value: T) -> Key {
        self.insert_from(|_| value)
    }

    /// Store the value `make` builds from the key it will get.
    ///
    /// # Panics
    /// As [`insert`](Self::insert).
    pub(crate) fn insert_from<F>(&mut self, make: F) -> Key
    where
        F: FnOnce(Key) -> T,
    {
        if let Some(index) = self.free.pop() {
            let generation = self.slots[index as usize].generation;
            let key = Key { index, generation };
            self.slots[index as usize].value = Some(make(key));
            key
        } else {
            let index = u32::try_from(self.slots.len()).expect("arena index space exhausted");
            let key = Key {
                index,
                generation: 0,
            };
            self.slots.push(Slot {
                generation: 0,
                value: Some(make(key)),
            });
            key
        }
    }

    #[must_use]
    pub(crate) fn get(&self, key: Key) -> Option<&T> {
        self.slot(key)?.value.as_ref()
    }

    pub(crate) fn get_mut(&mut self, key: Key) -> Option<&mut T> {
        self.slot_mut(key)?.value.as_mut()
    }

    pub(crate) fn remove(&mut self, key: Key) -> Option<T> {
        let slot = self.slot_mut(key)?;
        let value = slot.value.take()?;
        // wrapping: a collision needs 2^32 reuses of one slot
        slot.generation = slot.generation.wrapping_add(1);
        self.free.push(key.index);
        Some(value)
    }

    #[must_use]
    pub(crate) fn contains(&self, key: Key) -> bool {
        self.get(key).is_some()
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (Key, &T)> + '_ {
        self.slots.iter().enumerate().filter_map(|(index, slot)| {
            let value = slot.value.as_ref()?;
            let index = u32::try_from(index).expect("arena index space exhausted");
            Some((
                Key {
                    index,
                    generation: slot.generation,
                },
                value,
            ))
        })
    }

    fn slot(&self, key: Key) -> Option<&Slot<T>> {
        self.slots
            .get(key.index as usize)
            .filter(|slot| slot.generation == key.generation)
    }

    fn slot_mut(&mut self, key: Key) -> Option<&mut Slot<T>> {
        self.slots
            .get_mut(key.index as usize)
            .filter(|slot| slot.generation == key.generation)
    }
}

impl<T> Default for Arena<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// A slot value whose handler is taken out (`None`) for the duration of a call.
pub(crate) trait HandlerSlot {
    type Handler: ?Sized;

    // The slot itself is the interface: `slot_mut` mirrors it and `handler` derives from it.
    #[allow(clippy::ref_option)]
    fn slot(&self) -> &Option<Box<Self::Handler>>;

    fn slot_mut(&mut self) -> &mut Option<Box<Self::Handler>>;

    fn handler(&self) -> Option<&Self::Handler> {
        self.slot().as_deref()
    }
}

impl<T: HandlerSlot> Arena<T> {
    pub(crate) fn take_handler(&mut self, key: Key) -> Option<Box<T::Handler>> {
        self.get_mut(key)?.slot_mut().take()
    }

    pub(crate) fn restore_handler(&mut self, key: Key, handler: Box<T::Handler>) {
        if let Some(slot) = self.get_mut(key) {
            *slot.slot_mut() = Some(handler);
        }
    }

    pub(crate) fn handlers(&self) -> impl Iterator<Item = (Key, &T::Handler)> + '_ {
        self.iter()
            .filter_map(|(key, slot)| Some((key, slot.handler()?)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_then_get_returns_value() {
        let mut arena = Arena::new();
        let key = arena.insert("hello");
        assert_eq!(arena.get(key), Some(&"hello"));
        assert!(arena.contains(key));
    }

    #[test]
    fn get_mut_allows_mutation() {
        let mut arena = Arena::new();
        let key = arena.insert(1);
        *arena.get_mut(key).unwrap() += 41;
        assert_eq!(arena.get(key), Some(&42));
    }

    #[test]
    fn insert_from_passes_the_assigned_key() {
        let mut arena = Arena::new();
        let mut captured = None;
        let key = arena.insert_from(|k| {
            captured = Some(k);
            "v"
        });
        assert_eq!(
            captured,
            Some(key),
            "the closure saw the key it inserts under"
        );
        assert_eq!(arena.get(key), Some(&"v"));
    }

    #[test]
    fn insert_from_reflects_a_reused_slot_generation() {
        let mut arena = Arena::new();
        let first = arena.insert("first");
        arena.remove(first);
        let mut captured = None;
        let second = arena.insert_from(|k| {
            captured = Some(k);
            "second"
        });
        // The key `make` receives is the final one, with the reused slot's bumped generation.
        assert_eq!(captured, Some(second));
        assert_eq!(first.index, second.index);
        assert_ne!(first.generation, second.generation);
    }

    #[test]
    fn remove_returns_value_and_strands_the_key() {
        let mut arena = Arena::new();
        let key = arena.insert("v");
        assert_eq!(arena.remove(key), Some("v"));
        assert_eq!(arena.get(key), None);
        assert!(!arena.contains(key));
        // Removing an already-stale key is a no-op.
        assert_eq!(arena.remove(key), None);
    }

    #[test]
    fn reused_slot_gets_a_fresh_generation() {
        let mut arena = Arena::new();
        let first = arena.insert("first");
        arena.remove(first);
        let second = arena.insert("second");
        // The free list reuses the slot, so the index matches but the generation
        // differs: the old key stays stale, the new key is live.
        assert_eq!(first.index, second.index);
        assert_ne!(first.generation, second.generation);
        assert_eq!(arena.get(first), None);
        assert_eq!(arena.get(second), Some(&"second"));
    }

    #[test]
    fn wrong_generation_key_does_not_resolve() {
        let mut arena = Arena::new();
        let key = arena.insert("v");
        let forged = Key {
            index: key.index,
            generation: key.generation.wrapping_add(1),
        };
        assert_eq!(arena.get(forged), None);
    }

    #[test]
    fn out_of_range_key_does_not_resolve() {
        let arena: Arena<i32> = Arena::new();
        let bogus = Key {
            index: 999,
            generation: 0,
        };
        assert_eq!(arena.get(bogus), None);
    }

    #[test]
    fn distinct_keys_are_independent() {
        let mut arena = Arena::new();
        let a = arena.insert("a");
        let b = arena.insert("b");
        assert_ne!(a, b);
        arena.remove(a);
        // Removing one leaves the other untouched.
        assert_eq!(arena.get(a), None);
        assert_eq!(arena.get(b), Some(&"b"));
    }

    #[test]
    fn copied_key_addresses_the_same_slot() {
        let mut arena = Arena::new();
        let key = arena.insert("shared");
        // `Key: Copy`, so this duplicates the handle; `key` stays usable afterward
        // (a move would forbid the uses below).
        let copy = key;
        assert_eq!(key, copy);
        assert_eq!(arena.get(key), Some(&"shared"));
        assert_eq!(arena.get(copy), Some(&"shared"));
        // Both name the same slot: a mutation through one is seen through the other.
        *arena.get_mut(copy).unwrap() = "updated";
        assert_eq!(arena.get(key), Some(&"updated"));
    }

    #[test]
    fn iter_yields_live_entries_with_their_keys() {
        let mut arena = Arena::new();
        let a = arena.insert("a");
        let b = arena.insert("b");
        arena.remove(a);
        let c = arena.insert("c"); // reuses a's slot with a fresh generation

        let mut items: Vec<(Key, &str)> = arena.iter().map(|(k, &v)| (k, v)).collect();
        items.sort_by_key(|&(_, v)| v);
        // `a` is gone; `b` and the reused-slot `c` remain, each with its current key.
        assert_eq!(items, vec![(b, "b"), (c, "c")]);
    }

    #[test]
    fn key_u64_round_trips() {
        for key in [
            Key {
                index: 0,
                generation: 0,
            },
            Key {
                index: 1,
                generation: 2,
            },
            Key {
                index: u32::MAX,
                generation: 0,
            },
            Key {
                index: 0,
                generation: u32::MAX,
            },
            Key {
                index: u32::MAX,
                generation: u32::MAX,
            },
        ] {
            assert_eq!(Key::from_u64(key.to_u64()), key);
        }
    }

    #[test]
    fn remove_with_a_stale_key_spares_the_reused_slots_occupant() {
        let mut arena = Arena::new();
        let a = arena.insert("a");
        arena.remove(a);
        let b = arena.insert("b");
        assert_eq!(a.index, b.index);
        assert_eq!(arena.remove(a), None);
        assert_eq!(arena.get(b), Some(&"b"));
        assert!(arena.contains(b));
    }

    #[test]
    fn removing_a_stale_key_does_not_double_free() {
        let mut arena = Arena::new();
        let a = arena.insert("a");
        arena.remove(a);
        assert_eq!(arena.remove(a), None);
        let b = arena.insert("b");
        let c = arena.insert("c");
        assert_ne!(
            b.index, c.index,
            "a double-freed slot would be handed out twice"
        );
        assert_eq!(arena.get(b), Some(&"b"));
        assert_eq!(arena.get(c), Some(&"c"));
    }

    #[test]
    fn get_mut_misses_on_out_of_range_wrong_generation_and_removed_keys() {
        let mut arena = Arena::new();
        let key = arena.insert(1);

        let out_of_range = Key {
            index: 999,
            generation: 0,
        };
        assert!(arena.get_mut(out_of_range).is_none());

        let wrong_generation = Key {
            index: key.index,
            generation: key.generation.wrapping_add(1),
        };
        assert!(arena.get_mut(wrong_generation).is_none());

        arena.remove(key);
        assert!(arena.get_mut(key).is_none());
    }

    #[test]
    fn insert_reuses_freed_slots_before_growing() {
        let mut arena = Arena::new();
        let freed_lo = arena.insert("lo");
        let freed_hi = arena.insert("hi");
        arena.remove(freed_lo);
        arena.remove(freed_hi);
        let reused_a = arena.insert("a");
        let reused_b = arena.insert("b");
        assert!(reused_a.index == freed_lo.index || reused_a.index == freed_hi.index);
        assert!(reused_b.index == freed_lo.index || reused_b.index == freed_hi.index);
        assert_ne!(reused_a.index, reused_b.index);
        let grown = arena.insert("grown");
        assert_ne!(grown.index, freed_lo.index);
        assert_ne!(grown.index, freed_hi.index);
    }

    #[test]
    fn iter_on_an_empty_arena_yields_nothing() {
        let arena: Arena<i32> = Arena::new();
        assert_eq!(arena.iter().count(), 0);
    }
}

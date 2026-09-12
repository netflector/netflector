//! A non-empty, duplicate-free list with a per-element admission rule: the shape of every
//! configured list (ports, multicast groups, peers, MAC addresses). One comma-separated `FromStr`
//! and one array `Deserialize` serve them all.

use std::fmt;
use std::ops::Deref;
use std::str::FromStr;

use serde::{Deserialize, Deserializer};
use thiserror::Error;

/// What a list admits: the element noun for its error messages, and the per-element rule.
pub(crate) trait ListRule {
    type Item;

    /// The element noun, e.g. `port`.
    const NOUN: &'static str;

    /// Why `item` is refused, or `None` to admit it.
    fn refuse(_item: &Self::Item) -> Option<&'static str> {
        None
    }
}

/// Why a list was rejected. `noun` is the rule's element noun.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum ListError<T: fmt::Display> {
    #[error("{noun} list must not be empty")]
    Empty { noun: &'static str },
    #[error("duplicate {noun} {item}")]
    Duplicate { noun: &'static str, item: T },
    /// The rule refused an element, for the given reason.
    #[error("{item} {reason}")]
    Refused { item: T, reason: &'static str },
    /// A comma-separated token did not parse as an element.
    #[error("invalid {noun} \"{token}\"")]
    Invalid { noun: &'static str, token: String },
}

/// A non-empty, duplicate-free list under the rule `R`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UniqueList<R: ListRule>(Box<[R::Item]>);

impl<R: ListRule> Deref for UniqueList<R> {
    type Target = [R::Item];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<R: ListRule> TryFrom<Vec<R::Item>> for UniqueList<R>
where
    R::Item: PartialEq + Copy + fmt::Display,
{
    type Error = ListError<R::Item>;

    fn try_from(items: Vec<R::Item>) -> Result<Self, Self::Error> {
        if items.is_empty() {
            return Err(ListError::Empty { noun: R::NOUN });
        }
        for (i, item) in items.iter().enumerate() {
            if let Some(reason) = R::refuse(item) {
                return Err(ListError::Refused {
                    item: *item,
                    reason,
                });
            }
            if items[..i].contains(item) {
                return Err(ListError::Duplicate {
                    noun: R::NOUN,
                    item: *item,
                });
            }
        }
        Ok(Self(items.into_boxed_slice()))
    }
}

impl<R: ListRule> FromStr for UniqueList<R>
where
    R::Item: FromStr + PartialEq + Copy + fmt::Display,
{
    type Err = ListError<R::Item>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let items = s
            .split(',')
            .map(|token| {
                let token = token.trim();
                token.parse::<R::Item>().map_err(|_| ListError::Invalid {
                    noun: R::NOUN,
                    token: token.to_owned(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::try_from(items)
    }
}

impl<'de, R: ListRule> Deserialize<'de> for UniqueList<R>
where
    R::Item: Deserialize<'de> + PartialEq + Copy + fmt::Display,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Vec::<R::Item>::deserialize(deserializer)?
            .try_into()
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Even;

    impl ListRule for Even {
        type Item = u32;

        const NOUN: &'static str = "even";

        fn refuse(item: &u32) -> Option<&'static str> {
            (!item.is_multiple_of(2)).then_some("is odd")
        }
    }

    type Evens = UniqueList<Even>;

    #[test]
    fn parses_trimmed_comma_separated_items_in_order() {
        let list: Evens = " 2, 4 ,6".parse().unwrap();
        assert_eq!(&*list, &[2, 4, 6]);
    }

    #[test]
    fn refuses_before_it_checks_duplicates_and_names_the_element() {
        assert_eq!(
            "2,3,3".parse::<Evens>(),
            Err(ListError::Refused {
                item: 3,
                reason: "is odd"
            })
        );
        assert_eq!(
            "2,2".parse::<Evens>(),
            Err(ListError::Duplicate {
                noun: "even",
                item: 2
            })
        );
        assert_eq!(
            "2,x".parse::<Evens>(),
            Err(ListError::Invalid {
                noun: "even",
                token: "x".to_owned()
            })
        );
        // FromStr can't yield an empty list, so Empty is reachable only via TryFrom.
        assert_eq!(
            Evens::try_from(Vec::new()),
            Err(ListError::Empty { noun: "even" })
        );
    }

    #[test]
    fn deserializes_an_array_under_the_same_rule() {
        #[derive(Debug, Deserialize)]
        struct Doc {
            evens: Evens,
        }
        let doc: Doc = toml::from_str("evens = [2, 4]").unwrap();
        assert_eq!(&*doc.evens, &[2, 4]);
        let e = toml::from_str::<Doc>("evens = [2, 3]").unwrap_err();
        assert!(e.to_string().contains("3 is odd"));
    }
}

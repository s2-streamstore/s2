pub trait DeepSize {
    /// - size_of(primitive)
    /// - length for chunks of data like strings and bytes (so not including the container overhead)
    /// - deep size of all struct fields
    /// - deep size of actual variant for enums
    fn deep_size(&self) -> usize;
}

impl<X: DeepSize, Y: DeepSize> DeepSize for (X, Y) {
    fn deep_size(&self) -> usize {
        self.0.deep_size() + self.1.deep_size()
    }
}

impl<T: DeepSize> DeepSize for &[T] {
    fn deep_size(&self) -> usize {
        self.iter().map(DeepSize::deep_size).sum::<usize>()
    }
}

impl<T: DeepSize> DeepSize for Vec<T> {
    fn deep_size(&self) -> usize {
        self.iter().map(DeepSize::deep_size).sum::<usize>()
    }
}

impl<T: DeepSize> DeepSize for Option<T> {
    fn deep_size(&self) -> usize {
        match self {
            Some(v) => v.deep_size(),
            None => 1,
        }
    }
}

impl DeepSize for String {
    fn deep_size(&self) -> usize {
        self.len()
    }
}

impl DeepSize for bytes::Bytes {
    fn deep_size(&self) -> usize {
        self.len()
    }
}

impl<T: DeepSize> DeepSize for std::ops::Bound<T> {
    fn deep_size(&self) -> usize {
        match self {
            std::ops::Bound::Included(x) => x.deep_size(),
            std::ops::Bound::Excluded(x) => x.deep_size(),
            std::ops::Bound::Unbounded => 1,
        }
    }
}

macro_rules! impl_deep_size_prim {
    ($($t:ty),+) => {
        $(
            impl DeepSize for $t {
                fn deep_size(&self) -> usize {
                    size_of_val(self)
                }
            }
        )+
    };
}

impl_deep_size_prim!(bool, u64, usize, std::num::NonZeroU64);

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn string_strategy(max_chars: usize) -> impl Strategy<Value = String> {
        prop::collection::vec(any::<char>(), 0..=max_chars)
            .prop_map(|chars| chars.into_iter().collect())
    }

    #[test]
    fn primitives() {
        assert_eq!(42u64.deep_size(), size_of::<u64>());
        assert_eq!(true.deep_size(), size_of::<bool>());
        assert_eq!(0usize.deep_size(), size_of::<usize>());
        let nz = std::num::NonZeroU64::new(1).unwrap();
        assert_eq!(nz.deep_size(), size_of::<std::num::NonZeroU64>());
    }

    #[test]
    fn option_some() {
        let o: Option<u64> = Some(42);
        assert_eq!(o.deep_size(), size_of::<u64>());
    }

    #[test]
    fn option_none() {
        let o: Option<u64> = None;
        assert_eq!(o.deep_size(), 1);
    }

    #[test]
    fn tuple_deep_size() {
        let t = (42u64, String::from("hi"));
        assert_eq!(t.deep_size(), size_of::<u64>() + 2);
    }

    #[test]
    fn bound_included() {
        let b = std::ops::Bound::Included(100u64);
        assert_eq!(b.deep_size(), size_of::<u64>());
    }

    #[test]
    fn bound_excluded() {
        let b = std::ops::Bound::Excluded(100u64);
        assert_eq!(b.deep_size(), size_of::<u64>());
    }

    #[test]
    fn bound_unbounded() {
        let b: std::ops::Bound<u64> = std::ops::Bound::Unbounded;
        assert_eq!(b.deep_size(), 1);
    }

    proptest! {
        #[test]
        fn string_deep_size_matches_byte_len(s in string_strategy(256)) {
            prop_assert_eq!(s.deep_size(), s.len());
        }

        #[test]
        fn bytes_deep_size_matches_len(bytes in prop::collection::vec(any::<u8>(), 0..=1024)) {
            let bytes = bytes::Bytes::from(bytes);
            prop_assert_eq!(bytes.deep_size(), bytes.len());
        }

        #[test]
        fn vec_and_slice_deep_size_sum_elements(values in prop::collection::vec(any::<u64>(), 0..=256)) {
            let expected = values.len() * size_of::<u64>();
            prop_assert_eq!(values.deep_size(), expected);
            prop_assert_eq!(values.as_slice().deep_size(), expected);
        }

        #[test]
        fn nested_vec_of_strings_sums_string_lengths(
            values in prop::collection::vec(string_strategy(64), 0..=32),
        ) {
            let expected = values.iter().map(String::len).sum::<usize>();
            prop_assert_eq!(values.deep_size(), expected);
        }
    }
}

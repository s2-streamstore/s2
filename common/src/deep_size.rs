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
    use super::*;

    #[test]
    fn primitives() {
        assert_eq!(42u64.deep_size(), size_of::<u64>());
        assert_eq!(true.deep_size(), size_of::<bool>());
        assert_eq!(0usize.deep_size(), size_of::<usize>());
        let nz = std::num::NonZeroU64::new(1).unwrap();
        assert_eq!(nz.deep_size(), size_of::<std::num::NonZeroU64>());
    }

    #[test]
    fn string_deep_size() {
        let s = String::from("hello");
        assert_eq!(s.deep_size(), 5);
        assert_eq!(String::new().deep_size(), 0);
    }

    #[test]
    fn bytes_deep_size() {
        let b = bytes::Bytes::from("world");
        assert_eq!(b.deep_size(), 5);
        assert_eq!(bytes::Bytes::new().deep_size(), 0);
    }

    #[test]
    fn vec_deep_size() {
        let v: Vec<u64> = vec![1, 2, 3];
        assert_eq!(v.deep_size(), 3 * size_of::<u64>());
    }

    #[test]
    fn slice_deep_size() {
        let v: Vec<u64> = vec![10, 20];
        let s: &[u64] = &v;
        assert_eq!(s.deep_size(), 2 * size_of::<u64>());
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

    #[test]
    fn nested_vec_of_strings() {
        let v = vec![String::from("ab"), String::from("cde")];
        assert_eq!(v.deep_size(), 2 + 3);
    }
}

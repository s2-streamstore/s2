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

pub trait MeteredSize {
    /// Return the metered size of a record or batch of records.
    fn metered_size(&self) -> usize;
}

impl<T> MeteredSize for &T
where
    T: MeteredSize,
{
    fn metered_size(&self) -> usize {
        (**self).metered_size()
    }
}

impl<T: MeteredSize> MeteredSize for &[T] {
    fn metered_size(&self) -> usize {
        self.iter().fold(0, |acc, item| acc + item.metered_size())
    }
}

impl<T: MeteredSize> MeteredSize for Vec<T> {
    fn metered_size(&self) -> usize {
        self.as_slice().metered_size()
    }
}

pub struct Metered<T> {
    pub(super) size: usize,
    pub(super) inner: T,
}

impl<T> Metered<T> {
    pub fn into_inner(self) -> T {
        self.inner
    }

    pub const fn as_ref(&self) -> Metered<&T> {
        Metered {
            size: self.size,
            inner: &self.inner,
        }
    }
}

impl<T> std::fmt::Debug for Metered<T>
where
    T: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Metered")
            .field("size", &self.size)
            .field("inner", &self.inner)
            .finish()
    }
}

impl<T> PartialEq for Metered<T>
where
    T: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.size == other.size && self.inner == other.inner
    }
}

impl<T> Eq for Metered<T> where T: Eq {}

impl<T> std::ops::Deref for Metered<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T> From<T> for Metered<T>
where
    T: MeteredSize,
{
    fn from(inner: T) -> Self {
        Self {
            size: inner.metered_size(),
            inner,
        }
    }
}

impl<T> Default for Metered<T>
where
    T: Default + MeteredSize,
{
    fn default() -> Self {
        T::default().into()
    }
}

impl<T> Clone for Metered<T>
where
    T: Clone,
{
    fn clone(&self) -> Self {
        Self {
            size: self.size,
            inner: self.inner.clone(),
        }
    }
}

impl<T> MeteredSize for Metered<T> {
    fn metered_size(&self) -> usize {
        self.size
    }
}

impl<T> Metered<Vec<T>>
where
    T: MeteredSize,
{
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            size: 0,
            inner: Vec::with_capacity(capacity),
        }
    }

    pub fn reserve(&mut self, additional: usize) {
        self.inner.reserve(additional);
    }

    pub fn push(&mut self, item: Metered<T>) {
        self.inner.push(item.inner);
        self.size += item.size;
    }

    pub fn append(&mut self, other: Self) {
        self.inner.extend(other.inner);
        self.size += other.size;
    }
}

impl<T> FromIterator<Metered<T>> for Metered<Vec<T>>
where
    T: MeteredSize,
{
    fn from_iter<I: IntoIterator<Item = Metered<T>>>(iterable: I) -> Self {
        let it = iterable.into_iter();
        let (cap_lower, cap_upper) = it.size_hint();
        let mut buf = Self::with_capacity(cap_upper.unwrap_or(cap_lower));
        for item in it {
            buf.push(item);
        }
        buf
    }
}

impl<T> IntoIterator for Metered<Vec<T>> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

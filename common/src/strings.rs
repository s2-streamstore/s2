pub trait StrProps: std::fmt::Debug + Clone {
    const IS_PREFIX: bool;
    const FIELD_NAME: &'static str;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NameProps;

impl StrProps for NameProps {
    const IS_PREFIX: bool = false;
    const FIELD_NAME: &'static str = "name";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IdProps;

impl StrProps for IdProps {
    const IS_PREFIX: bool = false;
    const FIELD_NAME: &'static str = "id";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PrefixProps;

impl StrProps for PrefixProps {
    const IS_PREFIX: bool = true;
    const FIELD_NAME: &'static str = "prefix";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StartAfterProps;

impl StrProps for StartAfterProps {
    const IS_PREFIX: bool = true;
    const FIELD_NAME: &'static str = "start-after";
}

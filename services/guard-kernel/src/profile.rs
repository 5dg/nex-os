//! Synthetic execution profiles; production is intentionally unavailable.
use std::error::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    Development,
    Qualification,
}
impl Profile {
    pub fn from_env() -> Result<Self, Box<dyn Error>> {
        Self::parse(&std::env::var("NEX_PROFILE").unwrap_or_else(|_| "development".into()))
    }
    pub fn parse(value: &str) -> Result<Self, Box<dyn Error>> {
        match value {
            "development" => Ok(Self::Development),
            "synthetic-qualification" => Ok(Self::Qualification),
            _ => Err("unsupported execution profile; production and CUI are unavailable".into()),
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Development => "development",
            Self::Qualification => "synthetic-qualification",
        }
    }
    pub fn manifest_version(self) -> i32 {
        match self {
            Self::Development => 2,
            Self::Qualification => 3,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn profiles_cannot_enable_production_or_silent_fallback() {
        assert_eq!(Profile::parse("development").unwrap(), Profile::Development);
        assert_eq!(
            Profile::parse("synthetic-qualification").unwrap(),
            Profile::Qualification
        );
        for value in [
            "",
            "production",
            "qualification",
            "synthetic-qualification ",
        ] {
            assert!(Profile::parse(value).is_err(), "{value}");
        }
    }
}

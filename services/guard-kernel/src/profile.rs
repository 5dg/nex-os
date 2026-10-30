//! Synthetic execution profiles; production is intentionally unavailable.
use std::error::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    Development,
    Qualification,
    // Never selected from environment. Available only to an explicitly
    // configured, non-production embedding with independent authorities.
    ModelCandidate,
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
            Self::ModelCandidate => "production-model-candidate",
        }
    }
    pub fn manifest_version(self) -> i32 {
        match self {
            Self::Development => 2,
            Self::Qualification => 3,
            Self::ModelCandidate => 3,
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
            "production-model-candidate",
        ] {
            assert!(Profile::parse(value).is_err(), "{value}");
        }
    }
}

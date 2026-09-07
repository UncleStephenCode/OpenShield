use thiserror::Error;

use crate::state::MAX_AUTOMATIC_LEARNED_RULES;

/// Immutable count budgets for automatic application learning.
///
/// These budgets never enlarge the global automatic-rule reserve or the
/// persisted-state byte limit. Disabled and historical learned rules continue
/// to consume their budgets; changing limits does not remove existing rules.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LearningLimits {
    per_uid: usize,
    per_application: usize,
}

impl LearningLimits {
    /// Validates administrator-selected count budgets.
    ///
    /// # Errors
    ///
    /// Returns [`LearningLimitsError`] unless
    /// `1 <= per_application <= per_uid <= MAX_AUTOMATIC_LEARNED_RULES`.
    pub const fn new(per_uid: usize, per_application: usize) -> Result<Self, LearningLimitsError> {
        if per_application == 0
            || per_application > per_uid
            || per_uid > MAX_AUTOMATIC_LEARNED_RULES
        {
            return Err(LearningLimitsError);
        }
        Ok(Self {
            per_uid,
            per_application,
        })
    }

    #[must_use]
    pub const fn per_uid(self) -> usize {
        self.per_uid
    }

    #[must_use]
    pub const fn per_application(self) -> usize {
        self.per_application
    }
}

impl Default for LearningLimits {
    fn default() -> Self {
        Self {
            per_uid: 4_096,
            per_application: 1_024,
        }
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("learning limits must satisfy 1 <= per_application <= per_uid <= 7500")]
pub struct LearningLimitsError;

/// Privacy-preserving summary: no UIDs, paths, or executable identities.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LearningQuotaSummary {
    pub automatic_rules: usize,
    pub saturated_uids: usize,
    pub saturated_applications: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_are_bounded_and_defaults_leave_manual_capacity() {
        let defaults = LearningLimits::default();
        assert_eq!(defaults.per_uid(), 4_096);
        assert_eq!(defaults.per_application(), 1_024);
        assert!(LearningLimits::new(7_500, 7_500).is_ok());
        assert!(LearningLimits::new(1, 1).is_ok());
        for (uid, application) in [(0, 0), (1, 0), (0, 1), (2, 3), (7_501, 1), (usize::MAX, 1)] {
            assert!(LearningLimits::new(uid, application).is_err());
        }
    }
}

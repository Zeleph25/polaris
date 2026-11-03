//! System parameters and the constants the paper derives from them.

use serde::{Deserialize, Serialize};

use crate::NodeId;

/// `n` processes, of which the adversary corrupts at most `t`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Params {
    pub n: usize,
    pub t: usize,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ParamsError {
    #[error("n must be at least 2, got {0}")]
    TooFewProcesses(usize),
    #[error("n = {0} does not fit a NodeId")]
    TooManyProcesses(usize),
    #[error("t must be smaller than n (n = {n}, t = {t})")]
    CorruptionBoundTooLarge { n: usize, t: usize },
}

impl Params {
    pub fn new(n: usize, t: usize) -> Result<Self, ParamsError> {
        if n < 2 {
            return Err(ParamsError::TooFewProcesses(n));
        }
        if n > usize::from(NodeId::MAX) + 1 {
            return Err(ParamsError::TooManyProcesses(n));
        }
        if t >= n {
            return Err(ParamsError::CorruptionBoundTooLarge { n, t });
        }
        Ok(Self { n, t })
    }

    /// The paper's parameterization: t = floor((1 - epsilon) * n) for a
    /// guaranteed honest fraction epsilon in (0, 1].
    pub fn with_honest_fraction(n: usize, epsilon: f64) -> Result<Self, ParamsError> {
        // The small slack keeps e.g. (1 - 0.1) * 20 from landing just under 18.
        #[allow(
            clippy::cast_precision_loss,
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss
        )]
        let t = ((1.0 - epsilon) * n as f64 + 1e-9).floor() as usize;
        Self::new(n, t)
    }

    /// n - t: honest processes in the worst case, and the threshold of the
    /// pruning rule (|N[a] inter N[b]| >= n - t).
    pub fn min_honest(&self) -> usize {
        self.n - self.t
    }

    /// d = ceil(2n / (n - t)): every component of a pruned accusation graph
    /// has diameter at most d (Claim 2).
    pub fn diameter_bound(&self) -> u32 {
        u32::try_from((2 * self.n).div_ceil(self.n - self.t)).expect("n fits a NodeId")
    }

    /// R = d + 1: the number of rounds of one LearnOrExpose instance
    /// (Algorithm 2, line 6).
    pub fn loe_rounds(&self) -> u32 {
        self.diameter_bound() + 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loe_rounds_match_the_paper() {
        // epsilon = 1/2: d = 4, R = 5; epsilon = 1/4: d = 8, R = 9; epsilon = 1/10: d = 20, R = 21
        assert_eq!(Params::new(16, 8).unwrap().loe_rounds(), 5);
        assert_eq!(Params::new(16, 12).unwrap().loe_rounds(), 9);
        assert_eq!(Params::new(20, 18).unwrap().loe_rounds(), 21);
    }

    #[test]
    fn honest_fraction_gives_the_floor() {
        assert_eq!(Params::with_honest_fraction(16, 0.5).unwrap().t, 8);
        assert_eq!(Params::with_honest_fraction(16, 0.25).unwrap().t, 12);
        assert_eq!(Params::with_honest_fraction(20, 0.1).unwrap().t, 18);
        assert_eq!(Params::with_honest_fraction(7, 1.0 / 3.0).unwrap().t, 4);
    }

    #[test]
    fn rejects_bad_parameters() {
        assert_eq!(Params::new(1, 0), Err(ParamsError::TooFewProcesses(1)));
        assert_eq!(
            Params::new(4, 4),
            Err(ParamsError::CorruptionBoundTooLarge { n: 4, t: 4 })
        );
        assert!(Params::new(70_000, 1).is_err());
    }
}

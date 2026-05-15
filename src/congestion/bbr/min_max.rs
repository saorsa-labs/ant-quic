// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

/*
 * Based on Google code released under BSD license here:
 * https://groups.google.com/forum/#!topic/bbr-dev/3RTgkzi5ZD8
 */

/*
 * Kathleen Nichols' algorithm for tracking the minimum (or maximum)
 * value of a data stream over some fixed time interval.  (E.g.,
 * the minimum RTT over the past five minutes.) It uses constant
 * space and constant time per update yet almost always delivers
 * the same minimum as an implementation that has to keep all the
 * data in the window.
 *
 * The algorithm keeps track of the best, 2nd best & 3rd best min
 * values, maintaining an invariant that the measurement time of
 * the n'th best >= n-1'th best. It also makes sure that the three
 * values are widely separated in the time window since that bounds
 * the worse case error when that data is monotonically increasing
 * over the window.
 *
 * Upon getting a new min, we can forget everything earlier because
 * it has no value - the new min is <= everything else in the window
 * by definition and it samples the most recent. So we restart fresh on
 * every new min and overwrites 2nd & 3rd choices. The same property
 * holds for 2nd & 3rd best.
 */

use std::fmt::Debug;

#[derive(Copy, Clone, Debug)]
pub(super) struct MinMax {
    /// round count, not a timestamp
    window: u64,
    samples: [MinMaxSample; 3],
}

impl MinMax {
    pub(super) fn get(&self) -> u64 {
        self.samples[0].value
    }

    fn fill(&mut self, sample: MinMaxSample) {
        self.samples.fill(sample);
    }

    // Removed unused reset()

    /// update_min is also defined in the original source, but removed here since it is not used.
    pub(super) fn update_max(&mut self, current_round: u64, measurement: u64) {
        let sample = MinMaxSample {
            time: current_round,
            value: measurement,
        };

        if self.samples[0].value == 0  /* uninitialised */
            || /* found new max? */ sample.value >= self.samples[0].value
            || /* nothing left in window? */ sample.time - self.samples[2].time > self.window
        {
            self.fill(sample); /* forget earlier samples */
            return;
        }

        if sample.value >= self.samples[1].value {
            self.samples[2] = sample;
            self.samples[1] = sample;
        } else if sample.value >= self.samples[2].value {
            self.samples[2] = sample;
        }

        self.subwin_update(sample);
    }

    /* As time advances, update the 1st, 2nd, and 3rd choices. */
    fn subwin_update(&mut self, sample: MinMaxSample) {
        let dt = sample.time - self.samples[0].time;
        if dt > self.window {
            /*
             * Passed entire window without a new sample so make 2nd
             * choice the new sample & 3rd choice the new 2nd choice.
             * we may have to iterate this since our 2nd choice
             * may also be outside the window (we checked on entry
             * that the third choice was in the window).
             */
            self.samples[0] = self.samples[1];
            self.samples[1] = self.samples[2];
            self.samples[2] = sample;
            if sample.time - self.samples[0].time > self.window {
                self.samples[0] = self.samples[1];
                self.samples[1] = self.samples[2];
                self.samples[2] = sample;
            }
        } else if self.samples[1].time == self.samples[0].time && dt > self.window / 4 {
            /*
             * We've passed a quarter of the window without a new sample
             * so take a 2nd choice from the 2nd quarter of the window.
             */
            self.samples[2] = sample;
            self.samples[1] = sample;
        } else if self.samples[2].time == self.samples[1].time && dt > self.window / 2 {
            /*
             * We've passed half the window without finding a new sample
             * so take a 3rd choice from the last half of the window
             */
            self.samples[2] = sample;
        }
    }
}

impl Default for MinMax {
    fn default() -> Self {
        Self {
            window: 10,
            samples: [Default::default(); 3],
        }
    }
}

#[derive(Debug, Copy, Clone, Default)]
struct MinMaxSample {
    /// round number, not a timestamp
    time: u64,
    value: u64,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn default_starts_uninitialized() {
        let min_max = MinMax::default();
        assert_eq!(min_max.window, 10);
        assert_eq!(min_max.get(), 0);
        assert!(min_max.samples.iter().all(|sample| sample.time == 0));
        assert!(min_max.samples.iter().all(|sample| sample.value == 0));
    }

    #[test]
    fn first_sample_initializes_all_slots() {
        let mut min_max = MinMax::default();
        min_max.update_max(1, 100);

        assert_eq!(min_max.get(), 100);
        assert!(min_max.samples.iter().all(|sample| sample.time == 1));
        assert!(min_max.samples.iter().all(|sample| sample.value == 100));
    }

    #[test]
    fn higher_sample_replaces_all_slots() {
        let mut min_max = MinMax::default();
        min_max.update_max(1, 100);
        min_max.update_max(2, 120);

        assert_eq!(min_max.get(), 120);
        assert!(min_max.samples.iter().all(|sample| sample.time == 2));
        assert!(min_max.samples.iter().all(|sample| sample.value == 120));
    }

    #[test]
    fn lower_samples_do_not_replace_current_max_inside_window() {
        let mut min_max = MinMax::default();
        min_max.update_max(1, 100);
        min_max.update_max(2, 80);
        min_max.update_max(3, 90);

        assert_eq!(min_max.get(), 100);
        assert!(min_max.samples.iter().all(|sample| sample.time == 1));
        assert!(min_max.samples.iter().all(|sample| sample.value == 100));
    }

    #[test]
    fn quarter_and_half_window_samples_seed_backups() {
        let mut min_max = MinMax::default();
        min_max.update_max(0, 100);
        min_max.update_max(3, 80);
        min_max.update_max(6, 70);

        assert_eq!(min_max.get(), 100);
        assert_eq!(min_max.samples[1].value, 80);
        assert_eq!(min_max.samples[1].time, 3);
        assert_eq!(min_max.samples[2].value, 70);
        assert_eq!(min_max.samples[2].time, 6);
    }

    #[test]
    fn stale_best_promotes_backup_samples() {
        let mut min_max = MinMax::default();
        min_max.update_max(0, 100);
        min_max.update_max(3, 80);
        min_max.update_max(6, 70);
        min_max.update_max(11, 60);

        assert_eq!(min_max.get(), 80);
        assert_eq!(min_max.samples[0].time, 3);
        assert_eq!(min_max.samples[1].time, 6);
        assert_eq!(min_max.samples[2].time, 11);
    }

    #[test]
    fn expired_third_slot_resets_window() {
        let mut min_max = MinMax::default();
        min_max.update_max(1, 100);
        min_max.update_max(4, 80);
        min_max.update_max(7, 70);
        min_max.update_max(18, 60);

        assert_eq!(min_max.get(), 60);
        assert!(min_max.samples.iter().all(|sample| sample.time == 18));
        assert!(min_max.samples.iter().all(|sample| sample.value == 60));
    }

    #[test]
    fn equal_sample_counts_as_new_max() {
        let mut min_max = MinMax::default();
        min_max.update_max(1, 100);
        min_max.update_max(5, 80);
        min_max.update_max(6, 100);

        assert_eq!(min_max.get(), 100);
        assert!(min_max.samples.iter().all(|sample| sample.time == 6));
        assert!(min_max.samples.iter().all(|sample| sample.value == 100));
    }

    #[test]
    fn original_bbr_sequence_tracks_expected_max() {
        let round = 25;
        let mut min_max = MinMax::default();
        min_max.update_max(round + 1, 100);
        assert_eq!(100, min_max.get());
        min_max.update_max(round + 3, 120);
        assert_eq!(120, min_max.get());
        min_max.update_max(round + 5, 160);
        assert_eq!(160, min_max.get());
        min_max.update_max(round + 7, 100);
        assert_eq!(160, min_max.get());
        min_max.update_max(round + 10, 100);
        assert_eq!(160, min_max.get());
        min_max.update_max(round + 14, 100);
        assert_eq!(160, min_max.get());
        min_max.update_max(round + 16, 100);
        assert_eq!(100, min_max.get());
        min_max.update_max(round + 18, 130);
        assert_eq!(130, min_max.get());
    }
}

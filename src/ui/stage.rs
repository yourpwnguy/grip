//! The live stage — an animated build checklist.
//!
//! While `grip` works, a painter thread repaints a checklist on stderr: one
//! line per pipeline step, each showing its state (done / active / pending),
//! its label, and — once finished — the concrete result it produced (an IP, a
//! byte count, a fingerprint). The active step carries the pulsing [`mascot`]
//! and a live detail string. The block is redrawn in place, so the terminal
//! never scrolls while running.
//!
//! # Why a checklist, not a spinner
//! A spinner says "something is happening"; a checklist says *what* happened
//! and *what it found*. Each completed line is a fact you can read at a
//! glance after the run — `resolve → 93.184.216.34`, `recv → 1119 B` — which
//! is the point of a diagnostic tool.
//!
//! # Threading model
//! One painter thread is the sole writer to stderr for the stage's lifetime.
//! Callers mutate shared state (labels, results, active detail); the painter
//! samples it at a fixed rate. `--verbose` lines are queued and flushed above
//! the block so the two never interleave.
//!
//! # Invariants
//! - [`Stage::finish`] (also run from `Drop`) always joins the painter and
//!   restores the cursor, even on a `?` early return.
//! - Inert when not animating (JSON, `--quiet`, `--no-progress`, non-TTY, or
//!   no color): no thread, no escapes, and `log` degrades to plain stderr.
//! - The drawn block height equals the step count, so the in-place redraw
//!   erases exactly what it wrote.

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::ui::mascot;
use crate::ui::theme::{Palette, glyph, pal};

/// Repaint interval. ~20 fps: smooth pulse, negligible CPU, kind to slow ptys.
const FRAME: Duration = Duration::from_millis(50);

/// State of one checklist step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Pending,
    Active,
    Done,
    Failed,
}

/// A single pipeline step.
#[derive(Debug, Clone)]
struct Step {
    label: &'static str,
    phase: Phase,
    /// Concrete result shown after completion (e.g. an IP or byte count).
    result: String,
}

/// Shared, painter-sampled state.
#[derive(Debug)]
struct State {
    steps: Vec<Step>,
    /// Live detail for the currently active step.
    detail: String,
    /// Lines to print above the block, then drop.
    pending: Vec<String>,
    stopping: bool,
    tick: usize,
    drawn: usize,
}

/// A live animated stage.
pub struct Stage {
    state: Arc<Mutex<State>>,
    stop: Arc<AtomicBool>,
    painter: Option<JoinHandle<()>>,
    active: bool,
    start: Instant,
}

impl Stage {
    /// Create a stage over `steps`.
    ///
    /// `active` should be false for JSON, `--quiet`, `--no-progress`, or a
    /// non-TTY stderr; the stage is then inert and free.
    #[must_use]
    pub fn new(steps: &[&'static str], palette: Palette, active: bool) -> Self {
        let state = Arc::new(Mutex::new(State {
            steps: steps
                .iter()
                .map(|s| Step {
                    label: s,
                    phase: Phase::Pending,
                    result: String::new(),
                })
                .collect(),
            detail: String::new(),
            pending: Vec::new(),
            stopping: false,
            tick: 0,
            drawn: 0,
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let animate = active && palette.is_color();

        let painter = animate.then(|| {
            let state = Arc::clone(&state);
            let stop = Arc::clone(&stop);
            thread::spawn(move || paint_loop(&state, &stop, palette))
        });

        Self {
            state,
            stop,
            painter,
            active,
            start: Instant::now(),
        }
    }

    /// Mark step `index` active and set its live detail. The previous active
    /// step, if any, is left `Done` by [`Self::complete`]; call `begin` when a
    /// step *starts*.
    pub fn begin(&self, index: usize, detail: impl Into<String>) {
        if !self.active {
            return;
        }
        if let Ok(mut s) = self.state.lock() {
            if let Some(step) = s.steps.get_mut(index) {
                step.phase = Phase::Active;
            }
            s.detail = detail.into();
        }
    }

    /// Mark step `index` done, recording the concrete `result` it produced.
    pub fn complete(&self, index: usize, result: impl Into<String>) {
        if !self.active {
            return;
        }
        if let Ok(mut s) = self.state.lock()
            && let Some(step) = s.steps.get_mut(index)
        {
            step.phase = Phase::Done;
            step.result = result.into();
        }
    }

    /// Mark step `index` failed with a reason.
    pub fn fail(&self, index: usize, reason: impl Into<String>) {
        if !self.active {
            return;
        }
        if let Ok(mut s) = self.state.lock()
            && let Some(step) = s.steps.get_mut(index)
        {
            step.phase = Phase::Failed;
            step.result = reason.into();
        }
    }

    /// Update the active step's live detail without changing its phase.
    pub fn detail(&self, detail: impl Into<String>) {
        if !self.active {
            return;
        }
        if let Ok(mut s) = self.state.lock() {
            s.detail = detail.into();
        }
    }

    /// Emit a line that scrolls away above the block. Straight to stderr when
    /// inert, so `--verbose` still works in pipes and CI.
    pub fn log(&self, line: impl Into<String>) {
        let line = line.into();
        if self.painter.is_none() {
            eprintln!("{line}");
            return;
        }
        if let Ok(mut s) = self.state.lock() {
            s.pending.push(line);
        }
    }

    /// Elapsed wall-clock time since creation.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    /// Stop the painter and erase the block. Idempotent.
    pub fn finish(&mut self) {
        if let Ok(mut s) = self.state.lock() {
            s.stopping = true;
        }
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.painter.take() {
            let _ = h.join();
        }
    }
}

impl Drop for Stage {
    fn drop(&mut self) {
        self.finish();
    }
}

/// Painter thread body — the only writer to stderr while running.
fn paint_loop(state: &Arc<Mutex<State>>, stop: &Arc<AtomicBool>, p: Palette) {
    let mut err = std::io::stderr();
    let _ = write!(err, "\x1b[?25l"); // hide cursor
    let _ = err.flush();

    loop {
        let stopping = stop.load(Ordering::Relaxed);

        // Snapshot + render under the lock is cheap (a few short strings); we
        // hold it only long enough to build the frame, never across I/O.
        let (frame, logs, prev, done) = {
            let Ok(mut s) = state.lock() else { break };
            let logs = std::mem::take(&mut s.pending);
            let tick = s.tick;
            s.tick = tick.wrapping_add(1);
            let prev = s.drawn;
            let frame = render(&s, p, tick);
            s.drawn = frame.len();
            (frame, logs, prev, stopping)
        };

        // Move to the block's top and clear downward so both logs and the new
        // frame land in a clean region regardless of the previous height.
        if prev > 0 {
            let _ = write!(err, "\x1b[{prev}A");
            let _ = write!(err, "\x1b[0J");
        }
        for l in logs {
            let _ = writeln!(err, "{l}");
        }
        for l in &frame {
            let _ = writeln!(err, "{l}");
        }
        let _ = err.flush();

        if done {
            // Leave the completed checklist on screen; just restore the cursor.
            let _ = write!(err, "\x1b[?25h");
            let _ = err.flush();
            break;
        }
        thread::sleep(FRAME);
    }
}

/// Render the checklist to lines.
fn render(s: &State, p: Palette, tick: usize) -> Vec<String> {
    s.steps
        .iter()
        .map(|step| line(step, &s.detail, p, tick))
        .collect()
}

/// One checklist line: `<state>  <label>   <result/detail>`.
fn line(step: &Step, detail: &str, p: Palette, tick: usize) -> String {
    let (mark, label_color) = match step.phase {
        Phase::Done => (
            p.bold(mascot::MARK, pal::LIME),
            p.paint(step.label, pal::CHROME),
        ),
        Phase::Active => (
            p.bold(mascot::frame(tick), mascot::accent(tick)),
            p.bold(step.label, pal::AMBER),
        ),
        Phase::Pending => (p.dim(glyph::DOT, pal::STEEL), p.dim(step.label, pal::STEEL)),
        Phase::Failed => (
            p.bold(glyph::BAD, pal::RUST),
            p.paint(step.label, pal::RUST),
        ),
    };

    // Label column is fixed so results line up into a readable second column.
    let pad = 11usize.saturating_sub(step.label.chars().count());
    let trailer = match step.phase {
        Phase::Active if !detail.is_empty() => p.paint(detail, pal::MIST),
        Phase::Done | Phase::Failed if !step.result.is_empty() => {
            let c = if step.phase == Phase::Failed {
                pal::RUST
            } else {
                pal::MIST
            };
            p.dim(&step.result, c)
        }
        _ => String::new(),
    };

    format!("  {mark}  {label_color}{}{trailer}", " ".repeat(pad + 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> State {
        State {
            steps: vec![
                Step {
                    label: "resolve",
                    phase: Phase::Done,
                    result: "93.184.216.34".to_string(),
                },
                Step {
                    label: "connect",
                    phase: Phase::Active,
                    result: String::new(),
                },
                Step {
                    label: "fingerprint",
                    phase: Phase::Pending,
                    result: String::new(),
                },
            ],
            detail: "tcp handshake".to_string(),
            pending: Vec::new(),
            stopping: false,
            tick: 3,
            drawn: 0,
        }
    }

    #[test]
    fn block_height_equals_step_count() {
        let f = render(&sample(), Palette::plain(), 0);
        assert_eq!(f.len(), 3);
    }

    #[test]
    fn plain_render_shows_state_and_data() {
        let f = render(&sample(), Palette::plain(), 3);
        let joined = f.join("\n");
        assert!(!joined.contains('\x1b'), "plain must not emit ansi");
        assert!(joined.contains("resolve"));
        assert!(joined.contains("93.184.216.34"), "done result shown");
        assert!(joined.contains("connect"));
        assert!(joined.contains("tcp handshake"), "active detail shown");
        assert!(joined.contains("fingerprint"), "pending label shown");
    }

    #[test]
    fn done_mark_is_the_grip() {
        let f = render(&sample(), Palette::plain(), 0);
        assert!(f[0].contains(mascot::MARK));
    }

    #[test]
    fn failed_step_shows_reason() {
        let mut st = sample();
        st.steps[1].phase = Phase::Failed;
        st.steps[1].result = "connection refused".to_string();
        let f = render(&st, Palette::plain(), 0);
        assert!(f[1].contains("connection refused"));
    }

    #[test]
    fn inert_stage_is_silent_and_idempotent() {
        let mut st = Stage::new(&["a", "b"], Palette::plain(), false);
        st.begin(0, "d");
        st.complete(0, "r");
        st.fail(1, "x");
        st.detail("y");
        st.finish();
        st.finish();
    }

    #[test]
    fn out_of_range_indices_are_ignored() {
        let st = Stage::new(&["a"], Palette::plain(), true);
        st.begin(9, "no panic");
        st.complete(9, "no panic");
        st.fail(9, "no panic");
        // Give the painter a moment, then stop it.
        drop(st);
    }
}

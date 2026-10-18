//! Explicit continuous-mode controls and durable report/publication boundaries.
use super::*;

impl State {
    pub(super) fn continuous_command(&mut self, text: &str) -> Result<Option<ModuleAction>, Error> {
        if text == "pause" || text == "normal" {
            self.episode.pending_inspection = None;
            self.episode.paused = true;
            self.episode.round =
                self.episode.round.checked_add(1).ok_or_else(|| invalid("revision overflow"))?;
            if text == "normal" {
                self.episode.continuous = false;
            }
            self.save()?;
            return Ok(Some(self.reply(format!(
                "Research paused; mode: {}. Evidence, direction and report checkpoints are saved. Resume continues the retained work.",
                if self.episode.continuous { "Sicko (continuous)" } else { "normal" }
            ))));
        }
        let sicko = text == "sicko" || text.starts_with("sicko ");
        let steer = text == "steer" || text.starts_with("steer ");
        if !sicko && !steer {
            return Ok(None);
        }
        let direction = text.split_once(' ').map(|(_, details)| details.trim()).unwrap_or("");
        if steer && direction.is_empty() {
            return Ok(Some(self.reply("Use steer DETAILS to redirect the retained research without discarding its evidence.".into())));
        }
        if !direction.is_empty() {
            // Preserve prior directions on disk without an ever-growing prompt.
            let journal = self.root().join("directions");
            fs::create_dir_all(&journal)?;
            let entry = json!({"round":self.episode.round,"previous":self.episode.direction,"current":direction});
            let bytes = serde_json::to_vec(&entry)?;
            publish(&journal.join(format!("{}.json", digest(&bytes))), &bytes)?;
            self.episode.direction = direction.into();
        }
        self.episode.pending_inspection = None;
        self.episode.continuous |= sicko;
        self.episode.paused = false;
        self.episode.delivery_requested = false;
        self.episode.round =
            self.episode.round.checked_add(1).ok_or_else(|| invalid("revision overflow"))?;
        self.episode.last_incomplete = None;
        if self.episode.phase == COMPLETE
            && (steer || !self.ledger().review_approved().unwrap_or(false))
        {
            self.episode.phase = if steer { 1 } else { 2 };
        }
        self.episode.feedback = "Continue from saved work under the current user direction. Preserve the approved scope, investigate consequential unfinished questions and publish useful report checkpoints rather than exhausting optional leads.".into();
        self.save()?;
        self.next().map(Some)
    }

    fn checkpoint_key(&self) -> Result<(String, String), Error> {
        let report = self.ledger().inspect("fact-check", &json!({"kind":"report"}))?;
        let hash = required(&report, "report_digest")?.to_owned();
        Ok((
            format!(
                "research-{}-checkpoint-{}-{}",
                &self.current[..16],
                self.episode.round,
                &hash[..16]
            ),
            hash,
        ))
    }

    pub(super) fn checkpoint(&self) -> Result<ModuleAction, Error> {
        let report = self.ledger().stage_output("fact-check")?;
        let (key, hash) = self.checkpoint_key()?;
        let text = if self.episode.last_published_report.as_ref() == Some(&hash) {
            format!(
                "Sicko mode checkpoint: the checked report is unchanged ({hash}). Research continues. View it with /module peritus.deep-research checkpoint {hash}; use pause or steer DETAILS to control the run."
            )
        } else {
            format!(
                "Sicko mode report checkpoint\n\n{report}\n\nResearch continues. Use /module peritus.deep-research pause, steer DETAILS, or normal to control it."
            )
        };
        Ok(ModuleAction::Checkpoint { key, text, actions: self.menu() })
    }

    pub(super) fn acknowledge_checkpoint(&mut self, key: &str) -> Result<ModuleAction, Error> {
        if let Some(expected) = self.episode.pending_inspection.as_ref() {
            if key != expected || !self.episode.continuous || self.episode.paused {
                return Err(invalid("inspection acknowledgement belongs to a different revision"));
            }
            self.episode.pending_inspection = None;
            self.save()?;
            return self.next();
        }
        if !self.episode.continuous || self.episode.paused || self.episode.phase != COMPLETE {
            return Err(invalid("no continuing report checkpoint awaits acknowledgement"));
        }
        let (expected, hash) = self.checkpoint_key()?;
        if key != expected || !self.ledger().review_approved()? {
            return Err(invalid(
                "checkpoint acknowledgement belongs to a different report or revision",
            ));
        }
        self.episode.last_published_report = Some(hash);
        self.episode.phase = 1;
        self.episode.round =
            self.episode.round.checked_add(1).ok_or_else(|| invalid("revision overflow"))?;
        self.episode.feedback = "The report checkpoint has been presented. Continue useful research under current steering: inspect the retained inquiry frontier, select consequential unresolved questions or deeper competing explanations, and update the report when warranted. Do not redo settled provenance. Optional depth can continue, but publish coherent checkpoints rather than withholding all output until exhaustion. User pause/stop takes priority.".into();
        self.episode.last_incomplete = None;
        self.save()?;
        self.next()
    }
}

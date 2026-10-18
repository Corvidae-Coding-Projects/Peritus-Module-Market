//! Small report corrections and durable discovery handoffs without repeating whole drafts.
use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Revision {
    base: String,
    edits: Vec<Edit>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Edit {
    operation: String,
    path: String,
    old_text: String,
    value_json: String,
}

impl Research {
    pub(super) fn save_report(&self, report: Report) -> Result<Value, Error> {
        let id = self.record("drafts", &report)?;
        self.save("draft.json", &json!({"digest":id}))?;
        if let Err(error) = self.validate_report(&report) {
            return Ok(
                json!({"error":error.to_string(),"draft_digest":id,"next":"Correct this draft with research_report_revise; unchanged material need not be retransmitted."}),
            );
        }
        if let Some(review) = self.optional::<Value>("review.json")? {
            let review: Review = self.immutable(
                "reviews",
                review["digest"].as_str().ok_or_else(|| invalid("invalid review pointer"))?,
            )?;
            if review.report_digest == id && !review.approved {
                return Ok(
                    json!({"error":"This exact draft was rejected. Apply the concrete corrections before resubmitting.","draft_digest":id}),
                );
            }
        }
        self.record("reports", &report)?;
        self.save("report.json", &json!({"digest":id}))?;
        Ok(json!({"report_digest":id,"request_complete":true}))
    }

    pub(super) fn revise_report(&self, arguments: &Value) -> Result<Value, Error> {
        let revision: Revision = decode(arguments)?;
        check_id(&revision.base)?;
        let draft = self.optional::<Value>("draft.json")?;
        let report = self.optional::<Value>("report.json")?;
        let folder = if draft.as_ref().is_some_and(|p| p["digest"] == revision.base) {
            "drafts"
        } else if report.as_ref().is_some_and(|p| p["digest"] == revision.base) {
            "reports"
        } else {
            return Err(invalid(
                "Revision base must be the latest draft_digest or current report_digest; inspect the current report before editing.",
            ));
        };
        if revision.edits.is_empty() {
            return Err(invalid("Supply at least one report edit"));
        }
        let base: Report = self.immutable(folder, &revision.base)?;
        let mut value = serde_json::to_value(base)?;
        // This field is omitted in legacy records to preserve their content identities.
        value
            .as_object_mut()
            .ok_or_else(|| invalid("invalid report"))?
            .entry("controversies")
            .or_insert(json!(""));
        for edit in revision.edits {
            let replacement: Value = serde_json::from_str(&edit.value_json)?;
            let target = value.pointer_mut(&edit.path).ok_or_else(||invalid("Report edit path does not exist; use a JSON pointer to an existing field or array"))?;
            match edit.operation.as_str() {
                "set" => *target = replacement,
                "append" => target
                    .as_array_mut()
                    .ok_or_else(|| invalid("append requires an array"))?
                    .push(replacement),
                "replace_text" => {
                    let original = target
                        .as_str()
                        .ok_or_else(|| invalid("replace_text requires a string field"))?;
                    let new_text = replacement
                        .as_str()
                        .ok_or_else(|| invalid("replace_text value_json must encode a string"))?;
                    if edit.old_text.is_empty() || original.matches(&edit.old_text).count() != 1 {
                        return Err(invalid("replace_text old_text must match exactly once"));
                    }
                    *target = json!(original.replacen(&edit.old_text, new_text, 1));
                }
                _ => {
                    return Err(invalid(
                        "Report edit operation must be set, append or replace_text",
                    ));
                }
            }
        }
        self.save_report(decode(&value)?)
    }

    pub(super) fn discovery_passage(&self, candidate: &Candidate) -> Result<Passage, Error> {
        if !matches!(candidate.origin_stage.as_str(), "gather" | "controversies") {
            return Err(invalid("invalid candidate discovery stage"));
        }
        self.observed(
            &candidate.origin_stage,
            &candidate.source,
            candidate.offset,
            &candidate.quote,
        )
    }

    pub(crate) fn save_controversy_sweep(&self, key: &str, text: &str) -> Result<(), Error> {
        required(text)?;
        let candidates = self
            .ids("candidates")?
            .into_iter()
            .filter_map(|id| match self.candidate(&id) {
                Ok(candidate) if candidate.origin_stage == "controversies" => Some(Ok(id)),
                Ok(_) => None,
                Err(e) => Some(Err(e)),
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let id = self.record("controversy-sweeps", &json!({"request":key,"summary":text,"searches":self.ids("searches/controversies")?,"candidates":candidates}))?;
        self.save("controversy-sweep.json", &json!({"digest":id}))
    }
}

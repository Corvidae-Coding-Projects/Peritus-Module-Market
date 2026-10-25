//! Exact observed passages, claim-specific admission and version-bound report approval.
use crate::{Error, digest, invalid, publish};

mod inquiry;
mod inspection;
mod progress;
mod revision;
use inquiry::{Conclusion, InquiryRequirement, Provenance};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Clarification {
    question: String,
    suggestions: Vec<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    question: String,
    questions: Vec<String>,
    scope: String,
    period: String,
    strategy: String,
    output: String,
    clarifications: Vec<Clarification>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    investigation: Vec<InquiryRequirement>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Passage {
    source: String,
    url: String,
    title: String,
    fetched_at_unix: u64,
    offset: u64,
    text: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Candidate {
    #[serde(default = "gather_stage", skip_serializing_if = "is_gather")]
    origin_stage: String,
    question: usize,
    claim: String,
    relation: String,
    source: String,
    offset: u64,
    quote: String,
    category: String,
    publisher: String,
    date: String,
    chain: String,
    limitations: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Admission {
    candidate: String,
    decision: String,
    claim: String,
    rationale: String,
    authority: String,
    methods: String,
    period: String,
    independence: String,
    scope: String,
    limitations: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    provenance: Option<Provenance>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Finding {
    admission: String,
    interpretation: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Disposition {
    question: usize,
    status: String,
    explanation: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Report {
    title: String,
    synthesis: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    controversies: String,
    findings: Vec<Finding>,
    questions: Vec<Disposition>,
    limitations: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    conclusions: Vec<Conclusion>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Review {
    report_digest: String,
    approved: bool,
    reviewed: Vec<String>,
    corrections: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    inquiry_assessment: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Gap {
    question: usize,
    reason: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    attempts: Vec<String>,
}

/// Durable research ledger inside one exclusively owned module job.
/// Records are separately published; raw documents never accumulate in the run record.
pub struct Research {
    root: PathBuf,
}
impl Research {
    /// Creates an app-owned ledger under a module job, never in the project.
    pub fn new(job_root: &Path) -> Self {
        Self { root: job_root.join("research") }
    }
    fn file(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
    fn read<T: DeserializeOwned>(&self, name: &str) -> Result<T, Error> {
        Ok(serde_json::from_slice(&fs::read(self.file(name))?)?)
    }
    fn save<T: Serialize>(&self, name: &str, value: &T) -> Result<(), Error> {
        publish(&self.file(name), &serde_json::to_vec_pretty(value)?)
    }
    fn record<T: Serialize>(&self, folder: &str, value: &T) -> Result<String, Error> {
        let bytes = serde_json::to_vec(value)?;
        if bytes.len() > 1024 * 1024 {
            return Err(invalid(
                "research record exceeds the per-operation 1 MiB resource bound; split the record",
            ));
        }
        let id = digest(&bytes);
        publish(&self.file(&format!("{folder}/{id}.json")), &bytes)?;
        Ok(id)
    }
    fn immutable<T: DeserializeOwned>(&self, folder: &str, id: &str) -> Result<T, Error> {
        check_id(id)?;
        let bytes = fs::read(self.file(&format!("{folder}/{id}.json")))?;
        if digest(&bytes) != id {
            return Err(invalid("research record integrity mismatch"));
        }
        Ok(serde_json::from_slice(&bytes)?)
    }
    fn ids(&self, folder: &str) -> Result<Vec<String>, Error> {
        let entries = match fs::read_dir(self.file(folder)) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let mut ids = Vec::new();
        for entry in entries {
            let entry = entry?;
            if entry.file_type()?.is_file()
                && let Some(id) = entry.path().file_stem().and_then(|s| s.to_str())
            {
                check_id(id)?;
                ids.push(id.to_owned());
            }
        }
        ids.sort();
        Ok(ids)
    }
    fn plan(&self) -> Result<Plan, Error> {
        self.read("plan.json")
    }
    /// Exact saved plan identity used by a human Start action.
    pub fn plan_digest(&self) -> Result<String, Error> {
        Ok(digest(&serde_json::to_vec(&self.plan()?)?))
    }
    /// Approves the current plan only, after material clarification is resolved.
    pub fn approve(&self, expected: &str) -> Result<(), Error> {
        if !self.plan()?.clarifications.is_empty() {
            return Err(invalid(
                "Answer the material clarification questions with /module peritus.deep-research revise DETAILS before starting.",
            ));
        }
        if self.plan_digest()? != expected {
            return Err(invalid(
                "The plan changed or this Start is stale. View the current plan and approve its exact digest.",
            ));
        }
        self.save("approved.json", &json!({"plan_digest":expected}))
    }
    /// Whether the saved plan has a current explicit human approval.
    pub fn approved(&self) -> Result<bool, Error> {
        match self.read::<Value>("approved.json") {
            Ok(v) => Ok(v["plan_digest"] == self.plan_digest()?),
            Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }
    /// Records an actual successful host web_open/web_read page, scoped to its reading role.
    pub fn observe(&self, stage: &str, value: &Value) -> Result<(), Error> {
        if let (Some(query), Some(results)) = (value["query"].as_str(), value["results"].as_array())
        {
            if !self.approved()?
                || !matches!(stage, "gather" | "controversies" | "assess" | "fact-check")
            {
                return Err(invalid("source discovery requires an approved research stage"));
            }
            let urls = results.iter().filter_map(|r| r["url"].as_str()).collect::<Vec<_>>();
            self.record(&format!("searches/{stage}"), &json!({"query":query,"urls":urls}))?;
            return Ok(());
        }
        let (Some(source), Some(text), Some(url)) =
            (value["source"].as_str(), value["text"].as_str(), value["url"].as_str())
        else {
            return Ok(());
        };
        check_id(source)?;
        if !self.approved()? {
            return Err(invalid(
                "no research source reads may be admitted before explicit approval of the saved plan",
            ));
        }
        if !matches!(stage, "gather" | "controversies" | "assess" | "fact-check") {
            return Err(invalid("web evidence is not allowed in this research stage"));
        }
        let title =
            value["title"].as_str().unwrap_or_default().chars().take(512).collect::<String>();
        let fetched_at_unix = value["fetched_at_unix"].as_u64().unwrap_or(0);
        let base = value["offset"].as_u64().unwrap_or(0);
        // A legal 1 MiB web page expands further when JSON-escaped. Retain smaller exact
        // records, overlapping by the maximum quote size so boundary-spanning quotes remain
        // eligible. Chunking bounds allocations per record, never the retained investigation.
        let mut start = 0usize;
        loop {
            let mut end = start.saturating_add(64 * 1024).min(text.len());
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            let passage = Passage {
                source: source.into(),
                url: url.into(),
                title: title.clone(),
                fetched_at_unix,
                offset: base
                    .checked_add(start as u64)
                    .ok_or_else(|| invalid("source offset overflow"))?,
                text: text[start..end].into(),
            };
            self.record(&format!("reads/{stage}/{source}"), &passage)?;
            if end == text.len() {
                break;
            }
            start = end - 16384;
            while !text.is_char_boundary(start) {
                start += 1;
            }
        }
        self.save(&format!("sources/{source}.json"), &json!({"source":source,"url":url,"title":title,"fetched_at_unix":fetched_at_unix,"total_bytes":value["total_bytes"]}))
    }
    fn observed(
        &self,
        stage: &str,
        source: &str,
        offset: u64,
        quote: &str,
    ) -> Result<Passage, Error> {
        check_id(source)?;
        if quote.trim().is_empty() || quote.len() > 16384 {
            return Err(invalid("quote must contain 1..16384 bytes of the exact observed text"));
        }
        let folder = format!("reads/{stage}/{source}");
        let mut matches = std::collections::BTreeSet::new();
        let mut range_read = false;
        for id in self.ids(&folder)? {
            let page: Passage = self.immutable(&folder, &id)?;
            if let Some(start) =
                offset.checked_sub(page.offset).and_then(|n| usize::try_from(n).ok())
            {
                range_read |= page.text.get(start..start.saturating_add(quote.len())).is_some();
                if page.text.get(start..start.saturating_add(quote.len())) == Some(quote) {
                    return Ok(page);
                }
            }
            // Diagnose offsets using only passages this role already observed.
            // Keep the error bounded even when an exact phrase occurs repeatedly.
            for (start, _) in page.text.match_indices(quote).take(9) {
                if matches.len() < 9
                    && let Some(offset) = page.offset.checked_add(start as u64)
                {
                    matches.insert(offset);
                }
            }
        }
        if !matches.is_empty() {
            return Err(invalid(format!(
                "The exact quote is already read at UTF-8 byte offsets {matches:?}. Correct the supplied offset {offset}; another web_read is unnecessary. Offsets shown are bounded to nine matches.",
            )));
        }
        if range_read {
            return Err(invalid(
                "This role already read the requested range, but the quote differs. Copy the exact observed text and its UTF-8 byte offset; rereading the same range is unnecessary.",
            ));
        }
        Err(invalid(
            "This role has not read that exact source/range, or the quote differs. Use web_read on the original source and the exact UTF-8 offset before recording it.",
        ))
    }
    fn candidate(&self, id: &str) -> Result<Candidate, Error> {
        self.immutable("candidates", id)
    }
    fn admission(&self, id: &str) -> Result<Admission, Error> {
        self.immutable("admissions", id)
    }
    fn question(&self, index: usize) -> Result<(), Error> {
        if index == 0 || index > self.plan()?.questions.len() {
            return Err(invalid("question must be a 1-based index in the approved plan"));
        }
        Ok(())
    }
    /// Applies one typed role operation. Input errors are correctable tool observations.
    pub fn invoke(&self, stage: &str, name: &str, arguments: &Value) -> Result<Value, Error> {
        if name == "research_inspect" {
            return self.inspect(stage, arguments);
        }
        if name == "research_item" {
            return self.item(stage, arguments);
        }
        if stage != "plan" && !self.approved()? {
            return Err(invalid(
                "research cannot gather, admit, synthesize or check before the human approves the saved plan",
            ));
        }
        match (stage, name) {
            ("gather", "research_finish") => {
                self.stage_output("gather")?;
                Ok(json!({"saved":true,"request_complete":true}))
            }
            ("assess", "research_coverage") => self.save_coverage(arguments),
            ("assess" | "fact-check", "research_inquiry") => self.save_inquiry(arguments),
            ("assess" | "fact-check", "research_followup") => self.save_followup(stage, arguments),
            ("fact-check", "research_check") => self.save_check(arguments),
            ("plan", "research_plan") => {
                if self.read::<Value>("approved.json").is_ok() {
                    return Err(invalid(
                        "approved plans are immutable; ask the user to revise the scope",
                    ));
                }
                let plan: Plan = decode(arguments)?;
                for text in
                    [&plan.question, &plan.scope, &plan.period, &plan.strategy, &plan.output]
                {
                    required(text)?;
                }
                if plan.questions.is_empty() {
                    return Err(invalid("include at least one answerable subquestion"));
                }
                for q in &plan.questions {
                    required(q)?;
                }
                Self::validate_requirements(&plan)?;
                for q in &plan.clarifications {
                    required(&q.question)?;
                    for s in &q.suggestions {
                        required(s)?;
                    }
                }
                self.save("plan.json", &plan)?;
                Ok(
                    json!({"saved":true,"plan_digest":self.plan_digest()?,"needs_clarification":!plan.clarifications.is_empty(),"request_complete":true}),
                )
            }
            ("gather" | "controversies", "research_candidate") => {
                let mut item: Candidate = decode(arguments)?;
                item.origin_stage = stage.into();
                self.question(item.question)?;
                for s in [&item.claim, &item.publisher, &item.date, &item.chain, &item.limitations]
                {
                    required(s)?;
                }
                if !matches!(
                    item.category.as_str(),
                    "study"
                        | "investigation"
                        | "analysis"
                        | "dataset"
                        | "standard"
                        | "documentation"
                        | "source-code"
                        | "first-party"
                        | "discovery-only"
                ) || !matches!(item.relation.as_str(), "supports" | "contradicts")
                {
                    return Err(invalid("invalid evidence category or relation"));
                }
                let passage = self.observed(stage, &item.source, item.offset, &item.quote)?;
                let id = self.record("candidates", &item)?;
                Ok(
                    json!({"candidate":id,"url":passage.url,"state":"unassessed; unavailable to synthesis until admitted"}),
                )
            }
            ("gather" | "controversies", "research_gap") => {
                let gap: Gap = decode(arguments)?;
                self.question(gap.question)?;
                self.checked_gap(&gap)?;
                Ok(json!({"gap":self.record("gaps",&gap)?}))
            }
            ("assess", "research_admit") => {
                let admission: Admission = decode(arguments)?;
                let candidate = self.candidate(&admission.candidate)?;
                for s in [
                    &admission.claim,
                    &admission.rationale,
                    &admission.authority,
                    &admission.methods,
                    &admission.period,
                    &admission.independence,
                    &admission.scope,
                    &admission.limitations,
                ] {
                    required(s)?;
                }
                if !matches!(admission.decision.as_str(), "admitted" | "qualified" | "rejected") {
                    return Err(invalid("decision must be admitted, qualified or rejected"));
                }
                if admission.decision != "rejected" {
                    self.validate_provenance(&admission, &candidate)?;
                    if candidate.category == "discovery-only" {
                        return Err(invalid(
                            "blogs, SEO, aggregators, social and AI summaries are discovery-only and cannot support conclusions",
                        ));
                    }
                    if matches!(candidate.category.as_str(), "first-party" | "investigation")
                        && admission.decision != "qualified"
                    {
                        return Err(invalid(
                            "first-party statements and reported allegations require qualified, explicitly attributed scope",
                        ));
                    }
                    self.observed("assess", &candidate.source, candidate.offset, &candidate.quote)?;
                }
                let id = self.record("admissions", &admission)?;
                self.save(
                    &format!("decisions/{}.json", admission.candidate),
                    &json!({"admission":id}),
                )?;
                Ok(json!({"admission":id,"decision":admission.decision}))
            }
            ("write", "research_report") => self.save_report(decode(arguments)?),
            ("write", "research_report_revise") => self.revise_report(arguments),
            ("fact-check", "research_review") => {
                let review: Review = decode(arguments)?;
                let (id, report) = self.current_report()?;
                required(&review.inquiry_assessment)?;
                if review.approved {
                    self.validate_report(&report)?;
                }
                if review.report_digest != id {
                    return Err(invalid("review must bind the exact current report_digest"));
                }
                let inspected: Value = self.read(&format!("report-reads/fact-check-{id}.json"))?;
                if inspected["report_digest"] != id {
                    return Err(invalid(
                        "fact-check must inspect the exact current report before approving it",
                    ));
                }
                let expected =
                    report.findings.iter().map(|f| f.admission.as_str()).collect::<BTreeSet<_>>();
                let checked = review.reviewed.iter().map(String::as_str).collect::<BTreeSet<_>>();
                if checked.len() != review.reviewed.len()
                    || !checked.is_subset(&expected)
                    || (review.approved && checked != expected)
                {
                    return Err(invalid(
                        "Approval must review exactly every cited admission. An early rejection lists only actually checked cited admissions, without duplicates.",
                    ));
                }
                if review.approved && !review.corrections.is_empty()
                    || !review.approved && review.corrections.is_empty()
                {
                    return Err(invalid(
                        "approval requires no corrections; rejection requires concrete corrections",
                    ));
                }
                for reference in &review.reviewed {
                    let check = self.check(&id, reference)?.ok_or_else(|| invalid(format!("Save research_check for citation {reference} before completing review; inspect progress for pending citations")))?;
                    if review.approved && check["approved"] != true {
                        return Err(invalid(
                            "a failed citation check must be corrected before report approval",
                        ));
                    }
                    let admission = self.admission(reference)?;
                    let candidate = self.candidate(&admission.candidate)?;
                    self.observed(
                        "fact-check",
                        &candidate.source,
                        candidate.offset,
                        &candidate.quote,
                    )?;
                }
                for correction in &review.corrections {
                    required(correction)?;
                }
                let review_id = self.record("reviews", &review)?;
                self.save("review.json", &json!({"digest":review_id}))?;
                Ok(
                    json!({"review":review_id,"report_digest":id,"approved":review.approved,"request_complete":true}),
                )
            }
            _ => Err(invalid("research operation is unavailable to this role")),
        }
    }
    fn current_report(&self) -> Result<(String, Report), Error> {
        let v: Value = self.read("report.json")?;
        let id = v["digest"].as_str().ok_or_else(|| invalid("report pointer is invalid"))?;
        Ok((id.into(), self.immutable("reports", id)?))
    }
    fn current_review(&self) -> Result<Review, Error> {
        let v: Value = self.read("review.json")?;
        self.immutable(
            "reviews",
            v["digest"].as_str().ok_or_else(|| invalid("review pointer is invalid"))?,
        )
    }
    fn active_admissions(&self) -> Result<Vec<(String, Admission)>, Error> {
        let mut list = vec![];
        for candidate in self.ids("candidates")? {
            let Some(decision) = self.optional::<Value>(&format!("decisions/{candidate}.json"))?
            else {
                continue;
            };
            let id = decision["admission"]
                .as_str()
                .ok_or_else(|| invalid("admission pointer is invalid"))?;
            list.push((id.into(), self.admission(id)?));
        }
        Ok(list)
    }
    fn validate_report(&self, report: &Report) -> Result<(), Error> {
        required(&report.title)?;
        required(&report.synthesis)?;
        if report.controversies.trim().is_empty() {
            return Err(invalid(
                "Include the dedicated controversies field: present substantive accusations/criticisms, attribution, responses and documented outcomes. If not investigated or applicable, state that scope honestly; never invent a controversy.",
            ));
        }
        if !self.coverage_current()? {
            return Err(invalid(
                "Current independent-inquiry coverage is required; reassess legacy or changed evidence before publishing a report",
            ));
        }
        let active = self
            .active_admissions()?
            .into_iter()
            .filter(|(_, a)| a.decision != "rejected" && a.provenance.is_some())
            .map(|(id, _)| id)
            .collect::<BTreeSet<_>>();
        let mut found = BTreeSet::new();
        for finding in &report.findings {
            if !active.contains(&finding.admission) || !found.insert(&finding.admission) {
                return Err(invalid(
                    "report findings must cite unique, current admitted/qualified evidence; rejected/unassessed citations are unavailable",
                ));
            }
        }
        let mut questions = BTreeSet::new();
        for disposition in &report.questions {
            self.question(disposition.question)?;
            required(&disposition.explanation)?;
            if !questions.insert(disposition.question)
                || !matches!(
                    disposition.status.as_str(),
                    "supported" | "contested" | "partial" | "unknown"
                )
            {
                return Err(invalid(
                    "question dispositions must be unique and supported, contested, partial or unknown",
                ));
            }
            let mut relations = BTreeSet::new();
            for finding in &report.findings {
                let a = self.admission(&finding.admission)?;
                let c = self.candidate(&a.candidate)?;
                if c.question == disposition.question
                    || report.conclusions.iter().any(|conclusion| {
                        conclusion.question == disposition.question
                            && (conclusion.supports.contains(&finding.admission)
                                || conclusion.contradicts.contains(&finding.admission))
                    })
                {
                    relations.insert(c.relation);
                }
            }
            if disposition.status != "unknown" && relations.is_empty() {
                return Err(invalid(
                    "supported/contested means evidence addresses the question; cite an admitted finding for that question, or mark it unknown",
                ));
            }
            if matches!(disposition.status.as_str(), "supported" | "contested")
                && !self.question_answered(disposition.question)?
            {
                return Err(invalid(
                    "Supported/contested requires substantive answers to every approved criterion. Mark investigated remaining gaps partial/unknown; qualified subject accounts cannot stand in for independent inquiry.",
                ));
            }
        }
        if questions.len() != self.plan()?.questions.len() {
            return Err(invalid(
                "give every approved subquestion a supported, contested or unknown disposition",
            ));
        }
        for l in &report.limitations {
            required(l)?;
        }
        self.validate_conclusions(report)?;
        Ok(())
    }
    /// Validates a role's completed contract and provides the host-authored checkpoint artifact.
    pub fn stage_output(&self, stage: &str) -> Result<String, Error> {
        match stage {
            "plan" => self.plan_markdown(),
            "gather" => {
                self.ensure_followup_addressed()?;
                let mut covered = BTreeSet::new();
                for id in self.ids("candidates")? {
                    covered.insert(self.candidate(&id)?.question);
                }
                for id in self.ids("gaps")? {
                    let gap: Gap = self.immutable("gaps", &id)?;
                    covered.insert(gap.question);
                }
                if covered.len() != self.plan()?.questions.len() {
                    return Err(invalid(
                        "record candidates or an honest retrieval/evidence gap for every planned question before finishing gathering",
                    ));
                }
                Ok(format!(
                    "Gathering retained {} candidate passages. Inspect them with research_inspect candidates; search snippets are not admitted evidence. Gaps: {}",
                    self.ids("candidates")?.len(),
                    serde_json::to_string(&self.inspect(stage, &json!({"kind":"gaps"}))?)?
                ))
            }
            "assess" => {
                if !self.coverage_current()? {
                    return Err(invalid(
                        "Save research_coverage from useful vetted evidence, with honest unresolved or deferred detail; unused candidates do not require assessment. Produce a draft before expanding the agenda.",
                    ));
                }
                Ok(serde_json::to_string(&self.progress("assess")?)?)
            }
            "write" => {
                self.validate_report(&self.current_report()?.1)?;
                if self.corrections()?.is_some() {
                    return Err(invalid(
                        "submit a revised report that resolves or honestly qualifies the reviewer's corrections before finishing synthesis",
                    ));
                }
                self.save_report_markdown(false)
            }
            "fact-check" => {
                if !self.review_approved()? {
                    return Err(invalid(
                        "the exact current report still needs corrections or a completed source check",
                    ));
                }
                self.save_report_markdown(true)
            }
            _ => Err(invalid("unknown research stage")),
        }
    }
    fn save_report_markdown(&self, checked: bool) -> Result<String, Error> {
        let (id, _) = self.current_report()?;
        let text = if checked
            && self.optional::<Value>(&format!("reports/{id}-checkpoint.json"))?.is_some()
        {
            self.checked_report(&id)?
        } else {
            let text = self.report_markdown(checked)?;
            publish(
                &self.file(&format!(
                    "reports/{id}-{}.md",
                    if checked { "checked" } else { "draft" }
                )),
                text.as_bytes(),
            )?;
            if checked {
                let review: Value = self.read("review.json")?;
                self.save(&format!("reports/{id}-checkpoint.json"), &json!({"report_digest":id,"rendered_sha256":digest(text.as_bytes()),"review_digest":review["digest"]}))?;
            }
            text
        };
        if checked {
            self.save("checked-report.json", &json!({"digest":id}))?;
        }
        Ok(text)
    }
    /// Read an exact historical checked report without consulting newer draft/evidence state.
    pub fn checked_report(&self, id: &str) -> Result<String, Error> {
        check_id(id)?;
        let checkpoint: Value = self.read(&format!("reports/{id}-checkpoint.json"))?;
        let text = fs::read_to_string(self.file(&format!("reports/{id}-checked.md")))?;
        let review: Review = self.immutable(
            "reviews",
            checkpoint["review_digest"]
                .as_str()
                .ok_or_else(|| invalid("checkpoint review identity missing"))?,
        )?;
        if checkpoint["report_digest"] != id
            || checkpoint["rendered_sha256"] != digest(text.as_bytes())
            || !review.approved
            || review.report_digest != id
        {
            return Err(invalid("checked report artifact differs from its bound checkpoint"));
        }
        Ok(text)
    }
    /// Last completed report remains readable while later evidence/drafts evolve.
    pub fn last_checked_report(&self) -> Result<Option<(String, String)>, Error> {
        let Some(pointer) = self.optional::<Value>("checked-report.json")? else {
            // Older package versions already have a valid exact-report review,
            // but did not persist a separate historical-checkpoint pointer.
            if self.review_approved().unwrap_or(false) {
                self.save_report_markdown(true)?;
                return self.last_checked_report();
            }
            return Ok(None);
        };
        let id =
            pointer["digest"].as_str().ok_or_else(|| invalid("invalid checked report pointer"))?;
        Ok(Some((id.into(), self.checked_report(id)?)))
    }
    /// Whether a current report has a digest-bound, complete final source check.
    pub fn review_approved(&self) -> Result<bool, Error> {
        if self.optional::<Value>("report.json")?.is_none()
            || self.optional::<Value>("review.json")?.is_none()
        {
            return Ok(false);
        }
        let (id, report) = self.current_report()?;
        let review = self.current_review()?;
        if report.controversies.is_empty()
            || !review.approved
            || review.report_digest != id
            || review.inquiry_assessment.trim().is_empty()
        {
            return Ok(false);
        }
        self.validate_report(&report)?;
        Ok(true)
    }
    /// Current reviewer corrections when they bind the current draft.
    pub fn corrections(&self) -> Result<Option<Value>, Error> {
        if self.optional::<Value>("report.json")?.is_none() {
            return Ok(None);
        }
        let (id, _) = self.current_report()?;
        match self.current_review() {
            Ok(review) if review.report_digest == id && !review.approved => Ok(Some(json!(review))),
            Ok(_) => Ok(None),
            Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
    /// Saved plan and its explicit human Start command; material questions remain visible.
    pub fn plan_markdown(&self) -> Result<String, Error> {
        let plan = self.plan()?;
        let mut text = format!(
            "Research plan\n\n# {}\n\nScope: {}\n\nPeriod/version: {}\n\nSource strategy: {}\n\nReport: {}\n\n",
            plan.question, plan.scope, plan.period, plan.strategy, plan.output
        );
        for (i, q) in plan.questions.iter().enumerate() {
            text.push_str(&format!("{}. {q}\n", i + 1));
            let requirement = self.requirement(i + 1)?;
            text.push_str(&format!(
                "   Evidence need: {}\n",
                serde_json::to_string(&requirement.evidence_need)?
            ));
            for (criterion, target) in requirement.criteria.iter().enumerate() {
                text.push_str(&format!("   Answer criterion {}: {target}\n", criterion + 1));
            }
        }
        for q in plan.clarifications {
            text.push_str(&format!(
                "\nClarification: {}\nSuggested answers: {}\n",
                q.question,
                q.suggestions.join("; ")
            ));
        }
        text.push_str(&format!("\nRevise with /module peritus.deep-research revise DETAILS. No sources are gathered until you approve this saved plan.\n\nPlan digest: {}\nStart research: /module peritus.deep-research start {}",self.plan_digest()?,self.plan_digest()?));
        Ok(text)
    }
    /// Exact cited evidence is available separately from the concise primary report.
    pub fn evidence_markdown(&self, index: usize) -> Result<String, Error> {
        let (id, _) = self.current_report()?;
        self.evidence_for_report(&id, index)
    }
    /// Finding numbers are interpreted against the exact referenced report version.
    pub fn evidence_for_report(&self, id: &str, index: usize) -> Result<String, Error> {
        let report: Report = self.immutable("reports", id)?;
        let finding =
            index.checked_sub(1).and_then(|i| report.findings.get(i)).ok_or_else(|| {
                invalid("evidence number must identify a finding in the current report")
            })?;
        let a = self.admission(&finding.admission)?;
        let c = self.candidate(&a.candidate)?;
        let page = self.discovery_passage(&c)?;
        let provenance = match &a.provenance {
            Some(p) => format!("\nSource role: {}\nProvenance: {}\nDependencies: {}\n",p.label(),p.basis,p.dependencies.join("; ")),
            None => "\nLegacy assessment: source relationships have not been reassessed under the current inquiry standard.\n".into(),
        };
        Ok(format!(
            "# Evidence {index}\n\n{}\n\nAssessment: {}. Scope: {}. Limitations: {}\n\nRationale: {}\nAuthority: {}\nMethods: {}\nIndependence: {}\n\n[Source]({}) — {}; {}; chain {}\nSource {} bytes {}..{}; admission {}\n\n> {}\n\nInterpretation: {}{}\nReport digest: {id}\n",
            a.claim,
            a.decision,
            a.scope,
            a.limitations,
            a.rationale,
            a.authority,
            a.methods,
            a.independence,
            page.url,
            c.publisher,
            a.period,
            c.chain,
            c.source,
            c.offset,
            c.offset + c.quote.len() as u64,
            finding.admission,
            c.quote.replace('\n', "\n> "),
            finding.interpretation,
            provenance,
        ))
    }
    /// Human-readable report with qualifications, source ranges and explicit unknowns.
    pub fn report_markdown(&self, checked: bool) -> Result<String, Error> {
        let (id, report) = self.current_report()?;
        if checked && !self.review_approved()? {
            return Err(invalid("current report has not passed its bound source check"));
        }
        let legacy = report.conclusions.is_empty() || report.controversies.is_empty();
        if !legacy {
            self.validate_report(&report)?;
        }
        let mut text = format!(
            "# {}\n\n{}\n\n## Synthesis and interpretation\n\n{}\n",
            report.title,
            if checked {
                "Source-checked report (AI assessment; limitations below)."
            } else if legacy {
                "LEGACY RESEARCH OUTPUT — current independent-inquiry assessment is incomplete; use reassess."
            } else {
                "PARTIAL DRAFT — independent source check is incomplete."
            },
            report.synthesis
        );
        if !report.controversies.is_empty() {
            let section = report.controversies.trim_start();
            let section = section
                .lines()
                .next()
                .filter(|line| line.trim().eq_ignore_ascii_case("## Controversies and criticism"))
                .map_or(section, |line| section[line.len()..].trim_start());
            text.push_str(&format!("\n## Controversies and criticism\n\n{}\n", section));
        }
        text.push_str("\n## Sources\n");
        for (index, finding) in report.findings.iter().enumerate() {
            let a = self.admission(&finding.admission)?;
            let c = self.candidate(&a.candidate)?;
            let page = self.discovery_passage(&c)?;
            let title = if !page.title.trim().is_empty() {
                &page.title
            } else if !c.publisher.trim().is_empty() {
                &c.publisher
            } else {
                &page.url
            };
            text.push_str(&format!(
                "\n{}. [{}]({}) — {}; {}.\n",
                index + 1,
                title
                    .replace('\\', "\\\\")
                    .replace('[', "\\[")
                    .replace(']', "\\]")
                    .replace(['\n', '\r'], " "),
                page.url,
                c.publisher,
                c.date
            ));
            if let Some(p) = &a.provenance {
                text.push_str(&format!("   Source role: {}.\n", p.label()));
            }
        }
        text.push_str(&format!("\nExact passages, claim qualifications and assessment rationales are retained separately. Use `/module peritus.deep-research evidence {id} NUMBER` for a source above.\n"));
        let plan = self.plan()?;
        text.push_str("\n## Question coverage\n");
        for q in report.questions {
            text.push_str(&format!(
                "\n- {} — {}: {}\n",
                plan.questions[q.question - 1],
                q.status,
                q.explanation
            ));
        }
        text.push_str("\n## Limitations\n");
        for l in report.limitations {
            text.push_str(&format!("\n- {l}"));
        }
        text.push_str(&format!("\n\nReport digest: {id}\nPlan digest: {}\n", self.plan_digest()?));
        Ok(text)
    }
}
fn page_size() -> usize {
    8
}
fn required(s: &str) -> Result<(), Error> {
    if s.trim().is_empty() || s.contains('\0') {
        Err(invalid(
            "required research fields must contain nonempty text without NUL; use 'unknown' when metadata is unavailable",
        ))
    } else {
        Ok(())
    }
}
fn check_id(s: &str) -> Result<(), Error> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
        Err(invalid("expected an exact research/source digest"))
    } else {
        Ok(())
    }
}
fn decode<T: DeserializeOwned>(v: &Value) -> Result<T, Error> {
    Ok(serde_json::from_value(v.clone())?)
}

fn gather_stage() -> String {
    "gather".into()
}
fn is_gather(stage: &str) -> bool {
    stage == "gather"
}

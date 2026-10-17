//! Exact observed passages, claim-specific admission and version-bound report approval.
use crate::{Error, digest, invalid, publish};
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
    findings: Vec<Finding>,
    questions: Vec<Disposition>,
    limitations: Vec<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Review {
    report_digest: String,
    approved: bool,
    reviewed: Vec<String>,
    corrections: Vec<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Gap {
    question: usize,
    reason: String,
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
            if entry.file_type()?.is_file() {
                if let Some(id) = entry.path().file_stem().and_then(|s| s.to_str()) {
                    check_id(id)?;
                    ids.push(id.to_owned());
                }
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
        if !matches!(stage, "gather" | "assess" | "fact-check") {
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
        for id in self.ids(&folder)? {
            let page: Passage = self.immutable(&folder, &id)?;
            if let Some(start) =
                offset.checked_sub(page.offset).and_then(|n| usize::try_from(n).ok())
            {
                if page.text.get(start..start.saturating_add(quote.len())) == Some(quote) {
                    return Ok(page);
                }
            }
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
        if stage != "plan" && !self.approved()? {
            return Err(invalid(
                "research cannot gather, admit, synthesize or check before the human approves the saved plan",
            ));
        }
        match (stage, name) {
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
                for q in &plan.clarifications {
                    required(&q.question)?;
                    for s in &q.suggestions {
                        required(s)?;
                    }
                }
                self.save("plan.json", &plan)?;
                Ok(
                    json!({"saved":true,"plan_digest":self.plan_digest()?,"needs_clarification":!plan.clarifications.is_empty()}),
                )
            }
            ("gather", "research_candidate") => {
                let item: Candidate = decode(arguments)?;
                self.question(item.question)?;
                for s in [&item.claim, &item.publisher, &item.date, &item.chain, &item.limitations]
                {
                    required(s)?;
                }
                if !matches!(
                    item.category.as_str(),
                    "study"
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
                let passage = self.observed("gather", &item.source, item.offset, &item.quote)?;
                let id = self.record("candidates", &item)?;
                Ok(
                    json!({"candidate":id,"url":passage.url,"state":"unassessed; unavailable to synthesis until admitted"}),
                )
            }
            ("gather", "research_gap") => {
                let gap: Gap = decode(arguments)?;
                self.question(gap.question)?;
                required(&gap.reason)?;
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
                    if candidate.category == "discovery-only" {
                        return Err(invalid(
                            "blogs, SEO, aggregators, social and AI summaries are discovery-only and cannot support conclusions",
                        ));
                    }
                    if candidate.category == "first-party" && admission.decision != "qualified" {
                        return Err(invalid(
                            "first-party statements require qualified, explicitly attributed scope",
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
            ("write", "research_report") => {
                let report: Report = decode(arguments)?;
                self.validate_report(&report)?;
                let id = self.record("reports", &report)?;
                if let Ok(review) = self.current_review() {
                    if !review.approved && review.report_digest == id {
                        return Err(invalid(
                            "this exact draft was rejected; change the disputed claims/qualifications or state the unresolved evidence gap",
                        ));
                    }
                }
                self.save("report.json", &json!({"digest":id}))?;
                Ok(json!({"report_digest":id,"status":"draft; pending independent source check"}))
            }
            ("fact-check", "research_review") => {
                let review: Review = decode(arguments)?;
                let (id, report) = self.current_report()?;
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
                if review.reviewed.iter().map(String::as_str).collect::<BTreeSet<_>>() != expected {
                    return Err(invalid(
                        "reviewed must cover exactly every cited admission in the actual report",
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
                Ok(json!({"review":review_id,"report_digest":id,"approved":review.approved}))
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
            let decision: Value = self.read(&format!("decisions/{candidate}.json"))?;
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
        let active = self
            .active_admissions()?
            .into_iter()
            .filter(|(_, a)| a.decision != "rejected")
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
                || !matches!(disposition.status.as_str(), "supported" | "contested" | "unknown")
            {
                return Err(invalid(
                    "question dispositions must be unique and supported, contested or unknown",
                ));
            }
            let mut relations = BTreeSet::new();
            for finding in &report.findings {
                let a = self.admission(&finding.admission)?;
                let c = self.candidate(&a.candidate)?;
                if c.question == disposition.question {
                    relations.insert(c.relation);
                }
            }
            if disposition.status == "supported" && !relations.contains("supports")
                || disposition.status == "contested"
                    && !(relations.contains("supports") && relations.contains("contradicts"))
            {
                return Err(invalid(
                    "supported/contested questions require corresponding admitted evidence in this report",
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
        Ok(())
    }
    /// Paged role-scoped ledger, including exact source pointers for independent rereading.
    pub fn inspect(&self, stage: &str, args: &Value) -> Result<Value, Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Request {
            kind: String,
            #[serde(default)]
            offset: usize,
            #[serde(default = "page_size")]
            max_items: usize,
        }
        let request: Request = decode(args)?;
        if request.kind == "plan" {
            return Ok(
                json!({"plan":self.plan()?,"digest":self.plan_digest()?,"approved":self.approved()?}),
            );
        }
        if request.kind == "report" {
            let (id, report) = self.current_report()?;
            if stage == "fact-check" {
                self.save(
                    &format!("report-reads/fact-check-{id}.json"),
                    &json!({"report_digest":id}),
                )?;
            }
            return Ok(json!({"report_digest":id,"report":report}));
        }
        if request.kind == "review" {
            return Ok(json!(self.current_review()?));
        }
        if request.kind == "admissions" {
            let records = self
                .active_admissions()?
                .into_iter()
                .filter(|(_, a)| stage != "write" || a.decision != "rejected")
                .collect::<Vec<_>>();
            let page=records.iter().skip(request.offset).take(request.max_items.clamp(1,32)).map(|(id,a)|Ok(json!({"admission":id,"assessment":a,"candidate":self.candidate(&a.candidate)?}))).collect::<Result<Vec<_>,Error>>()?;
            return Ok(
                json!({"records":page,"next_offset":(request.offset+page.len()<records.len()).then_some(request.offset+page.len())}),
            );
        }
        if stage == "write" && !matches!(request.kind.as_str(), "gaps") {
            return Err(invalid(
                "synthesis may read only the plan, admitted evidence, gaps, draft and correction feedback",
            ));
        }
        let folder = match request.kind.as_str() {
            "candidates" => "candidates",
            "gaps" => "gaps",
            "sources" => "sources",
            _ => {
                return Err(invalid(
                    "kind must be plan, candidates, admissions, gaps, sources, report or review",
                ));
            }
        };
        let ids = self.ids(folder)?;
        let mut records = Vec::new();
        for id in ids.iter().skip(request.offset).take(request.max_items.clamp(1, 32)) {
            records.push(json!({"id":id,"record":if folder=="sources"{self.read::<Value>(&format!("sources/{id}.json"))?}else{self.immutable::<Value>(folder,id)?}}));
        }
        Ok(
            json!({"records":records,"next_offset":(request.offset+records.len()<ids.len()).then_some(request.offset+records.len())}),
        )
    }
    /// Validates a role's completed contract and provides the host-authored checkpoint artifact.
    pub fn stage_output(&self, stage: &str) -> Result<String, Error> {
        match stage {
            "plan" => self.plan_markdown(),
            "gather" => {
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
                Ok(serde_json::to_string(&self.inspect("write", &json!({"kind":"admissions"}))?)?)
            }
            "write" => {
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
        let text = self.report_markdown(checked)?;
        let (id, _) = self.current_report()?;
        publish(
            &self.file(&format!("reports/{id}-{}.md", if checked { "checked" } else { "draft" })),
            text.as_bytes(),
        )?;
        Ok(text)
    }
    /// Whether a current report has a digest-bound, complete final source check.
    pub fn review_approved(&self) -> Result<bool, Error> {
        let (id, _) = self.current_report()?;
        let review = self.current_review()?;
        Ok(review.approved && review.report_digest == id)
    }
    /// Current reviewer corrections when they bind the current draft.
    pub fn corrections(&self) -> Result<Option<Value>, Error> {
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
    /// Human-readable report with qualifications, source ranges and explicit unknowns.
    pub fn report_markdown(&self, checked: bool) -> Result<String, Error> {
        let (id, report) = self.current_report()?;
        if checked && !self.review_approved()? {
            return Err(invalid("current report has not passed its bound source check"));
        }
        self.validate_report(&report)?;
        let mut text = format!(
            "# {}\n\n{}\n\n## Synthesis and interpretation\n\n{}\n",
            report.title,
            if checked {
                "Source-checked report (AI assessment; limitations below)."
            } else {
                "PARTIAL DRAFT — independent source check is incomplete."
            },
            report.synthesis
        );
        for finding in report.findings {
            let a = self.admission(&finding.admission)?;
            let c = self.candidate(&a.candidate)?;
            let page = self.observed("gather", &c.source, c.offset, &c.quote)?;
            text.push_str(&format!("\n## Finding\n\n{}\n\nQualification: {}. Scope: {}. Limitations: {}\n\n[Source]({}) · {} · period {} · evidence chain {}\nRetained source {} bytes {}..{}; admission {}\n\n> {}\n",a.claim,a.decision,a.scope,a.limitations,page.url,c.publisher,a.period,c.chain,c.source,c.offset,c.offset+c.quote.len()as u64,finding.admission,c.quote.replace('\n',"\n> ")));
            if !finding.interpretation.trim().is_empty() {
                text.push_str(&format!("\nInterpretation: {}\n", finding.interpretation));
            }
        }
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

//! Digest-bound reviewer progress and independent coverage repair requests.
use super::inquiry::{CriterionAnswer, InquiryAnswer, STANDARD};
use super::*;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CitationCheck {
    report_digest: String,
    admission: String,
    approved: bool,
    reason: String,
    corrections: Vec<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Coverage {
    questions: Vec<InquiryAnswer>,
    conclusion: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Followup {
    questions: Vec<usize>,
    reason: String,
    leads: Vec<String>,
}

impl Research {
    pub(super) fn optional<T: DeserializeOwned>(&self, name: &str) -> Result<Option<T>, Error> {
        match self.read(name) {
            Ok(v) => Ok(Some(v)),
            Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
    pub(super) fn coverage_current(&self) -> Result<bool, Error> {
        let Some(saved) = self.optional::<Value>("coverage.json")? else { return Ok(false) };
        if saved["standard"] != STANDARD {
            return Ok(false);
        }
        let coverage: Coverage = decode(&saved["coverage"])?;
        // Only evidence used in the explanation creates assessment dependencies.
        // Unused discovery leads must not invalidate an otherwise checked answer.
        for question in &coverage.questions {
            if self.validate_inquiry(question, true).is_err() {
                return Ok(false);
            }
        }
        Ok(coverage.questions.len() == self.plan()?.questions.len())
    }
    /// A human delivery boundary records unfinished work honestly; it approves no factual claim.
    pub(crate) fn prepare_delivery(&self) -> Result<(), Error> {
        let mut questions = Vec::new();
        for record in self.inquiry_records()? {
            let question = record["requirement"]["question"]
                .as_u64()
                .ok_or_else(|| invalid("invalid inquiry question"))?
                as usize;
            let requirement = self.requirement(question)?;
            let previous = serde_json::from_value::<InquiryAnswer>(record["state"].clone()).ok();
            let mut answers = Vec::new();
            for criterion in 1..=requirement.criteria.len() {
                let answer = previous.as_ref()
                    .and_then(|q|q.answers.iter().find(|a|a.criterion==criterion))
                    .filter(|answer| self.validate_inquiry(
                        &InquiryAnswer{question,assessment:"Validate retained answer at human delivery boundary.".into(),answers:vec![(*answer).clone()]}, false).is_ok())
                    .cloned()
                    .unwrap_or_else(|| CriterionAnswer {
                        criterion,status:"deferred".into(),explanation:"Not established in the current inquiry at the requested drafting boundary. This is unfinished work, not a claim that available evidence was exhausted or that the detail is immaterial.".into(),supports:vec![],contradicts:vec![],gap:String::new(),next_action:String::new()
                    });
                let mut answer = answer;
                if answer.status == "open" {
                    answer.status = "deferred".into();
                    answer.explanation.push_str(" This remains unfinished at the requested delivery boundary; the provisional explanation and evidence are preserved.");
                }
                answers.push(answer);
            }
            questions.push(InquiryAnswer{question,assessment:"Requested draft from current vetted evidence. Retained established answers keep their evidence; deferred criteria explicitly identify unfinished inquiry and limit question completeness.".into(),answers});
        }
        self.save_coverage(&json!({"questions":questions,"conclusion":"Drafting snapshot, not an approval of research adequacy. Synthesis must qualify unfinished questions; the exact report still needs substantive and citation review."}))?;
        Ok(())
    }
    pub(super) fn save_coverage(&self, args: &Value) -> Result<Value, Error> {
        let coverage: Coverage = decode(args)?;
        required(&coverage.conclusion)?;
        let mut questions = BTreeSet::new();
        for q in &coverage.questions {
            self.validate_inquiry(q, true)?;
            if !questions.insert(q.question) {
                return Err(invalid("coverage questions must be unique"));
            }
        }
        if questions.len() != self.plan()?.questions.len() {
            return Err(invalid(
                "Assess coverage of every approved question; request followup for missing reachable evidence",
            ));
        }
        let searches = self.ids("searches/assess")?;
        for q in &coverage.questions {
            self.save_inquiry(&json!(q))?;
        }
        self.save(
            "coverage.json",
            &json!({"standard":STANDARD,"coverage":coverage,"searches":searches}),
        )?;
        Ok(json!({"saved":true,"request_complete":true}))
    }
    pub(super) fn save_followup(&self, stage: &str, args: &Value) -> Result<Value, Error> {
        let request: Followup = decode(args)?;
        required(&request.reason)?;
        if request.questions.is_empty() {
            return Err(invalid("Identify approved questions needing further evidence"));
        }
        for q in &request.questions {
            self.question(*q)?;
        }
        for lead in &request.leads {
            required(lead)?;
        }
        let id = self.record("followups", &json!({"stage":stage,"request":request,"baseline_candidates":self.ids("candidates")?,"baseline_gaps":self.ids("gaps")?}))?;
        self.save("followup.json", &json!({"digest":id}))?;
        Ok(
            json!({"saved":true,"request_complete":true,"followup":id,"next":"Gatherer will investigate these gaps within the unchanged approved plan"}),
        )
    }
    /// Latest saved request for additional evidence; the coordinator checkpoints consumption.
    pub fn followup(&self) -> Result<Option<(String, Value)>, Error> {
        let Some(pointer) = self.optional::<Value>("followup.json")? else { return Ok(None) };
        let id = pointer["digest"].as_str().ok_or_else(|| invalid("invalid followup pointer"))?;
        Ok(Some((id.into(), self.immutable("followups", id)?)))
    }
    fn followup_missing(&self) -> Result<Vec<u64>, Error> {
        let Some((_, request)) = self.followup()? else { return Ok(vec![]) };
        let Some(questions) = request["request"]["questions"].as_array() else {
            return Err(invalid("invalid saved followup questions"));
        };
        let mut addressed = BTreeSet::new();
        for (folder, baseline) in [("candidates", "baseline_candidates"), ("gaps", "baseline_gaps")]
        {
            let Some(before) = request[baseline].as_array() else { continue };
            for id in self.ids(folder)? {
                if before.iter().any(|v| v.as_str() == Some(&id)) {
                    continue;
                }
                let q = if folder == "candidates" {
                    self.candidate(&id)?.question
                } else {
                    self.immutable::<Gap>(folder, &id)?.question
                };
                addressed.insert(q as u64);
            }
        }
        Ok(questions.iter().filter_map(Value::as_u64).filter(|q| !addressed.contains(q)).collect())
    }
    pub(super) fn ensure_followup_addressed(&self) -> Result<(), Error> {
        let missing = self.followup_missing()?;
        if !missing.is_empty() {
            return Err(invalid(format!(
                "The skeptic's followup still needs new evidence or a newly investigated gap for questions {missing:?}; do not finish by reusing the earlier coverage"
            )));
        }
        Ok(())
    }
    pub(super) fn check(&self, report: &str, admission: &str) -> Result<Option<Value>, Error> {
        check_id(report)?;
        check_id(admission)?;
        self.optional(&format!("checks/{report}/{admission}.json"))
    }
    pub(super) fn save_check(&self, args: &Value) -> Result<Value, Error> {
        let check: CitationCheck = decode(args)?;
        let (id, report) = self.current_report()?;
        if check.report_digest != id
            || !report.findings.iter().any(|f| f.admission == check.admission)
        {
            return Err(invalid(
                "citation check must bind a cited admission in the exact current report",
            ));
        }
        required(&check.reason)?;
        if check.approved && !check.corrections.is_empty()
            || !check.approved && check.corrections.is_empty()
        {
            return Err(invalid(
                "An approved check has no corrections; a failed check needs concrete corrections",
            ));
        }
        for correction in &check.corrections {
            required(correction)?;
        }
        let admission = self.admission(&check.admission)?;
        let candidate = self.candidate(&admission.candidate)?;
        self.observed("fact-check", &candidate.source, candidate.offset, &candidate.quote)?;
        self.save(&format!("checks/{id}/{}.json", check.admission), &check)?;
        Ok(
            json!({"saved":true,"report_digest":id,"admission":check.admission,"next":"Inspect progress; check remaining citations, then save research_review. Saved checks do not need repeated reads."}),
        )
    }
    pub(super) fn progress(&self, stage: &str) -> Result<Value, Error> {
        let candidates = self.ids("candidates")?;
        let mut pending = Vec::new();
        let mut covered = BTreeSet::new();
        for id in &candidates {
            covered.insert(self.candidate(id)?.question);
            if !self.assessment_current(id)? {
                pending.push(id);
            }
        }
        for id in self.ids("gaps")? {
            covered.insert(self.immutable::<Gap>("gaps", &id)?.question);
        }
        let mut value = json!({"stage":stage,"candidate_count":candidates.len(),"pending_assessments":pending,"covered_questions":covered,"coverage_current":self.coverage_current()?,"independent_searches":self.ids(&format!("searches/{stage}"))?.len(),"review_available":self.optional::<Value>("review.json")?.is_some()});
        value["controversy_sweep_available"] =
            json!(self.optional::<Value>("controversy-sweep.json")?.is_some());
        value["research_standard"] = json!(STANDARD);
        value["assessment_queue_is_optional"] = json!(true);
        value["selection_guidance"] = json!(
            "Use admission_index/candidate_index to select evidence useful to an early draft, then research_item for exact scope. Pending discoveries are optional leads, not mandatory assessment debt. Further research must resolve a consequential defect in the actual answer."
        );
        if self.optional::<Value>("plan.json")?.is_some() {
            value["inquiry"] = json!(self.inquiry_frontier()?);
        }
        let followup = self.followup()?;
        value["coverage_mode"] =
            json!(if followup.is_some() { "followup_resolution" } else { "initial_coverage" });
        value["initial_omission_search_complete"] = json!(!self.ids("searches/assess")?.is_empty());
        value["completion_criterion"] = json!(
            "Establish an evidence-grounded explanation that answers the approved substantive criteria. For controversies establish specific accusations, attribution, responses and documented outcomes without deciding guilt. Citation accuracy, attributed self-reports and caveats alone do not establish investigative adequacy. Trace source interests/dependencies, test consequential claims against external observations, and pursue material competing accounts. Report length is presentation, not an investigation budget. Stop when core questions are answered or genuinely investigated limits are established; avoid unrelated optional expansion."
        );
        if let Some((id, request)) = followup {
            value["followup"] = json!({"digest":id,"questions":request["request"]["questions"],"reason":request["request"]["reason"],"missing_new_evidence_or_gap":self.followup_missing()?,"next_action":if stage=="gather" {"Investigate only the requested material concerns. Finish once each has new evidence or an investigated gap; do not expand the task."}else{"Reassess additions and resolve the saved request against current admitted evidence and explicit limits. Do not restart broad discovery without a specific new blocking concern. Save adequate coverage, retaining optional leads separately."}});
        }
        if self.optional::<Value>("report.json")?.is_some() {
            let (id, report) = self.current_report()?;
            let mut checks = Vec::new();
            for f in &report.findings {
                let a = self.admission(&f.admission)?;
                let c = self.candidate(&a.candidate)?;
                checks.push(json!({"admission":f.admission,"source":c.source,"offset":c.offset,"max_bytes":c.quote.len().max(4),"passage_read":self.observed("fact-check",&c.source,c.offset,&c.quote).is_ok(),"judgment":self.check(&id,&f.admission)?.map(|v|v["approved"].clone())}));
            }
            let all_checked = checks.iter().all(|c| !c["judgment"].is_null());
            value["report_digest"] = json!(id);
            value["reviewed"] =
                json!(report.findings.iter().map(|f| &f.admission).collect::<Vec<_>>());
            value["citations"] = json!(checks);
            value["next_action"] = json!(if all_checked {
                "All citation judgments are saved. Submit research_review now, approving only if the report and coverage are sound. A missing review is your output to create, not a dependency to wait for."
            } else {
                "For each pending citation: research_item, web_read its exact passage if not yet read, then research_check. Save judgments as you go; do not reread completed checks."
            });
        }
        Ok(value)
    }
    pub(super) fn item(&self, stage: &str, args: &Value) -> Result<Value, Error> {
        let id = args["id"]
            .as_str()
            .ok_or_else(|| invalid("research_item needs an exact candidate/admission id"))?;
        check_id(id)?;
        if self.ids("admissions")?.iter().any(|i| i == id) {
            let a = self.admission(id)?;
            if stage == "write" && (a.decision == "rejected" || a.provenance.is_none()) {
                return Err(invalid("rejected evidence is unavailable to synthesis"));
            }
            let c = self.candidate(&a.candidate)?;
            if self
                .optional::<Value>(&format!("decisions/{}.json", a.candidate))?
                .is_none_or(|v| v["admission"] != id)
            {
                return Err(invalid("admission is not the current assessment"));
            }
            Ok(
                json!({"admission":id,"assessment":a,"candidate":c,"read_arguments":{"source":c.source,"offset":c.offset,"max_bytes":c.quote.len().max(4)}}),
            )
        } else {
            if stage == "write" {
                return Err(invalid(
                    "synthesis may inspect only current admitted/qualified evidence",
                ));
            }
            let c = self.candidate(id)?;
            Ok(
                json!({"candidate":id,"record":c,"decision":self.optional::<Value>(&format!("decisions/{id}.json"))?,"read_arguments":{"source":c.source,"offset":c.offset,"max_bytes":c.quote.len().max(4)}}),
            )
        }
    }
}

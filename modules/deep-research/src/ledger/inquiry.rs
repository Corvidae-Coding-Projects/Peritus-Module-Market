//! Investigative obligations, interested-source provenance and evidence-backed explanations.
use super::*;

pub(super) const STANDARD: u64 = 2;

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(super) enum EvidenceNeed {
    DeclaredPosition,
    Specification,
    IndependentAssessment,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InquiryRequirement {
    pub question: usize,
    pub evidence_need: EvidenceNeed,
    pub criteria: Vec<String>,
}

#[derive(Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Relationship {
    Subject,
    Affiliated,
    External,
    Unclear,
}

#[derive(Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Account {
    SelfReport,
    AttributedStatement,
    Observation,
    Argument,
    Specification,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProvenancePassage {
    source: String,
    offset: u64,
    quote: String,
    establishes: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Provenance {
    relationship: Relationship,
    account: Account,
    pub(super) basis: String,
    pub(super) dependencies: Vec<String>,
    checked_passages: Vec<ProvenancePassage>,
}

impl Provenance {
    pub(super) fn label(&self) -> &'static str {
        if self.account == Account::AttributedStatement {
            return match self.relationship {
                Relationship::Subject => "attribution only; subject's statement",
                Relationship::Affiliated => "attribution only; affiliated speaker",
                Relationship::External => "attribution only; external speaker",
                Relationship::Unclear => "attribution only; relationship not established",
            };
        }
        match self.relationship {
            Relationship::Subject => "subject's own account",
            Relationship::Affiliated => "affiliated source",
            Relationship::External => {
                if self.account == Account::SelfReport {
                    "external publisher quoting a self-report"
                } else {
                    "external evidence or analysis"
                }
            }
            Relationship::Unclear => "source relationship not established",
        }
    }
    fn assessment_credit(&self) -> bool {
        // Attribution establishes that a statement was made, never the underlying conduct.
        self.account == Account::AttributedStatement
            || self.relationship == Relationship::External
                && matches!(self.account, Account::Observation | Account::Argument)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CriterionAnswer {
    pub criterion: usize,
    pub status: String,
    pub explanation: String,
    pub supports: Vec<String>,
    pub contradicts: Vec<String>,
    pub gap: String,
    pub next_action: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InquiryAnswer {
    pub question: usize,
    pub assessment: String,
    pub answers: Vec<CriterionAnswer>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Conclusion {
    pub question: usize,
    pub claim: String,
    pub reasoning: String,
    pub supports: Vec<String>,
    pub contradicts: Vec<String>,
    pub alternatives: Vec<String>,
    pub confidence: String,
    pub uncertainties: Vec<String>,
}

impl Research {
    pub(super) fn assessment_current(&self, candidate: &str) -> Result<bool, Error> {
        let Some(pointer) = self.optional::<Value>(&format!("decisions/{candidate}.json"))? else {
            return Ok(false);
        };
        let id =
            pointer["admission"].as_str().ok_or_else(|| invalid("invalid assessment pointer"))?;
        Ok(self.admission(id)?.provenance.is_some())
    }

    pub(super) fn requirement(&self, question: usize) -> Result<InquiryRequirement, Error> {
        self.question(question)?;
        let plan = self.plan()?;
        Ok(plan.investigation.into_iter().find(|r| r.question == question).unwrap_or_else(|| {
            InquiryRequirement {
                question,
                evidence_need: EvidenceNeed::IndependentAssessment,
                criteria: vec![plan.questions[question - 1].clone()],
            }
        }))
    }

    pub(super) fn validate_requirements(plan: &Plan) -> Result<(), Error> {
        let mut seen = BTreeSet::new();
        for r in &plan.investigation {
            if r.question == 0 || r.question > plan.questions.len() || !seen.insert(r.question) {
                return Err(invalid("investigation must map each approved question exactly once"));
            }
            if r.criteria.is_empty() {
                return Err(invalid(
                    "Each question needs substantive answer criteria, not a source-count target",
                ));
            }
            for criterion in &r.criteria {
                required(criterion)?;
            }
        }
        if seen.len() != plan.questions.len() {
            return Err(invalid(
                "Plan investigation must include evidence_need and answer criteria for every question",
            ));
        }
        Ok(())
    }

    pub(super) fn validate_provenance(
        &self,
        admission: &Admission,
        candidate: &Candidate,
    ) -> Result<(), Error> {
        let Some(p) = &admission.provenance else {
            return Err(invalid(
                "Assess source provenance: relationship, account, dependencies and actually checked provenance passages are missing",
            ));
        };
        required(&p.basis)?;
        for dependency in &p.dependencies {
            required(dependency)?;
        }
        for passage in &p.checked_passages {
            required(&passage.establishes)?;
            self.observed("assess", &passage.source, passage.offset, &passage.quote)?;
        }
        if p.account == Account::AttributedStatement
            && (admission.decision != "qualified" || p.checked_passages.is_empty())
        {
            return Err(invalid(
                "An attributed_statement requires qualified scope and an actually read passage establishing the original statement/authenticity. It establishes what was said, not whether alleged conduct occurred.",
            ));
        }
        if p.relationship == Relationship::External && p.checked_passages.is_empty() {
            return Err(invalid(
                "External-source credit needs an actually read provenance passage and a claim-specific independence basis; publisher name alone is insufficient",
            ));
        }
        // Being the original speaker does not establish a relationship to the
        // investigated subject. Narrow attribution is validated above and must
        // preserve that separate, potentially unknown relationship.
        if candidate.category == "first-party"
            && p.account != Account::AttributedStatement
            && (!matches!(p.relationship, Relationship::Subject | Relationship::Affiliated)
                || !matches!(p.account, Account::SelfReport | Account::Specification))
        {
            return Err(invalid(
                "First-party claims remain subject/affiliated self-reports, attributed statements or specifications, including when a journalist quotes them",
            ));
        }
        if matches!(
            p.relationship,
            Relationship::Subject | Relationship::Affiliated | Relationship::Unclear
        ) && admission.decision == "admitted"
        {
            return Err(invalid(
                "Interested or uncertain-source evidence requires qualified attribution; it cannot alone establish an independent assessment",
            ));
        }
        Ok(())
    }

    pub(super) fn checked_gap(&self, gap: &Gap) -> Result<(), Error> {
        required(&gap.reason)?;
        if gap.attempts.is_empty() {
            return Err(invalid(
                "An investigated gap must identify actual alternative search queries attempted, not only a caveat or lack of time",
            ));
        }
        let mut observed = BTreeSet::new();
        for stage in ["gather", "controversies", "assess", "fact-check"] {
            for id in self.ids(&format!("searches/{stage}"))? {
                let record: Value = self.immutable(&format!("searches/{stage}"), &id)?;
                if let Some(query) = record["query"].as_str() {
                    observed.insert(query.to_owned());
                }
            }
        }
        if gap.attempts.iter().any(|q| !observed.contains(q)) {
            return Err(invalid("Gap attempts must exactly name actual saved web_search queries"));
        }
        Ok(())
    }

    fn evidence_credit(&self, id: &str, question: usize) -> Result<bool, Error> {
        let admission = self.admission(id)?;
        self.question(question)?;
        // Discovery tags organize leads; evidence can inform several approved questions.
        // The answer/conclusion must explain relevance, and the current admission remains authoritative.
        if admission.decision == "rejected" {
            return Err(invalid(
                "Inquiry evidence must address this question and be currently admitted/qualified",
            ));
        }
        let current: Value = self.read(&format!("decisions/{}.json", admission.candidate))?;
        if current["admission"] != id {
            return Err(invalid("Inquiry cites a superseded assessment"));
        }
        Ok(admission.provenance.as_ref().is_some_and(Provenance::assessment_credit))
    }

    pub(super) fn validate_inquiry(
        &self,
        inquiry: &InquiryAnswer,
        complete: bool,
    ) -> Result<(), Error> {
        let requirement = self.requirement(inquiry.question)?;
        required(&inquiry.assessment)?;
        let mut seen = BTreeSet::new();
        for answer in &inquiry.answers {
            if answer.criterion == 0
                || answer.criterion > requirement.criteria.len()
                || !seen.insert(answer.criterion)
            {
                return Err(invalid(
                    "Inquiry answers must reference unique 1-based criteria from the approved plan",
                ));
            }
            required(&answer.explanation)?;
            let mut ids = BTreeSet::new();
            let mut external_support = false;
            for id in &answer.supports {
                if !ids.insert(id) {
                    return Err(invalid("Duplicate inquiry evidence"));
                }
                external_support |= self.evidence_credit(id, inquiry.question)?;
            }
            for id in &answer.contradicts {
                if !ids.insert(id) {
                    return Err(invalid(
                        "The same evidence cannot both support and contradict the same answer",
                    ));
                }
                self.evidence_credit(id, inquiry.question)?;
            }
            match answer.status.as_str() {
                "answered" => {
                    if answer.supports.is_empty() {
                        return Err(invalid(
                            "An answered criterion needs evidence supporting its substantive explanation",
                        ));
                    }
                    if requirement.evidence_need == EvidenceNeed::IndependentAssessment
                        && !external_support
                    {
                        return Err(invalid(
                            "This question requires independent assessment. Qualified subject/affiliate accounts or uncertain provenance do not answer it. Investigate external evidence, use authenticated attributed_statement solely for what was said, or retain an actually investigated unresolved gap.",
                        ));
                    }
                }
                "unresolved" => {
                    let gap: Gap = self.immutable("gaps", &answer.gap)?;
                    self.checked_gap(&gap)?;
                }
                "deferred" => {
                    // An explicit scope decision is not a claim that research exhausted this lead.
                    // Such a criterion cannot justify a fully answered question.
                }
                "open" if !complete => {
                    required(&answer.next_action)?;
                }
                _ => {
                    return Err(invalid(
                        "Coverage needs answered, investigated unresolved, or explicitly deferred criteria; explain scope deferrals honestly without claiming exhausted research",
                    ));
                }
            }
        }
        if complete && seen.len() != requirement.criteria.len() {
            return Err(invalid(
                "Address every approved answer criterion; citation presence is not question coverage",
            ));
        }
        Ok(())
    }

    pub(super) fn save_inquiry(&self, args: &Value) -> Result<Value, Error> {
        let inquiry: InquiryAnswer = decode(args)?;
        self.validate_inquiry(&inquiry, false)?;
        let id = self.record("inquiries", &inquiry)?;
        self.save(&format!("inquiry/{}.json", inquiry.question), &json!({"digest":id}))?;
        Ok(
            json!({"saved":true,"inquiry":id,"next":"Investigate material open questions; this saves the evolving explanation without completing the stage"}),
        )
    }

    pub(super) fn inquiry_records(&self) -> Result<Vec<Value>, Error> {
        let mut records = Vec::new();
        for question in 1..=self.plan()?.questions.len() {
            let requirement = self.requirement(question)?;
            let pointer = self.optional::<Value>(&format!("inquiry/{question}.json"))?;
            let state = match pointer {
                Some(p) => self.immutable::<Value>(
                    "inquiries",
                    p["digest"].as_str().ok_or_else(|| invalid("invalid inquiry pointer"))?,
                )?,
                None => Value::Null,
            };
            records.push(json!({"requirement":requirement,"state":state}));
        }
        Ok(records)
    }

    pub(super) fn inquiry_frontier(&self) -> Result<Vec<Value>, Error> {
        Ok(self.inquiry_records()?.into_iter().map(|v|json!({"requirement":v["requirement"],"answers":v["state"]["answers"].as_array().map(|answers|answers.iter().map(|a|json!({"criterion":a["criterion"],"status":a["status"],"next_action":a["next_action"]})).collect::<Vec<_>>())})).collect())
    }

    pub(super) fn question_answered(&self, question: usize) -> Result<bool, Error> {
        let Some(coverage) = self.optional::<Value>("coverage.json")? else { return Ok(false) };
        if coverage["standard"] != STANDARD {
            return Ok(false);
        }
        Ok(coverage["coverage"]["questions"]
            .as_array()
            .and_then(|questions| questions.iter().find(|q| q["question"] == question))
            .and_then(|q| q["answers"].as_array())
            .is_some_and(|answers| {
                !answers.is_empty() && answers.iter().all(|a| a["status"] == "answered")
            }))
    }

    pub(super) fn validate_conclusions(&self, report: &Report) -> Result<(), Error> {
        if report.conclusions.is_empty() {
            return Err(invalid(
                "Report must explain its substantive conclusions, supporting/contrary evidence, alternatives and uncertainty; a citation catalog is insufficient",
            ));
        }
        let cited = report.findings.iter().map(|f| f.admission.as_str()).collect::<BTreeSet<_>>();
        let mut questions = BTreeSet::new();
        for (index, conclusion) in report.conclusions.iter().enumerate() {
            self.question(conclusion.question)?;
            questions.insert(conclusion.question);
            required(&conclusion.claim)?;
            required(&conclusion.reasoning)?;
            if !matches!(conclusion.confidence.as_str(), "high" | "moderate" | "low" | "unresolved")
            {
                return Err(invalid(
                    "Conclusion confidence must be high, moderate, low or unresolved",
                ));
            }
            let mut external = false;
            for id in &conclusion.supports {
                if !cited.contains(id.as_str()) {
                    return Err(invalid(
                        "Conclusion evidence must be included in the report's actual source findings",
                    ));
                }
                external |= self.evidence_credit(id, conclusion.question)?;
            }
            for id in &conclusion.contradicts {
                if !cited.contains(id.as_str()) {
                    return Err(invalid("Contrary evidence must remain cited and visible"));
                }
                external |= self.evidence_credit(id, conclusion.question)?;
            }
            if conclusion.confidence != "unresolved" && conclusion.supports.is_empty() {
                return Err(invalid(
                    "A substantive conclusion needs supporting evidence or unresolved confidence",
                ));
            }
            if self.requirement(conclusion.question)?.evidence_need
                == EvidenceNeed::IndependentAssessment
                && !external
                && matches!(conclusion.confidence.as_str(), "high" | "moderate")
            {
                return Err(invalid(format!(
                    "Conclusion {} (question {}): high/moderate confidence in an independent assessment needs relevant independent evidence across its supporting and contrary record. A source may support the existence of an attributed allegation without establishing the underlying conduct; preserve that scope and explain its evidentiary function.",
                    index + 1,
                    conclusion.question
                )));
            }
            for note in conclusion.alternatives.iter().chain(&conclusion.uncertainties) {
                required(note)?;
            }
        }
        if questions.len() != self.plan()?.questions.len() {
            return Err(invalid(
                "Explain the result or investigated uncertainty for every inquiry question",
            ));
        }
        Ok(())
    }
}

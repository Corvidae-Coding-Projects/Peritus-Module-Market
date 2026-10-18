use super::*;

impl Research {
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
        if request.kind == "progress" {
            return self.progress(stage);
        }
        if request.kind == "plan" {
            if self.optional::<Value>("plan.json")?.is_none() {
                return Ok(
                    json!({"available":false,"next_action":"Save research_plan; no plan exists yet"}),
                );
            }
            return Ok(
                json!({"plan":self.plan()?,"digest":self.plan_digest()?,"approved":self.approved()?}),
            );
        }
        if request.kind == "inquiry" {
            if self.optional::<Value>("plan.json")?.is_none() {
                return Ok(
                    json!({"available":false,"next_action":"Save the research plan and answer criteria before investigating"}),
                );
            }
            let records = self.inquiry_records()?;
            let mut page = records
                .iter()
                .skip(request.offset)
                .take(request.max_items.clamp(1, 32))
                .cloned()
                .collect::<Vec<_>>();
            trim_page(&mut page)?;
            return Ok(
                json!({"total":records.len(),"records":page,"next_offset":(request.offset+page.len()<records.len()).then_some(request.offset+page.len())}),
            );
        }
        if request.kind == "report" {
            if self.optional::<Value>("report.json")?.is_none() {
                return Ok(
                    json!({"available":false,"next_action":"Synthesis must save research_report before there is a report"}),
                );
            }
            let (id, report) = self.current_report()?;
            if stage == "fact-check" {
                self.save(
                    &format!("report-reads/fact-check-{id}.json"),
                    &json!({"report_digest":id}),
                )?;
            }
            return Ok(json!({"report_digest":id,"report":report}));
        }
        if request.kind == "controversies" {
            let Some(pointer) = self.optional::<Value>("controversy-sweep.json")? else {
                return Ok(
                    json!({"available":false,"next_action":"The dedicated researcher has not saved a handoff yet"}),
                );
            };
            let id = pointer["digest"]
                .as_str()
                .ok_or_else(|| invalid("invalid controversy handoff pointer"))?;
            return Ok(
                json!({"digest":id,"handoff":self.immutable::<Value>("controversy-sweeps",id)?}),
            );
        }
        if request.kind == "review" {
            if self.optional::<Value>("review.json")?.is_none() {
                return Ok(
                    json!({"available":false,"next_action":"No final review has been submitted. The fact-checker creates it with research_review after saving citation checks; it is not an external dependency."}),
                );
            }
            return Ok(json!(self.current_review()?));
        }
        if matches!(request.kind.as_str(), "admission_index" | "candidate_index") {
            let mut records = Vec::new();
            if request.kind == "admission_index" {
                for (id, admission) in self.active_admissions()? {
                    if stage == "write"
                        && (admission.decision == "rejected" || admission.provenance.is_none())
                    {
                        continue;
                    }
                    let candidate = self.candidate(&admission.candidate)?;
                    records.push(json!({"admission":id,"candidate":admission.candidate,
                        "question":candidate.question,"claim":admission.claim,
                        "decision":admission.decision,"scope":admission.scope,"limitations":admission.limitations,"source":candidate.source,
                        "source_role":admission.provenance.as_ref().map(|p|p.label())}));
                }
            } else {
                if stage == "write" {
                    return Err(invalid("Unassessed candidates are unavailable to synthesis"));
                }
                for id in self.ids("candidates")? {
                    let candidate = self.candidate(&id)?;
                    records.push(json!({"candidate":id,"question":candidate.question,
                        "claim":candidate.claim,"origin_stage":candidate.origin_stage,"category":candidate.category,"source":candidate.source,
                        "assessment":self.optional::<Value>(&format!("decisions/{id}.json"))?}));
                }
            }
            let total = records.len();
            let mut page = records
                .into_iter()
                .skip(request.offset)
                .take(request.max_items.clamp(1, 32))
                .collect::<Vec<_>>();
            trim_page(&mut page)?;
            return Ok(
                json!({"total":total,"records":page,"detail":"Use research_item with a selected admission/candidate ID for exact evidence and scope; this index is navigation, not a source check.","next_offset":(request.offset+page.len()<total).then_some(request.offset+page.len())}),
            );
        }
        if request.kind == "admissions" {
            let records = self
                .active_admissions()?
                .into_iter()
                .filter(|(_, a)| {
                    stage != "write" || (a.decision != "rejected" && a.provenance.is_some())
                })
                .collect::<Vec<_>>();
            let mut page=records.iter().skip(request.offset).take(request.max_items.clamp(1,32)).map(|(id,a)|Ok(json!({"admission":id,"assessment":a,"candidate":self.candidate(&a.candidate)?}))).collect::<Result<Vec<_>,Error>>()?;
            trim_page(&mut page)?;
            return Ok(
                json!({"total":records.len(),"records":page,"next_offset":(request.offset+page.len()<records.len()).then_some(request.offset+page.len())}),
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
        trim_page(&mut records)?;
        Ok(
            json!({"total":ids.len(),"records":records,"next_offset":(request.offset+records.len()<ids.len()).then_some(request.offset+records.len())}),
        )
    }
}

// Bound each serialized projection, not the durable investigation or total records.
fn trim_page(records: &mut Vec<Value>) -> Result<(), Error> {
    while records.len() > 1 && serde_json::to_vec(records)?.len() > 12 * 1024 {
        records.pop();
    }
    Ok(())
}

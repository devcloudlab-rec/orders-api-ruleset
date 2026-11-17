package main

import rego.v1

# Every organization ruleset must protect the default branch of all repositories
# with reviews, checks and history rules, and must not allow bypass.

rule_types := {r.type | some r in input.rules}

deny contains msg if {
	input.enforcement != "active"
	msg := sprintf("enforcement must be active, found %s", [input.enforcement])
}

deny contains msg if {
	count(input.bypass_actors) > 0
	msg := "bypass_actors must be empty"
}

deny contains msg if {
	some required in {"required_status_checks", "pull_request", "non_fast_forward", "deletion"}
	not required in rule_types
	msg := sprintf("missing rule: %s", [required])
}

deny contains msg if {
	some r in input.rules
	r.type == "pull_request"
	r.parameters.required_approving_review_count < 1
	msg := "pull_request must require at least one approval"
}

deny contains msg if {
	some r in input.rules
	r.type == "pull_request"
	not r.parameters.require_code_owner_review
	msg := "pull_request must require code owner review"
}

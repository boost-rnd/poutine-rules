# METADATA
# title: Cache Poisoning
# custom:
#   level: warning
# related_resources:
# - ref: https://adnanthekhan.com/2024/05/06/the-monsters-in-your-build-cache-github-actions-cache-poisoning/
#   description: The Monsters in Your Build Cache – GitHub Actions Cache Poisoning
package rules.cache_poisoning

import data.poutine
import data.poutine.utils
import rego.v1

rule := poutine.rule(rego.metadata.chain())

github.caching_actions contains "actions/setup-go"

has_action_with_cache(workflow, action) if {
	step := workflow.jobs[_].steps[_]
	step.action == action
	not utils.step_args(step).cache
}

has_action_with_cache(workflow, action) if {
	step := workflow.jobs[_].steps[_]
	step.action == action
	utils.step_args(step).cache == "true"
}

results contains poutine.finding(rule, pkg.purl, {"path": workflow.path, "details": details}) if {
	action := github.caching_actions[_]
	pkg := input.packages[_]
	workflow := pkg.github_actions_workflows[_]

	utils.filter_workflow_events(workflow, {"pull_request_target"})
	count(utils.find_pr_checkouts(workflow)) > 0
	has_action_with_cache(workflow, action)

	release_workflows_paths = [w.path |
		w := pkg.github_actions_workflows[_]
		w.path != workflow.path
		has_action_with_cache(w, action)
		utils.filter_workflow_events(w, {
			"push",
			"release",
			"schedule",
			"workflow_dispatch",
			"merge_group",
		})
	]

	count(release_workflows_paths) > 0

	details := sprintf("could poison the cache of workflows: %s", [concat(", ", release_workflows_paths)])
}

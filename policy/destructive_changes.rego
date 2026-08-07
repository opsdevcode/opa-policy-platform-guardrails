# Terraform plan policy: block destructive deletes without replacement.
package main

# rego.v1 keeps one syntax valid on both OPA 0.59+ and OPA 1.x, where `if` and
# `contains` became mandatory.
import rego.v1

deny contains msg if {
	change := input.resource_changes[_]
	change.change.actions[_] == "delete"
	not create_in_actions(change.change.actions)
	msg := sprintf("destructive delete without replacement: %s", [change.address])
}

create_in_actions(actions) if {
	actions[_] == "create"
}

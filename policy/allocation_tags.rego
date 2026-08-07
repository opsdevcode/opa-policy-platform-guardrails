# Terraform plan policy: resources with tags must include FinOps allocation keys.
package main

import rego.v1

required_allocation_keys := {"Owner", "Service", "Environment", "CostCenter"}

_object_has_allocation_tags(tags) if {
	every key in required_allocation_keys {
		tags[key]
	}
}

_array_tag_key(entry) := key if {
	parts := split(entry, ":")
	count(parts) >= 2
	key := parts[0]
}

_array_has_allocation_tags(tags) if {
	found := {key | some entry in tags; key := _array_tag_key(entry)}
	required_allocation_keys == found
}

_has_allocation_tags(tags) if {
	is_object(tags)
	_object_has_allocation_tags(tags)
}

_has_allocation_tags(tags) if {
	is_array(tags)
	_array_has_allocation_tags(tags)
}

deny contains msg if {
	change := input.resource_changes[_]
	tags := change.change.after.tags
	tags
	not _has_allocation_tags(tags)
	msg := sprintf("%s missing required allocation tags (Owner, Service, Environment, CostCenter)", [change.address])
}

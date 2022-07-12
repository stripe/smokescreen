package versioninfo

import "strings"

// Short provides a short string summarizing available version information.
func Short() string {
	parts := make([]string, 0, 3)
	if Version != "unknown" && Version != "(devel)" {
		parts = append(parts, Version)
	}
	if Revision != "unknown" && Revision != "" {
		parts = append(parts, "rev")
		commit := Revision
		if len(commit) > 7 {
			commit = commit[:7]
		}
		parts = append(parts, commit)
		if DirtyBuild {
			parts = append(parts, "dirty")
		}
	}
	if len(parts) == 0 {
		return "devel"
	}
	return strings.Join(parts, "-")
}

package acl

import (
	"errors"
	"fmt"
	"strings"

	"github.com/stripe/smokescreen/v2/pkg/smokescreen/hostport"
	"golang.org/x/net/publicsuffix"
)

// ValidateDomainGlob takes a domain glob and verifies they conform to smokescreen's
// domain glob policy.
//
// Only a single wildcard per glob is allowed, in one of these forms:
//
//   - A leading "*." matches one or more subdomain labels (e.g., "*.example.com").
//   - A "*" spanning a label other than the leftmost one matches exactly one label
//     (e.g., "access-analyzer.*.amazonaws.com").
//   - A "*" after a literal prefix within a label matches one or more characters
//     within that label (e.g., "api*.example.com" or "web*-canary.example.com").
//
// Wildcards other than the leading "*." never cross a ".". The labels to the right
// of such a wildcard must be literal and form a registrable domain, so the wildcard
// can't reach into a public suffix such as "com", "co.uk", or "github.io". See
// HostMatchesGlob for how matches that cross into another registrable domain are
// handled.
//
// Globs must include text after a wildcard, and domains must use their normalized
// form (e.g., Punycode).
func ValidateDomainGlob(svc string, glob string) error {
	if glob == "" {
		return fmt.Errorf("glob cannot be empty")
	}

	if glob == "*" || glob == "*." {
		return fmt.Errorf("%v: %v: domain glob must not match everything", svc, glob)
	}

	if strings.Count(glob, "*") > 1 {
		return fmt.Errorf("%v: %v: only one wildcard is allowed per domain glob", svc, glob)
	}

	if !strings.HasPrefix(glob, "*.") && strings.Contains(glob, "*") {
		return validateLabelWildcardGlob(svc, glob)
	}

	// Extract domain part for validation (remove wildcard prefix if present)
	domainToCheck := strings.TrimPrefix(glob, "*.")

	normalizedDomain, err := hostport.NormalizeHost(domainToCheck, false)

	if err != nil {
		return fmt.Errorf("%v: %v: incorrect ACL entry: %v", svc, glob, err)
		// There was no error but the config contains a non-normalized form
	} else if normalizedDomain != domainToCheck {
		if strings.HasPrefix(glob, "*.") {
			// (Re-add) wildcard if one was provided (for the error message)
			normalizedDomain = "*." + normalizedDomain
		}
		return fmt.Errorf("%v: %v: incorrect ACL entry; use %q", svc, glob, normalizedDomain)
	}
	return nil
}

// validateLabelWildcardGlob validates a glob whose single wildcard sits inside a
// label (e.g., "api*.example.com"), as opposed to a leading "*." wildcard.
func validateLabelWildcardGlob(svc string, glob string) error {
	g, err := parseLabelWildcardGlob(glob)
	if err == nil {
		_, err = g.check()
	}
	if err != nil {
		return fmt.Errorf("%v: %v: %v", svc, glob, err)
	}
	return nil
}

// labelWildcardGlob is a domain glob whose single wildcard sits inside a label.
type labelWildcardGlob struct {
	labels []string // the glob's labels, without a trailing dot
	idx    int      // index of the label containing the wildcard
	prefix string   // literal text before the wildcard in labels[idx]
	suffix string   // literal text after the wildcard in labels[idx]
}

// parseLabelWildcardGlob parses glob and runs the validation checks that only
// need string operations. Callers must also call check, which is more expensive.
func parseLabelWildcardGlob(glob string) (labelWildcardGlob, error) {
	if strings.Count(glob, "*") != 1 {
		return labelWildcardGlob{}, errors.New("only one wildcard is allowed per domain glob")
	}
	labels := strings.Split(strings.TrimSuffix(glob, "."), ".")
	idx := -1
	for i, l := range labels {
		if l == "" {
			return labelWildcardGlob{}, errors.New("domain glob must not contain empty labels")
		}
		if strings.Contains(l, "*") {
			idx = i
		}
	}

	label := labels[idx]
	prefix, suffix, _ := strings.Cut(label, "*")
	// A leftmost whole-label wildcard is the leading "*." form, which isn't a label
	// wildcard. A leading "*" glued to a label is most likely a typo for "*." (e.g.,
	// "*bob.example.com" for "*.bob.example.com"), so require a literal prefix.
	if prefix == "" && (suffix != "" || idx == 0) {
		return labelWildcardGlob{}, errors.New("domain glob must represent a full prefix (sub)domain")
	}
	if strings.HasPrefix(label, "xn--") {
		return labelWildcardGlob{}, errors.New("wildcards are not supported in Punycode labels")
	}
	for _, r := range prefix + suffix {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return labelWildcardGlob{}, errors.New("wildcard label may only contain lowercase ASCII letters, digits, '-' and '_'")
		}
	}
	// The wildcard matches at least one character.
	if len(label) > 63 {
		return labelWildcardGlob{}, errors.New("wildcard label can never match a label of at most 63 characters")
	}

	if idx == len(labels)-1 {
		return labelWildcardGlob{}, errors.New("wildcard must not be in the top-level domain")
	}
	if strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return labelWildcardGlob{}, errors.New("domain glob must not match IP addresses")
	}
	return labelWildcardGlob{labels: labels, idx: idx, prefix: prefix, suffix: suffix}, nil
}

// check runs the validation checks that need normalization or the public suffix
// list, and returns the registrable domain of the labels after the wildcard.
func (g labelWildcardGlob) check() (string, error) {
	rest := strings.Join(g.labels[g.idx+1:], ".")
	parts := []string{rest}
	if g.idx > 0 {
		parts = append(parts, strings.Join(g.labels[:g.idx], "."))
	}
	for _, part := range parts {
		normalized, err := hostport.NormalizeHost(part, false)
		if err != nil {
			return "", fmt.Errorf("incorrect ACL entry: %v", err)
		}
		if normalized != part {
			return "", fmt.Errorf("incorrect ACL entry; %q must be in normalized form %q", part, normalized)
		}
	}

	// A wildcard directly under a public suffix would span registrable domains owned
	// by unrelated parties (e.g., "foo*.com" or "foo*.github.io").
	registrable, err := publicsuffix.EffectiveTLDPlusOne(rest)
	if err != nil {
		return "", errors.New("wildcard label must be followed by a registrable domain, not a public suffix")
	}
	// Reject globs whose wildcard sits under a wildcard public suffix rule (e.g.,
	// "*.compute.amazonaws.com"), since they could never match.
	example := strings.Replace(strings.Join(g.labels, "."), "*", "x", 1)
	if r, err := publicsuffix.EffectiveTLDPlusOne(example); err != nil || r != registrable {
		return "", errors.New("wildcard must not match a public suffix")
	}
	return registrable, nil
}

// matchLabels reports whether hostLabels, the labels of a normalized host, match
// g's labels.
func (g labelWildcardGlob) matchLabels(hostLabels []string) bool {
	if len(hostLabels) != len(g.labels) {
		return false
	}
	for i, gl := range g.labels {
		hl := hostLabels[i]
		if i != g.idx {
			if hl != gl {
				return false
			}
		} else if len(hl) <= len(g.prefix)+len(g.suffix) || !strings.HasPrefix(hl, g.prefix) || !strings.HasSuffix(hl, g.suffix) {
			return false
		}
	}
	return true
}

// HostMatchesGlob matches a hostname string against a domain glob after
// converting both to a canonical form (punycode normalization, lowercase with trailing dots removed).
//
// For globs with a wildcard other than the leading "*.", the host must also have
// the same registrable domain as the glob's literal suffix, according to the public
// suffix list. This keeps "access-analyzer.*.amazonaws.com" from matching
// "access-analyzer.s3.amazonaws.com", which is an S3 bucket that anyone can own.
//
// domainGlob should already have been passed through ACL.Validate().
func HostMatchesGlob(host string, domainGlob string) bool {
	return hostMatchesGlob(host, domainGlob, true)
}

// hostMatchesGlob implements HostMatchesGlob. If sameRegistrableDomain is false,
// a label wildcard also matches hosts in another registrable domain, which is what
// deny lists need to stay as broad as they read.
func hostMatchesGlob(host string, domainGlob string, sameRegistrableDomain bool) bool {
	if host == "" {
		return false
	}

	// Normalize both the request host and the glob to ASCII/Punycode.
	// Handle optional wildcard prefix by normalizing only the domain part.
	normalizedHost, err := hostport.NormalizeHost(host, false)
	if err != nil {
		return false
	}

	if !strings.HasPrefix(domainGlob, "*.") && strings.Contains(domainGlob, "*") {
		return hostMatchesLabelWildcard(normalizedHost, domainGlob, sameRegistrableDomain)
	}

	hasWildcard := strings.HasPrefix(domainGlob, "*.")
	domainPart := domainGlob
	if hasWildcard {
		domainPart = strings.TrimPrefix(domainGlob, "*.")
	}

	normalizedGlob, err := hostport.NormalizeHost(domainPart, false)
	if err != nil {
		return false
	}

	h := strings.TrimRight(strings.ToLower(normalizedHost), ".")
	g := strings.TrimRight(strings.ToLower(normalizedGlob), ".")

	if hasWildcard {
		// Wildcard matches any subdomain of g (e.g., *.example.com), not the root itself
		suffix := "." + g
		if strings.HasSuffix(h, suffix) {
			return true
		}
	} else if g == h {
		return true
	}
	return false
}

// hostMatchesLabelWildcard reports whether the normalized host matches glob, a
// glob with a single wildcard confined to one label. A whole-label wildcard
// matches any one label, and a wildcard after a literal prefix matches one or
// more characters. The host must have exactly as many labels as glob, and every
// other label must match exactly. Globs that ValidateDomainGlob rejects never
// match.
func hostMatchesLabelWildcard(host string, glob string, sameRegistrableDomain bool) bool {
	g, err := parseLabelWildcardGlob(glob)
	if err != nil {
		return false
	}
	h := strings.TrimRight(host, ".")
	if !g.matchLabels(strings.Split(h, ".")) {
		return false
	}
	// Only run the more expensive checks once the labels match.
	registrable, err := g.check()
	if err != nil {
		return false
	}
	if !sameRegistrableDomain {
		return true
	}
	got, err := publicsuffix.EffectiveTLDPlusOne(h)
	return err == nil && got == registrable
}

// MatchGlob matches host against domainGlob. If crossPublicSuffix is true, a
// label wildcard also matches hosts outside the glob's registrable domain, so
// the glob matches every host that its text describes.
func MatchGlob(host string, domainGlob string, crossPublicSuffix bool) bool {
	return hostMatchesGlob(host, domainGlob, !crossPublicSuffix)
}

// globsOverlap reports whether some host could match both a and b. It treats a
// label wildcard as covering every subdomain of the labels after its wildcard,
// so it can report an overlap that no real host has. It never misses one.
func globsOverlap(a, b string) bool {
	aExact, bExact := !strings.Contains(a, "*"), !strings.Contains(b, "*")
	switch {
	case aExact && bExact:
		return a == b
	case aExact:
		return hostMatchesGlob(a, b, false)
	case bExact:
		return hostMatchesGlob(b, a, false)
	}
	as, bs := wildcardSuffix(a), wildcardSuffix(b)
	return as == bs || strings.HasSuffix(as, "."+bs) || strings.HasSuffix(bs, "."+as)
}

// wildcardSuffix returns the labels to the right of the label that holds the
// wildcard in glob.
func wildcardSuffix(glob string) string {
	labels := strings.Split(strings.TrimSuffix(glob, "."), ".")
	for i, l := range labels {
		if strings.Contains(l, "*") {
			return strings.Join(labels[i+1:], ".")
		}
	}
	return glob
}

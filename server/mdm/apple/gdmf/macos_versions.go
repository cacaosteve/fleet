package gdmf

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fleetdm/fleet/v4/server/fleet"
)

// Well-known policy names for macOS OS-currency policies that Fleet keeps
// materialized from Apple's GDMF feed. Matching is by exact policy name
// (global or team).
const (
	// PolicyNameUpToDate is the standard-library / Fleet-maintained policy that
	// requires the latest macOS for each supported major (grace_days = 0).
	PolicyNameUpToDate = "Operating system up to date (macOS)"
	// PolicyNameAcceptable is the standard-library / Fleet-maintained policy that
	// allows the previous point release for 30 days after a new release.
	PolicyNameAcceptable = "Operating system version is acceptable (macOS)"

	// DogfoodPolicyNameUpToDate is the dogfood GitOps alias for PolicyNameUpToDate.
	DogfoodPolicyNameUpToDate = "macOS - Operating system up to date"
	// DogfoodPolicyNameAcceptable is the dogfood GitOps alias for PolicyNameAcceptable.
	DogfoodPolicyNameAcceptable = "macOS - Operating system version is acceptable"

	GraceDaysUpToDate   = 0
	GraceDaysAcceptable = 30

	// numMajorTracks is how many major-version tracks are included in the
	// materialized policy (latest major + previous major), matching Fleet
	// dogfood's dual-major pattern so older hardware can still pass.
	numMajorTracks = 2
)

// MacOSCurrencyPolicy defines a Fleet-maintained macOS OS-currency policy.
type MacOSCurrencyPolicy struct {
	Name      string
	GraceDays int
}

// MacOSCurrencyPolicies is the set of policies whose queries are rewritten from
// GDMF data on each sync.
func MacOSCurrencyPolicies() []MacOSCurrencyPolicy {
	return []MacOSCurrencyPolicy{
		{Name: PolicyNameUpToDate, GraceDays: GraceDaysUpToDate},
		{Name: PolicyNameAcceptable, GraceDays: GraceDaysAcceptable},
		{Name: DogfoodPolicyNameUpToDate, GraceDays: GraceDaysUpToDate},
		{Name: DogfoodPolicyNameAcceptable, GraceDays: GraceDaysAcceptable},
	}
}

// VersionFloor is the minimum ProductVersion required for one major-version track.
type VersionFloor struct {
	Major   int
	Version string
}

type macOSRelease struct {
	version string
	posted  time.Time
}

// RequiredMacOSVersions computes per-major minimum versions from Apple GDMF
// assets given a grace window.
//
// For each of the top major-version tracks:
//
//	required = latest     if age(latest.PostingDate) >= graceDays
//	         = previous   otherwise (same major; falls back to latest if none)
//
// graceDays = 0 always requires the latest release for each track.
func RequiredMacOSVersions(assets []Asset, graceDays int, now time.Time) []VersionFloor {
	if graceDays < 0 {
		graceDays = 0
	}
	if len(assets) == 0 {
		return nil
	}

	byMajor := map[int][]macOSRelease{}
	for _, a := range assets {
		major, ok := majorVersion(a.ProductVersion)
		if !ok {
			continue
		}
		posted, ok := parsePostingDate(a.PostingDate)
		if !ok {
			// Without a posting date we can still use the version as a floor when
			// grace is 0; for grace > 0 treat missing dates as already aged out
			// (require latest) by using a zero time (age is large).
			posted = time.Time{}
		}
		byMajor[major] = append(byMajor[major], macOSRelease{
			version: a.ProductVersion,
			posted:  posted,
		})
	}

	majors := make([]int, 0, len(byMajor))
	for major := range byMajor {
		majors = append(majors, major)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(majors)))
	if len(majors) > numMajorTracks {
		majors = majors[:numMajorTracks]
	}

	floors := make([]VersionFloor, 0, len(majors))
	for _, major := range majors {
		rels := dedupeMacOSReleases(byMajor[major])
		sort.Slice(rels, func(i, j int) bool {
			return fleet.CompareVersions(rels[i].version, rels[j].version) > 0
		})
		if len(rels) == 0 {
			continue
		}
		latest := rels[0]
		required := latest.version
		if graceDays > 0 && len(rels) > 1 {
			age := now.Sub(latest.posted)
			// If posting date is unknown (zero), treat as aged out → require latest.
			if !latest.posted.IsZero() && age < time.Duration(graceDays)*24*time.Hour {
				required = rels[1].version
			}
		}
		floors = append(floors, VersionFloor{Major: major, Version: required})
	}
	return floors
}

// PolicyQuery builds the osquery SQL for a macOS OS-currency policy from version floors.
func PolicyQuery(floors []VersionFloor) string {
	if len(floors) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("SELECT 1 FROM os_version WHERE ")
	for i, f := range floors {
		if i > 0 {
			b.WriteString(" OR ")
		}
		fmt.Fprintf(&b, "version >= '%s'", f.Version)
	}
	b.WriteByte(';')
	return b.String()
}

// MacOSAssetsForCurrencyPolicies returns the asset list to use when computing
// OS-currency floors. AssetSets is preferred (fuller history for "previous"
// within a major); PublicAssetSets is used as a fallback.
func MacOSAssetsForCurrencyPolicies(meta *AssetMetadata) []Asset {
	if meta == nil {
		return nil
	}
	if len(meta.AssetSets.MacOS) > 0 {
		return meta.AssetSets.MacOS
	}
	return meta.PublicAssetSets.MacOS
}

func majorVersion(version string) (int, bool) {
	version = strings.TrimSpace(version)
	if version == "" {
		return 0, false
	}
	majorStr, _, _ := strings.Cut(version, ".")
	major, err := strconv.Atoi(majorStr)
	if err != nil || major <= 0 {
		return 0, false
	}
	return major, true
}

func parsePostingDate(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	// GDMF uses YYYY-MM-DD.
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// dedupeMacOSReleases keeps one release per ProductVersion, preferring the
// earliest posting date (first public availability) when duplicates exist.
func dedupeMacOSReleases(rels []macOSRelease) []macOSRelease {
	best := map[string]macOSRelease{}
	for _, r := range rels {
		prev, ok := best[r.version]
		if !ok {
			best[r.version] = r
			continue
		}
		switch {
		case prev.posted.IsZero() && !r.posted.IsZero():
			best[r.version] = r
		case !prev.posted.IsZero() && !r.posted.IsZero() && r.posted.Before(prev.posted):
			best[r.version] = r
		}
	}
	out := make([]macOSRelease, 0, len(best))
	for _, r := range best {
		out = append(out, r)
	}
	return out
}

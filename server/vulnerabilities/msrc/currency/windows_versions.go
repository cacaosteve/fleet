// Package currency materializes Fleet-managed Windows OS-currency policy
// queries from MSRC FixedBuilds (the same catalog Fleet already syncs for
// Windows OS vulnerability matching).
//
// This is intentionally a vuln-feed proxy for "latest patched build per
// product-version track", not Microsoft Release Health. Missing posting dates
// under a grace window are treated as aged out (require latest), matching the
// macOS GDMF currency behavior.
package currency

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fleetdm/fleet/v4/server/fleet"
	msrc "github.com/fleetdm/fleet/v4/server/vulnerabilities/msrc/parsed"
)

const (
	// FleetManagedKeyWindowsUpToDate identifies policies Fleet may rewrite to
	// require the latest Windows FixedBuild per track (grace_days = 0).
	FleetManagedKeyWindowsUpToDate = fleet.FleetManagedKeyWindowsUpToDate
	// FleetManagedKeyWindowsAcceptable identifies policies Fleet may rewrite to
	// allow the previous FixedBuild for 30 days after a newer build appears.
	FleetManagedKeyWindowsAcceptable = fleet.FleetManagedKeyWindowsAcceptable

	GraceDaysUpToDate   = 0
	GraceDaysAcceptable = 30

	// numProductTracks is how many Windows product-version tracks (e.g.
	// 10.0.22631, 10.0.26100) are included in the materialized policy.
	numProductTracks = 4
)

// WindowsCurrencyPolicy defines a Fleet-maintained Windows OS-currency policy.
type WindowsCurrencyPolicy struct {
	Key       string
	GraceDays int
}

// WindowsCurrencyPolicies is the set of Fleet-owned Windows OS-currency
// policies whose queries are rewritten from MSRC FixedBuilds on each sync.
func WindowsCurrencyPolicies() []WindowsCurrencyPolicy {
	return []WindowsCurrencyPolicy{
		{Key: FleetManagedKeyWindowsUpToDate, GraceDays: GraceDaysUpToDate},
		{Key: FleetManagedKeyWindowsAcceptable, GraceDays: GraceDaysAcceptable},
	}
}

// VersionFloor is the minimum build required for one product-version track
// (first three components of a FixedBuild, e.g. 10.0.22631).
type VersionFloor struct {
	// Track is the product-version prefix (major.minor.build), e.g. "10.0.22631".
	Track string
	// Version is the full FixedBuild floor, e.g. "10.0.22631.4169".
	Version string
}

// WindowsRelease is one FixedBuild observed in MSRC for a client OS track.
type WindowsRelease struct {
	Track   string
	Version string
	Posted  time.Time
}

// RequiredWindowsVersions computes per-track minimum FixedBuilds from MSRC
// releases given a grace window.
//
// For each of the newest product-version tracks:
//
//	required = latest     if age(latest.Posted) >= graceDays
//	         = previous   otherwise (same track; falls back to latest if none)
//
// graceDays = 0 always requires the latest FixedBuild for each track.
func RequiredWindowsVersions(releases []WindowsRelease, graceDays int, now time.Time) []VersionFloor {
	if graceDays < 0 {
		graceDays = 0
	}
	if len(releases) == 0 {
		return nil
	}

	byTrack := map[string][]WindowsRelease{}
	for _, r := range releases {
		if r.Track == "" || r.Version == "" || !safeOSVersion(r.Version) {
			continue
		}
		byTrack[r.Track] = append(byTrack[r.Track], r)
	}

	tracks := make([]string, 0, len(byTrack))
	for track := range byTrack {
		tracks = append(tracks, track)
	}
	// Sort tracks newest-first using dotted numeric compare (not semver —
	// Windows FixedBuilds are 4-part and semver ignores the UBR).
	sortWindowsVersionsDesc(tracks)
	if len(tracks) > numProductTracks {
		tracks = tracks[:numProductTracks]
	}

	floors := make([]VersionFloor, 0, len(tracks))
	for _, track := range tracks {
		rels := dedupeWindowsReleases(byTrack[track])
		versions := make([]string, len(rels))
		for i, r := range rels {
			versions[i] = r.Version
		}
		sortWindowsVersionsDesc(versions)
		byVersion := map[string]WindowsRelease{}
		for _, r := range rels {
			byVersion[r.Version] = r
		}
		ordered := make([]WindowsRelease, 0, len(versions))
		for _, v := range versions {
			ordered = append(ordered, byVersion[v])
		}
		if len(ordered) == 0 {
			continue
		}
		latest := ordered[0]
		required := latest.Version
		if graceDays > 0 && len(ordered) > 1 {
			age := now.Sub(latest.Posted)
			// If posting date is unknown (zero), treat as aged out → require latest.
			if !latest.Posted.IsZero() && age < time.Duration(graceDays)*24*time.Hour {
				required = ordered[1].Version
			}
		}
		floors = append(floors, VersionFloor{Track: track, Version: required})
	}
	return floors
}

// sortWindowsVersionsDesc sorts dotted numeric versions newest-first in place.
func sortWindowsVersionsDesc(versions []string) {
	sort.Slice(versions, func(i, j int) bool {
		return compareDottedNumeric(versions[i], versions[j]) > 0
	})
}

// compareDottedNumeric compares versions like "10.0.22631.3000" component-wise.
// Returns >0 if a>b, <0 if a<b, 0 if equal.
func compareDottedNumeric(a, b string) int {
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		var ai, bi int
		if i < len(as) {
			ai, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			bi, _ = strconv.Atoi(bs[i])
		}
		if ai != bi {
			return ai - bi
		}
	}
	return 0
}

// PolicyQuery builds the osquery SQL for a Windows OS-currency policy from
// FixedBuild floors. Each floor is scoped to its product-version track via
// LIKE so a host on 10.0.22631.x cannot satisfy a 10.0.26100.y floor.
func PolicyQuery(floors []VersionFloor) string {
	if len(floors) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("SELECT 1 FROM os_version WHERE ")
	first := true
	for _, f := range floors {
		if f.Track == "" || f.Version == "" || !safeOSVersion(f.Track) || !safeOSVersion(f.Version) {
			continue
		}
		if !first {
			b.WriteString(" OR ")
		}
		first = false
		fmt.Fprintf(&b, "(version LIKE '%s.%%' AND version_compare(version, '%s') >= 0)", f.Track, f.Version)
	}
	if first {
		return ""
	}
	b.WriteByte(';')
	return b.String()
}

// ReleasesFromBulletins extracts Windows 10/11 client FixedBuilds from parsed
// MSRC security bulletins. Server SKUs are excluded. Posted times come from the
// newest vulnerability PublishedEpoch that references the FixedBuild's KB.
func ReleasesFromBulletins(bulletins []*msrc.SecurityBulletin) []WindowsRelease {
	type best struct {
		track   string
		version string
		posted  time.Time
	}
	bestByVersion := map[string]best{}

	for _, b := range bulletins {
		if b == nil {
			continue
		}
		clientPIDs := clientWindowsProductIDs(b.Products)
		if len(clientPIDs) == 0 {
			continue
		}

		// KBID → newest published time among vulns remediated by that KB.
		kbPosted := map[uint]time.Time{}
		for _, vuln := range b.Vulnerabilities {
			if vuln.PublishedEpoch == nil {
				continue
			}
			posted := time.Unix(*vuln.PublishedEpoch, 0).UTC()
			for kbID := range vuln.RemediatedBy {
				if prev, ok := kbPosted[kbID]; !ok || posted.After(prev) {
					kbPosted[kbID] = posted
				}
			}
		}

		for kbID, fix := range b.VendorFixes {
			if !productIDsIntersect(fix.ProductIDs, clientPIDs) {
				continue
			}
			posted := kbPosted[kbID]
			for _, build := range fix.FixedBuilds {
				track, ok := productTrack(build)
				if !ok {
					continue
				}
				prev, exists := bestByVersion[build]
				if !exists {
					bestByVersion[build] = best{track: track, version: build, posted: posted}
					continue
				}
				switch {
				case prev.posted.IsZero() && !posted.IsZero():
					bestByVersion[build] = best{track: track, version: build, posted: posted}
				case !prev.posted.IsZero() && !posted.IsZero() && posted.Before(prev.posted):
					// Prefer earliest observed publication for the build.
					bestByVersion[build] = best{track: track, version: build, posted: posted}
				}
			}
		}
	}

	out := make([]WindowsRelease, 0, len(bestByVersion))
	for _, r := range bestByVersion {
		out = append(out, WindowsRelease{
			Track:   r.track,
			Version: r.version,
			Posted:  r.posted,
		})
	}
	return out
}

func clientWindowsProductIDs(products msrc.Products) map[string]bool {
	out := map[string]bool{}
	for pID, product := range products {
		name := product.Name()
		if name != "Windows 10" && name != "Windows 11" {
			continue
		}
		out[pID] = true
	}
	return out
}

func productIDsIntersect(a map[string]bool, b map[string]bool) bool {
	for id := range a {
		if b[id] {
			return true
		}
	}
	return false
}

// productTrack returns the first three components of a FixedBuild
// ("10.0.22631.4169" → "10.0.22631").
func productTrack(version string) (string, bool) {
	version = strings.TrimSpace(version)
	if !safeOSVersion(version) {
		return "", false
	}
	parts := strings.Split(version, ".")
	if len(parts) != 4 {
		return "", false
	}
	return parts[0] + "." + parts[1] + "." + parts[2], true
}

func safeOSVersion(version string) bool {
	if version == "" {
		return false
	}
	for _, r := range version {
		if (r < '0' || r > '9') && r != '.' {
			return false
		}
	}
	return true
}

func dedupeWindowsReleases(rels []WindowsRelease) []WindowsRelease {
	best := map[string]WindowsRelease{}
	for _, r := range rels {
		prev, ok := best[r.Version]
		if !ok {
			best[r.Version] = r
			continue
		}
		switch {
		case prev.Posted.IsZero() && !r.Posted.IsZero():
			best[r.Version] = r
		case !prev.Posted.IsZero() && !r.Posted.IsZero() && r.Posted.Before(prev.Posted):
			best[r.Version] = r
		}
	}
	out := make([]WindowsRelease, 0, len(best))
	for _, r := range best {
		out = append(out, r)
	}
	return out
}

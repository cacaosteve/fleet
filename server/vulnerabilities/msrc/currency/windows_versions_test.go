package currency

import (
	"testing"
	"time"

	"github.com/fleetdm/fleet/v4/server/ptr"
	msrc "github.com/fleetdm/fleet/v4/server/vulnerabilities/msrc/parsed"
	"github.com/stretchr/testify/require"
)

func TestRequiredWindowsVersionsGrace(t *testing.T) {
	now := time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC)
	releases := []WindowsRelease{
		{Track: "10.0.22631", Version: "10.0.22631.3000", Posted: now.Add(-10 * 24 * time.Hour)},
		{Track: "10.0.22631", Version: "10.0.22631.2000", Posted: now.Add(-40 * 24 * time.Hour)},
		{Track: "10.0.26100", Version: "10.0.26100.1000", Posted: now.Add(-5 * 24 * time.Hour)},
		{Track: "10.0.26100", Version: "10.0.26100.500", Posted: now.Add(-60 * 24 * time.Hour)},
	}

	t.Run("grace 0 requires latest per track", func(t *testing.T) {
		floors := RequiredWindowsVersions(releases, 0, now)
		require.Equal(t, []VersionFloor{
			{Track: "10.0.26100", Version: "10.0.26100.1000"},
			{Track: "10.0.22631", Version: "10.0.22631.3000"},
		}, floors)
	})

	t.Run("grace 30 allows previous while latest is young", func(t *testing.T) {
		floors := RequiredWindowsVersions(releases, 30, now)
		require.Equal(t, []VersionFloor{
			{Track: "10.0.26100", Version: "10.0.26100.500"},
			{Track: "10.0.22631", Version: "10.0.22631.2000"},
		}, floors)
	})

	t.Run("grace 30 requires latest when aged out", func(t *testing.T) {
		aged := []WindowsRelease{
			{Track: "10.0.22631", Version: "10.0.22631.3000", Posted: now.Add(-40 * 24 * time.Hour)},
			{Track: "10.0.22631", Version: "10.0.22631.2000", Posted: now.Add(-80 * 24 * time.Hour)},
		}
		floors := RequiredWindowsVersions(aged, 30, now)
		require.Equal(t, []VersionFloor{
			{Track: "10.0.22631", Version: "10.0.22631.3000"},
		}, floors)
	})
}

func TestPolicyQuery(t *testing.T) {
	require.Empty(t, PolicyQuery(nil))
	q := PolicyQuery([]VersionFloor{
		{Track: "10.0.26100", Version: "10.0.26100.1000"},
		{Track: "10.0.22631", Version: "10.0.22631.3000"},
	})
	require.Equal(t,
		"SELECT 1 FROM os_version WHERE (version LIKE '10.0.26100.%' AND version_compare(version, '10.0.26100.1000') >= 0) OR (version LIKE '10.0.22631.%' AND version_compare(version, '10.0.22631.3000') >= 0);",
		q,
	)
}

func TestWindowsCurrencyPolicies(t *testing.T) {
	policies := WindowsCurrencyPolicies()
	require.Len(t, policies, 2)
	require.Equal(t, FleetManagedKeyWindowsUpToDate, policies[0].Key)
	require.Equal(t, GraceDaysUpToDate, policies[0].GraceDays)
	require.Equal(t, FleetManagedKeyWindowsAcceptable, policies[1].Key)
	require.Equal(t, GraceDaysAcceptable, policies[1].GraceDays)
}

func TestReleasesFromBulletins(t *testing.T) {
	bulletin := msrc.NewSecurityBulletin("Windows 11")
	bulletin.Products["111"] = msrc.NewProductFromFullName("Windows 11 Version 22H2 for x64-based Systems")
	bulletin.Products["222"] = msrc.NewProductFromFullName("Windows Server 2022 for x64-based Systems")

	published := int64(time.Date(2024, 1, 10, 0, 0, 0, 0, time.UTC).Unix())
	vuln := msrc.NewVulnerability(ptr.Int64(published))
	vuln.ProductIDs["111"] = true
	vuln.RemediatedBy[5001] = true
	bulletin.Vulnerabilities["CVE-TEST-1"] = vuln

	clientFix := msrc.NewVendorFix("10.0.22631.3000")
	clientFix.ProductIDs["111"] = true
	bulletin.VendorFixes[5001] = clientFix

	serverFix := msrc.NewVendorFix("10.0.20348.999")
	serverFix.ProductIDs["222"] = true
	bulletin.VendorFixes[5002] = serverFix

	releases := ReleasesFromBulletins([]*msrc.SecurityBulletin{bulletin})
	require.Len(t, releases, 1)
	require.Equal(t, "10.0.22631", releases[0].Track)
	require.Equal(t, "10.0.22631.3000", releases[0].Version)
	require.Equal(t, time.Unix(published, 0).UTC(), releases[0].Posted)
}

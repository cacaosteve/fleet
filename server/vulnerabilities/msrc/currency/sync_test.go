package currency

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fleetdm/fleet/v4/server/mock"
	"github.com/fleetdm/fleet/v4/server/ptr"
	msrc "github.com/fleetdm/fleet/v4/server/vulnerabilities/msrc/parsed"
	"github.com/stretchr/testify/require"
)

func TestSyncWindowsCurrencyPolicies(t *testing.T) {
	ds := new(mock.Store)
	updated := map[string]string{}
	ds.UpdateFleetManagedPolicyQueriesFunc = func(ctx context.Context, key string, query string) ([]uint, error) {
		updated[key] = query
		return []uint{1}, nil
	}

	bulletin := msrc.NewSecurityBulletin("Windows 11")
	bulletin.Products["111"] = msrc.NewProductFromFullName("Windows 11 Version 22H2 for x64-based Systems")
	published := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	vuln := msrc.NewVulnerability(ptr.Int64(published))
	vuln.ProductIDs["111"] = true
	vuln.RemediatedBy[1] = true
	bulletin.Vulnerabilities["CVE-1"] = vuln
	fix := msrc.NewVendorFix("10.0.22631.3000", "10.0.22631.2000")
	fix.ProductIDs["111"] = true
	bulletin.VendorFixes[1] = fix

	orig := loadBulletinsFromDirFn
	t.Cleanup(func() { loadBulletinsFromDirFn = orig })
	loadBulletinsFromDirFn = func(string) ([]*msrc.SecurityBulletin, error) {
		return []*msrc.SecurityBulletin{bulletin}, nil
	}

	now := time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC)
	err := SyncWindowsCurrencyPolicies(context.Background(), ds, slog.Default(), "/tmp/unused", now)
	require.NoError(t, err)
	require.Contains(t, updated, FleetManagedKeyWindowsUpToDate)
	require.Contains(t, updated, FleetManagedKeyWindowsAcceptable)
	require.Contains(t, updated[FleetManagedKeyWindowsUpToDate], "10.0.22631.3000")
}

func TestSyncWindowsCurrencyPoliciesEmptyPath(t *testing.T) {
	ds := new(mock.Store)
	ds.UpdateFleetManagedPolicyQueriesFunc = func(ctx context.Context, key string, query string) ([]uint, error) {
		t.Fatal("should not update policies when vuln path is empty")
		return nil, nil
	}
	err := SyncWindowsCurrencyPolicies(context.Background(), ds, slog.Default(), "", time.Now().UTC())
	require.NoError(t, err)
	require.False(t, ds.UpdateFleetManagedPolicyQueriesFuncInvoked)
}

func TestLoadBulletinsFromDirUsesTestdata(t *testing.T) {
	src := filepath.Join("..", "testdata")
	entries, err := os.ReadDir(src)
	require.NoError(t, err)

	dir := t.TempDir()
	copied := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if len(name) < 11 || name[:11] != "fleet_msrc_" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(src, name))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), b, 0o600))
		copied++
	}
	require.Greater(t, copied, 0)

	bulletins, err := loadBulletinsFromDir(dir)
	require.NoError(t, err)
	require.NotEmpty(t, bulletins)

	releases := ReleasesFromBulletins(bulletins)
	require.NotEmpty(t, releases)
	floors := RequiredWindowsVersions(releases, 0, time.Now().UTC())
	require.NotEmpty(t, floors)
	require.NotEmpty(t, PolicyQuery(floors))
}

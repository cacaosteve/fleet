package currency

import (
	"context"
	"log/slog"
	"path/filepath"
	"sort"
	"time"

	"github.com/fleetdm/fleet/v4/server/contexts/ctxerr"
	"github.com/fleetdm/fleet/v4/server/fleet"
	vulnio "github.com/fleetdm/fleet/v4/server/vulnerabilities/io"
	msrc "github.com/fleetdm/fleet/v4/server/vulnerabilities/msrc/parsed"
)

// loadBulletinsFromDirFn is overridden in tests.
var loadBulletinsFromDirFn = loadBulletinsFromDir

// SyncWindowsCurrencyPolicies loads local MSRC bulletins from vulnPath,
// derives Windows OS-currency floors, and rewrites Fleet-managed Windows
// policy queries. When vulnPath is empty or no client releases are found,
// existing policy queries are left unchanged (last-known-good).
func SyncWindowsCurrencyPolicies(
	ctx context.Context,
	ds fleet.Datastore,
	logger *slog.Logger,
	vulnPath string,
	now time.Time,
) error {
	if logger == nil {
		logger = slog.Default()
	}
	logger = logger.With("component", "msrc-windows-currency")

	if vulnPath == "" {
		logger.InfoContext(ctx, "vulnerabilities databases path not configured; skipping Windows currency policy refresh")
		return nil
	}

	bulletins, err := loadBulletinsFromDirFn(vulnPath)
	if err != nil {
		return ctxerr.Wrap(ctx, err, "load MSRC bulletins for Windows currency policies")
	}
	releases := ReleasesFromBulletins(bulletins)
	if len(releases) == 0 {
		logger.InfoContext(ctx, "no Windows 10/11 FixedBuilds in MSRC bulletins; preserving policy queries")
		return nil
	}
	logger.InfoContext(ctx, "derived Windows OS-currency releases from MSRC",
		"releases", len(releases),
		"bulletins", len(bulletins),
	)

	for _, p := range WindowsCurrencyPolicies() {
		floors := RequiredWindowsVersions(releases, p.GraceDays, now)
		query := PolicyQuery(floors)
		if query == "" {
			continue
		}
		ids, err := ds.UpdateFleetManagedPolicyQueries(ctx, p.Key, query)
		if err != nil {
			return ctxerr.Wrap(ctx, err, "update Fleet-managed Windows currency policy queries")
		}
		if len(ids) > 0 {
			logger.InfoContext(ctx, "updated Fleet-managed Windows currency policy queries",
				"fleet_managed_key", p.Key,
				"grace_days", p.GraceDays,
				"query", query,
				"updated_count", len(ids),
			)
		}
	}
	return nil
}

func loadBulletinsFromDir(dir string) ([]*msrc.SecurityBulletin, error) {
	fsClient := vulnio.NewFSClient(dir)
	files, err := fsClient.MSRCBulletins()
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, nil
	}

	// Keep the newest bulletin file per product name.
	newest := map[string]vulnio.MetadataFileName{}
	for _, f := range files {
		product := f.ProductName()
		prev, ok := newest[product]
		if !ok || prev.Before(f) {
			newest[product] = f
		}
	}

	products := make([]string, 0, len(newest))
	for product := range newest {
		products = append(products, product)
	}
	sort.Strings(products)

	out := make([]*msrc.SecurityBulletin, 0, len(products))
	for _, product := range products {
		path := filepath.Join(dir, newest[product].String())
		bulletin, err := msrc.UnmarshalBulletin(path)
		if err != nil {
			return nil, err
		}
		out = append(out, bulletin)
	}
	return out, nil
}

package gdmf

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/fleetdm/fleet/v4/server/contexts/ctxerr"
	"github.com/fleetdm/fleet/v4/server/fleet"
)

// getAssetMetadataFn is overridden in tests.
var getAssetMetadataFn = GetAssetMetadata

// SyncMacOSCurrencyPolicies fetches Apple's GDMF feed, refreshes
// apple_software_update_assets for macOS, and rewrites well-known macOS
// OS-currency policy queries from the resulting version floors.
func SyncMacOSCurrencyPolicies(ctx context.Context, ds fleet.Datastore, logger *slog.Logger, now time.Time) error {
	if logger == nil {
		logger = slog.Default()
	}
	logger = logger.With("component", "gdmf-macos-currency")

	meta, err := getAssetMetadataFn()
	if err != nil {
		return ctxerr.Wrap(ctx, err, "fetch GDMF asset metadata")
	}
	if err := replaceMacOSAssets(ctx, ds, meta); err != nil {
		return err
	}
	logger.InfoContext(ctx, "refreshed apple_software_update_assets from GDMF",
		"macos_asset_sets", len(meta.AssetSets.MacOS),
		"macos_public_asset_sets", len(meta.PublicAssetSets.MacOS),
	)

	assets := MacOSAssetsForCurrencyPolicies(meta)
	if len(assets) == 0 {
		logger.InfoContext(ctx, "no macOS assets in GDMF response; skipping policy refresh")
		return nil
	}

	for _, p := range MacOSCurrencyPolicies() {
		floors := RequiredMacOSVersions(assets, p.GraceDays, now)
		query := PolicyQuery(floors)
		if query == "" {
			continue
		}
		ids, err := ds.UpdatePolicyQueriesByName(ctx, p.Name, query)
		if err != nil {
			return ctxerr.Wrap(ctx, err, "update macOS currency policy queries")
		}
		for _, id := range ids {
			if err := ds.ResetPolicy(ctx, id); err != nil {
				return ctxerr.Wrap(ctx, err, "reset policy after GDMF query update")
			}
		}
		if len(ids) > 0 {
			logger.InfoContext(ctx, "updated macOS currency policy queries",
				"policy", p.Name,
				"grace_days", p.GraceDays,
				"query", query,
				"updated_count", len(ids),
			)
		}
	}
	return nil
}

func replaceMacOSAssets(ctx context.Context, ds fleet.Datastore, meta *AssetMetadata) error {
	if meta == nil {
		return ctxerr.New(ctx, "GDMF asset metadata is nil")
	}
	// Prefer AssetSets (fuller history); fall back to PublicAssetSets.
	src := meta.AssetSets.MacOS
	if len(src) == 0 {
		src = meta.PublicAssetSets.MacOS
	}
	assets := make([]fleet.AppleSoftwareUpdateAsset, 0, len(src))
	seen := map[string]struct{}{}
	for _, a := range src {
		key := a.ProductVersion + "\x00" + a.Build
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		row := fleet.AppleSoftwareUpdateAsset{
			Class:          fleet.AppleSoftwareUpdateAssetClassMacOS,
			ProductVersion: a.ProductVersion,
			Build:          a.Build,
		}
		if t, ok := parsePostingDate(a.PostingDate); ok {
			row.PostingDate = &t
		}
		if t, ok := parsePostingDate(a.ExpirationDate); ok {
			row.ExpirationDate = &t
		}
		devices, err := json.Marshal(a.SupportedDevices)
		if err != nil {
			return ctxerr.Wrap(ctx, err, "marshal supported devices")
		}
		if len(a.SupportedDevices) == 0 {
			devices = []byte("[]")
		}
		row.SupportedDevices = devices
		assets = append(assets, row)
	}
	if err := ds.ReplaceAppleSoftwareUpdateAssets(ctx, fleet.AppleSoftwareUpdateAssetClassMacOS, assets); err != nil {
		return ctxerr.Wrap(ctx, err, "replace apple software update assets")
	}
	return nil
}

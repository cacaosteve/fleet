package gdmf

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/fleetdm/fleet/v4/server/mock"
	"github.com/stretchr/testify/require"
)

func TestSyncMacOSCurrencyPolicies(t *testing.T) {
	ds := new(mock.Store)
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)

	orig := getAssetMetadataFn
	t.Cleanup(func() { getAssetMetadataFn = orig })
	getAssetMetadataFn = func() (*AssetMetadata, error) {
		return &AssetMetadata{
			AssetSets: AssetSets{
				MacOS: []Asset{
					{ProductVersion: "26.4.1", PostingDate: "2026-07-20", Build: "a", SupportedDevices: []string{"J1"}},
					{ProductVersion: "26.4.0", PostingDate: "2026-07-01", Build: "b", SupportedDevices: []string{"J1"}},
					{ProductVersion: "15.7.5", PostingDate: "2026-07-20", Build: "c", SupportedDevices: []string{"J2"}},
					{ProductVersion: "15.7.4", PostingDate: "2026-06-15", Build: "d", SupportedDevices: []string{"J2"}},
				},
			},
		}, nil
	}

	var replaced []fleet.AppleSoftwareUpdateAsset
	ds.ReplaceAppleSoftwareUpdateAssetsFunc = func(ctx context.Context, class fleet.AppleSoftwareUpdateAssetClass, assets []fleet.AppleSoftwareUpdateAsset) error {
		require.Equal(t, fleet.AppleSoftwareUpdateAssetClassMacOS, class)
		replaced = assets
		return nil
	}

	updated := map[string]string{}
	var resetIDs []uint
	nextID := uint(1)
	ds.UpdatePolicyQueriesByNameFunc = func(ctx context.Context, name string, query string) ([]uint, error) {
		updated[name] = query
		id := nextID
		nextID++
		return []uint{id}, nil
	}
	ds.ResetPolicyFunc = func(ctx context.Context, policyID uint) error {
		resetIDs = append(resetIDs, policyID)
		return nil
	}

	err := SyncMacOSCurrencyPolicies(context.Background(), ds, slog.Default(), now)
	require.NoError(t, err)
	require.True(t, ds.ReplaceAppleSoftwareUpdateAssetsFuncInvoked)
	require.Len(t, replaced, 4)

	require.Equal(t,
		"SELECT 1 FROM os_version WHERE (major = 26 AND version_compare(version, '26.4.1') >= 0) OR (major = 15 AND version_compare(version, '15.7.5') >= 0);",
		updated[PolicyNameUpToDate],
	)
	require.Equal(t,
		"SELECT 1 FROM os_version WHERE (major = 26 AND version_compare(version, '26.4.0') >= 0) OR (major = 15 AND version_compare(version, '15.7.4') >= 0);",
		updated[PolicyNameAcceptable],
	)
	require.Equal(t, updated[PolicyNameUpToDate], updated[DogfoodPolicyNameUpToDate])
	require.Equal(t, updated[PolicyNameAcceptable], updated[DogfoodPolicyNameAcceptable])
	require.Len(t, resetIDs, 4)
}

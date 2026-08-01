package mysql

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/fleetdm/fleet/v4/server/contexts/ctxerr"
	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/jmoiron/sqlx"
)

// ReplaceAppleSoftwareUpdateAssets replaces all cached GDMF assets for class.
func (ds *Datastore) ReplaceAppleSoftwareUpdateAssets(ctx context.Context, class fleet.AppleSoftwareUpdateAssetClass, assets []fleet.AppleSoftwareUpdateAsset) error {
	return ds.withRetryTxx(ctx, func(tx sqlx.ExtContext) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM apple_software_update_assets WHERE class = ?`, class); err != nil {
			return ctxerr.Wrap(ctx, err, "delete apple software update assets")
		}
		if len(assets) == 0 {
			return nil
		}

		valueStrings := make([]string, 0, len(assets))
		args := make([]interface{}, 0, len(assets)*6)
		for _, a := range assets {
			devices := a.SupportedDevices
			if len(devices) == 0 || !json.Valid(devices) {
				devices = []byte("[]")
			}
			valueStrings = append(valueStrings, "(?, ?, ?, ?, ?, ?)")
			args = append(args, class, a.ProductVersion, a.Build, a.PostingDate, a.ExpirationDate, devices)
		}
		stmt := `
INSERT INTO apple_software_update_assets
  (class, product_version, build, posting_date, expiration_date, supported_devices)
VALUES ` + strings.Join(valueStrings, ", ")
		if _, err := tx.ExecContext(ctx, stmt, args...); err != nil {
			return ctxerr.Wrap(ctx, err, "insert apple software update assets")
		}
		return nil
	})
}

// AppleSoftwareUpdateAssetsUpdatedAt returns MAX(updated_at) for the class.
func (ds *Datastore) AppleSoftwareUpdateAssetsUpdatedAt(ctx context.Context, class fleet.AppleSoftwareUpdateAssetClass) (*time.Time, error) {
	var updatedAt *time.Time
	err := sqlx.GetContext(ctx, ds.reader(ctx), &updatedAt, `
SELECT MAX(updated_at) FROM apple_software_update_assets WHERE class = ?
`, class)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "select apple software update assets updated_at")
	}
	return updatedAt, nil
}

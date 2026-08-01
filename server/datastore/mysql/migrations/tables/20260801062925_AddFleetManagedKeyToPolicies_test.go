package tables

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUp_20260801062925(t *testing.T) {
	db := applyUpToPrev(t)

	teamID := execNoErrLastID(t, db, `INSERT INTO teams (name) VALUES ('ManagedKeyTest')`)

	// Pre-existing policies with Fleet-maintained display names stay user-owned
	// until GitOps/API sets fleet_managed_key explicitly.
	globalNamed := execNoErrLastID(t, db, `
		INSERT INTO policies (name, query, description, platforms, checksum)
		VALUES ('Operating system up to date (macOS)', 'SELECT 1', '', 'darwin', UNHEX(MD5(CONCAT_WS(CHAR(0), '', 'Operating system up to date (macOS)'))))`)
	dogfoodAlias := execNoErrLastID(t, db, `
		INSERT INTO policies (name, query, description, platforms, team_id, checksum)
		VALUES ('macOS - Operating system up to date', 'SELECT 1', '', 'darwin', ?, UNHEX(MD5(CONCAT_WS(CHAR(0), ?, 'macOS - Operating system up to date'))))`, teamID, teamID)

	applyNext(t, db)

	var key *string
	err := db.QueryRow(`SELECT fleet_managed_key FROM policies WHERE id = ?`, globalNamed).Scan(&key)
	require.NoError(t, err)
	require.Nil(t, key, "migration must not claim policies by name")

	err = db.QueryRow(`SELECT fleet_managed_key FROM policies WHERE id = ?`, dogfoodAlias).Scan(&key)
	require.NoError(t, err)
	require.Nil(t, key, "migration must not claim policies by name")

	// Explicit key works; unique fleet_managed_team_key rejects a second global claim.
	execNoErr(t, db, `
		UPDATE policies SET fleet_managed_key = 'macos_os_up_to_date' WHERE id = ?`, globalNamed)

	_, err = db.Exec(`
		INSERT INTO policies (name, query, description, platforms, fleet_managed_key, checksum)
		VALUES ('other', 'SELECT 1', '', 'darwin', 'macos_os_up_to_date', UNHEX(MD5(CONCAT_WS(CHAR(0), '', 'other'))))`)
	require.Error(t, err)

	// Same key on a different team is allowed.
	_, err = db.Exec(`
		INSERT INTO policies (name, query, description, platforms, team_id, fleet_managed_key, checksum)
		VALUES ('team up to date', 'SELECT 1', '', 'darwin', ?, 'macos_os_up_to_date', UNHEX(MD5(CONCAT_WS(CHAR(0), ?, 'team up to date'))))`, teamID, teamID)
	require.NoError(t, err)
}

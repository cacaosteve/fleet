package tables

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUp_20260801062925(t *testing.T) {
	db := applyUpToPrev(t)

	teamID := execNoErrLastID(t, db, `INSERT INTO teams (name) VALUES ('ManagedKeyTest')`)

	globalUpToDate := execNoErrLastID(t, db, `
		INSERT INTO policies (name, query, description, platforms, checksum)
		VALUES ('Operating system up to date (macOS)', 'SELECT 1', '', 'darwin', UNHEX(MD5(CONCAT_WS(CHAR(0), '', 'Operating system up to date (macOS)'))))`)
	windowsSameName := execNoErrLastID(t, db, `
		INSERT INTO policies (name, query, description, platforms, team_id, checksum)
		VALUES ('Operating system up to date (macOS)', 'SELECT 1', '', 'windows', ?, UNHEX(MD5(CONCAT_WS(CHAR(0), ?, 'Operating system up to date (macOS)'))))`, teamID, teamID)
	dogfoodAcceptable := execNoErrLastID(t, db, `
		INSERT INTO policies (name, query, description, platforms, checksum)
		VALUES ('macOS - Operating system version is acceptable', 'SELECT 1', '', 'darwin', UNHEX(MD5(CONCAT_WS(CHAR(0), '', 'macOS - Operating system version is acceptable'))))`)

	applyNext(t, db)

	var key *string
	err := db.QueryRow(`SELECT fleet_managed_key FROM policies WHERE id = ?`, globalUpToDate).Scan(&key)
	require.NoError(t, err)
	require.NotNil(t, key)
	require.Equal(t, "macos_os_up_to_date", *key)

	err = db.QueryRow(`SELECT fleet_managed_key FROM policies WHERE id = ?`, windowsSameName).Scan(&key)
	require.NoError(t, err)
	require.Nil(t, key, "non-darwin policy with same name must not be claimed")

	err = db.QueryRow(`SELECT fleet_managed_key FROM policies WHERE id = ?`, dogfoodAcceptable).Scan(&key)
	require.NoError(t, err)
	require.NotNil(t, key)
	require.Equal(t, "macos_os_acceptable", *key)

	// Unique fleet_managed_team_key rejects a second global claim (team_id NULL).
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

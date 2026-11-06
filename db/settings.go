package db

import "database/sql"

// Settings is a tiny key-value store for global app config the UI toggles at
// runtime (e.g. traffic_capture). Missing keys fall back to caller defaults.

// GetSetting returns the stored value and ok=false when the key is unset.
func (d *DB) GetSetting(key string) (value string, ok bool, err error) {
	err = d.QueryRow(`SELECT value FROM settings WHERE key=$1`, key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return value, true, nil
}

// SetSetting upserts a setting value.
func (d *DB) SetSetting(key, value string) error {
	_, err := d.Exec(`
INSERT INTO settings(key, value) VALUES ($1, $2)
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`, key, value)
	return err
}

// DeleteSetting removes a setting row; a missing key is not an error.
// (F6: refresh token 旋转/登出时删除哈希记录。)
func (d *DB) DeleteSetting(key string) error {
	_, err := d.Exec(`DELETE FROM settings WHERE key=$1`, key)
	return err
}

// GetBool returns the boolean setting, or def when unset/unparseable.
func (d *DB) GetBool(key string, def bool) bool {
	v, ok, err := d.GetSetting(key)
	if err != nil || !ok {
		return def
	}
	return v == "true" || v == "1"
}

// SetBool stores a boolean setting as "true"/"false".
func (d *DB) SetBool(key string, val bool) error {
	if val {
		return d.SetSetting(key, "true")
	}
	return d.SetSetting(key, "false")
}

// SetSettingIfAbsent claims a key atomically without overwriting another writer.
// An existing empty value is also reserved; recovery must use the reset script.
func (d *DB) SetSettingIfAbsent(key, value string) (bool, error) {
	result, err := d.Exec(`INSERT INTO settings(key, value) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING`, key, value)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	return n == 1, err
}

// TakeSetting atomically removes and returns a one-use credential. A SELECT
// followed by DELETE lets simultaneous callers redeem the same credential.
func (d *DB) TakeSetting(key string) (value string, ok bool, err error) {
	err = d.QueryRow(`DELETE FROM settings WHERE key=$1 RETURNING value`, key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return value, true, nil
}

// ChangeAuthPassword replaces only the hash the caller authenticated against.
// Password replacement, version revocation and refresh deletion commit together;
// malformed/overflowing versions or a failed write leave the old session intact.
func (d *DB) ChangeAuthPassword(oldHash, newHash string) (bool, error) {
	tx, err := d.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var current string
	if err := tx.QueryRow(`SELECT value FROM settings WHERE key='auth.password_hash' FOR UPDATE`).Scan(&current); err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	if current != oldHash {
		return false, nil
	}
	if _, err := tx.Exec(`UPDATE settings SET value=$1, updated_at=now() WHERE key='auth.password_hash'`, newHash); err != nil {
		return false, err
	}
	if _, err := tx.Exec(`INSERT INTO settings(key,value) VALUES ('auth.key_version','1')
ON CONFLICT (key) DO UPDATE SET value=(settings.value::bigint + 1)::text, updated_at=now()`); err != nil {
		return false, err
	}
	if _, err := tx.Exec(`DELETE FROM settings WHERE key LIKE 'auth.refresh.%'`); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

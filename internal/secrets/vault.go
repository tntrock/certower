package secrets

import (
	"context"
	"errors"

	"github.com/tntrock/certower/internal/store"
)

// Vault stores and retrieves encrypted values in the database.
type Vault struct {
	Store *store.Store
	KEK   KEK
}

// Put encrypts value and stores it under a new ID, which it returns. Names
// are unique per organization and project.
func (v *Vault) Put(ctx context.Context, orgID, projectID, name string, value []byte) (string, error) {
	id := store.NewID()
	sealed, err := Seal(v.KEK, value, []byte(id))
	if err != nil {
		return "", err
	}
	err = v.Store.CreateSecret(ctx, store.SecretRow{
		ID: id, OrgID: orgID, ProjectID: projectID, Name: name,
		KEKID: sealed.KEKID, WrappedDEK: sealed.WrappedDEK, Ciphertext: sealed.Ciphertext,
	})
	return id, err
}

// Get decrypts the value stored under id.
func (v *Vault) Get(ctx context.Context, id string) ([]byte, error) {
	row, err := v.Store.GetSecret(ctx, id)
	if err != nil {
		return nil, err
	}
	return Open(v.KEK, Sealed{KEKID: row.KEKID, WrappedDEK: row.WrappedDEK, Ciphertext: row.Ciphertext}, []byte(row.ID))
}

// Delete removes a value.
func (v *Vault) Delete(ctx context.Context, id string) error {
	return v.Store.DeleteSecret(ctx, id)
}

// WithStore returns a Vault bound to another store handle, such as a
// transaction.
func (v *Vault) WithStore(st *store.Store) *Vault {
	return &Vault{Store: st, KEK: v.KEK}
}

// ErrOutOfScope means a secret exists but belongs to another organization
// or project than the one asking for it.
var ErrOutOfScope = errors.New("secret belongs to another scope")

// GetScoped decrypts a value only if it belongs to orgID and either to
// projectID or to the whole organization.
func (v *Vault) GetScoped(ctx context.Context, id, orgID, projectID string) ([]byte, error) {
	row, err := v.Store.GetSecret(ctx, id)
	if err != nil {
		return nil, err
	}
	if row.OrgID != orgID || (row.ProjectID != "" && row.ProjectID != projectID) {
		return nil, ErrOutOfScope
	}
	return Open(v.KEK, Sealed{KEKID: row.KEKID, WrappedDEK: row.WrappedDEK, Ciphertext: row.Ciphertext}, []byte(row.ID))
}

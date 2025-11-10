package backend

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path"

	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
)

type VaultStore struct {
	client *vault.Client
}

func NewVaultStore(ctx context.Context, vaultUrl string) (*VaultStore, error) {
	if len(vaultUrl) == 0 {
		return nil, errors.New("a vault url must be present")
	}

	client, err := vault.New(
		vault.WithAddress(vaultUrl),
	)
	if err != nil {
		return nil, err
	}

	// This will attempt to authenticate with Vault, and will return an error if it fails.
	// The token can be provided in a number of ways, but the easiest is to set the VAULT_TOKEN environment variable.
	// see: https://developer.hashicorp.com/vault/docs/auth
	_, err = client.Auth.TokenLookUpSelf(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate with vault: %w", err)
	}

	return &VaultStore{
		client: client,
	}, nil
}

func (v *VaultStore) Get(ctx context.Context, p *Profile, key string) ([]byte, error) {
	resp, err := v.client.Secrets.KvV2Read(ctx, path.Join(p.ProjectID, key), vault.WithMountPath(getMountPath(p)))
	if err != nil {
		return nil, err
	}

	data, ok := resp.Data.Data["value"]
	if !ok {
		return nil, fmt.Errorf("secret data did not contain a value for key 'value'")
	}

	value, ok := data.(string)
	if !ok {
		return nil, fmt.Errorf("secret value was not a string")
	}

	return []byte(value), nil
}
func (v *VaultStore) List(ctx context.Context, p *Profile) ([]Key, error) {
	resp, err := v.client.Secrets.KvV2List(ctx, p.ProjectID, vault.WithMountPath(getMountPath(p)))
	if err != nil {
		var vaultErr *vault.ResponseError
		if errors.As(err, &vaultErr) && vaultErr.StatusCode == http.StatusNotFound {
			return []Key{}, nil
		}
		return nil, err
	}

	var keys []Key
	for _, keyName := range resp.Data.Keys {
		// This will be slow, as we have to fetch metadata for each key.
		// There isn't a better way to do this with the Vault API.
		secretMetadata, err := v.client.Secrets.KvV2ReadMetadata(ctx, path.Join(p.ProjectID, keyName), vault.WithMountPath(getMountPath(p)))
		if err != nil {
			return nil, err
		}

		keys = append(keys, Key{
			Name:      keyName,
			CreatedAt: secretMetadata.Data.CreatedTime,
		})
	}

	return keys, nil
}
func (v *VaultStore) CheckExists(ctx context.Context, p *Profile, key string) (bool, error) {
	_, err := v.client.Secrets.KvV2Read(ctx, path.Join(p.ProjectID, key), vault.WithMountPath(getMountPath(p)))
	if err != nil {
		var vaultErr *vault.ResponseError
		if errors.As(err, &vaultErr) && vaultErr.StatusCode == http.StatusNotFound {
			return false, nil
		}
		return false, err
	}

	return true, nil
}
func (v *VaultStore) Put(ctx context.Context, p *Profile, key, value string, overwrite bool) error {
	if !overwrite {
		exists, err := v.CheckExists(ctx, p, key)
		if err != nil {
			return err
		}
		if exists {
			return fmt.Errorf("secret with key '%s' already exists", key)
		}
	}

	req := schema.KvV2WriteRequest{
		Data: map[string]interface{}{
			"value": value,
		},
	}
	_, err := v.client.Secrets.KvV2Write(ctx, path.Join(p.ProjectID, key), req, vault.WithMountPath(getMountPath(p)))
	return err
}
func (v *VaultStore) Delete(ctx context.Context, p *Profile, key string) error {
	_, err := v.client.Secrets.KvV2DeleteMetadataAndAllVersions(ctx, path.Join(p.ProjectID, key), vault.WithMountPath(getMountPath(p)))
	if err != nil {
		var vaultErr *vault.ResponseError
		if errors.As(err, &vaultErr) && vaultErr.StatusCode == http.StatusNotFound {
			return nil
		}
		return err
	}
	return nil
}
func (v *VaultStore) SetParameter(key string, value interface{}) {
}
func (v *VaultStore) Close() error {
	return nil
}

func getMountPath(p *Profile) string {
	if p.VaultMountPath != "" {
		return p.VaultMountPath
	}
	return "secret"
}

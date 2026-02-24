package backend

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault-client-go/schema"
	"github.com/stretchr/testify/assert"
)

func TestVaultStore(t *testing.T) {
	// This is a mock Vault server that simulates the Vault KVv2 API.
	secrets := make(map[string]map[string]interface{})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle auth requests
		if strings.Contains(r.URL.Path, "/auth/token/lookup-self") {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{"data": {"id": "test"}}`)
			return
		}

		// Regex to extract mount path and secret path from request URL
		re := regexp.MustCompile(`/v1/([^/]+)/(data|metadata)/(.+)`)
		matches := re.FindStringSubmatch(r.URL.Path)
		if len(matches) != 4 {
			http.Error(w, "invalid path", http.StatusBadRequest)
			return
		}
		pathType := matches[2]
		secretPath := matches[3]

		switch r.Method {
		case http.MethodPost, http.MethodPut:
			if pathType != "data" {
				http.Error(w, "wrong path type for write", http.StatusBadRequest)
				return
			}
			var req schema.KvV2WriteRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			secrets[secretPath] = req.Data
			fmt.Fprintln(w, "{}")
		case http.MethodGet:
			if r.URL.Query().Get("list") == "true" {
				if pathType != "metadata" {
					http.Error(w, "wrong path type for list", http.StatusBadRequest)
					return
				}
				var keys []string
				// Ensure prefix ends with a slash for "folder" listing
				prefix := strings.TrimSuffix(secretPath, "/") + "/"

				for k := range secrets {
					if strings.HasPrefix(k, prefix) {
						keyPart := strings.TrimPrefix(k, prefix)
						if strings.Contains(keyPart, "/") {
							keys = append(keys, strings.Split(keyPart, "/")[0]+"/")
						} else {
							keys = append(keys, keyPart)
						}
					}
				}

				// Deduplicate keys
				dedupedKeys := make(map[string]bool)
				var finalKeys []string
				for _, key := range keys {
					if !dedupedKeys[key] {
						dedupedKeys[key] = true
						finalKeys = append(finalKeys, key)
					}
				}

				resp := map[string]interface{}{
					"data": map[string]interface{}{
						"keys": finalKeys,
					},
				}
				json.NewEncoder(w).Encode(resp)
				return
			}

			if pathType == "metadata" {
				if _, ok := secrets[secretPath]; !ok {
					http.Error(w, "not found", http.StatusNotFound)
					return
				}
				resp := map[string]interface{}{
					"data": map[string]interface{}{
						"created_time": time.Now().UTC().Format(time.RFC3339),
					},
				}
				json.NewEncoder(w).Encode(resp)
				return
			}

			if pathType == "data" {
				if data, ok := secrets[secretPath]; ok {
					resp := map[string]interface{}{
						"data": map[string]interface{}{
							"data": data,
						},
					}
					json.NewEncoder(w).Encode(resp)
				} else {
					http.Error(w, "not found", http.StatusNotFound)
				}
				return
			}

			http.Error(w, "unhandled GET path", http.StatusInternalServerError)

		case http.MethodDelete:
			if pathType != "metadata" {
				http.Error(w, "wrong path type for delete", http.StatusBadRequest)
				return
			}
			delete(secrets, secretPath)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	ctx := context.Background()

	t.Run("NewVaultStore", func(t *testing.T) {
		t.Run("should return an error if the vault url is empty", func(t *testing.T) {
			_, err := NewVaultStore(ctx, "")
			assert.Error(t, err)
		})

		t.Run("should return a new vault store", func(t *testing.T) {
			store, err := NewVaultStore(ctx, server.URL)
			assert.NoError(t, err)
			assert.NotNil(t, store)
		})
	})

	t.Run("VaultStore methods", func(t *testing.T) {
		store, err := NewVaultStore(ctx, server.URL)
		assert.NoError(t, err)
		assert.NotNil(t, store)

		profile := &Profile{
			ProjectID: "test-project",
		}
		key := "test-key"
		value := "test-value"

		t.Run("Put and Get", func(t *testing.T) {
			err := store.Put(ctx, profile, key, value, false)
			assert.NoError(t, err)

			retrievedValue, err := store.Get(ctx, profile, key)
			assert.NoError(t, err)
			assert.Equal(t, value, string(retrievedValue))
		})

		t.Run("CheckExists", func(t *testing.T) {
			exists, err := store.CheckExists(ctx, profile, key)
			assert.NoError(t, err)
			assert.True(t, exists)

			exists, err = store.CheckExists(ctx, profile, "non-existent-key")
			assert.NoError(t, err)
			assert.False(t, exists)
		})

		t.Run("List", func(t *testing.T) {
			keys, err := store.List(ctx, profile)
			assert.NoError(t, err)
			assert.Len(t, keys, 1)
			assert.Equal(t, key, keys[0].Name)
		})

		t.Run("Delete", func(t *testing.T) {
			err := store.Delete(ctx, profile, key)
			assert.NoError(t, err)

			_, err = store.Get(ctx, profile, key)
			assert.Error(t, err)
		})
	})
}

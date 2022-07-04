package backend

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"io/ioutil"
	"os"
	"os/user"
	"path"
	"time"
)

type FileStore struct {
	storeLocation string
	projectID     string
	cryptoKey     []byte
}

func NewFileStore(storeLocation, projectID, cryptoKey string) *FileStore {
	disc := &FileStore{
		projectID: projectID,
		cryptoKey: []byte(cryptoKey),
	}
	disc.storeLocation = disc.secretStoreLocation(storeLocation, projectID)
	return disc
}

type FileStoreEntry struct {
	Value   []byte
	KeyInfo Key
}

// Get reads the store from file, fetches and decrypt the value for given key
func (d *FileStore) Get(_ context.Context, _ *Profile, key string) ([]byte, error) {
	storeData, err := d.getStore()
	if err != nil {
		return nil, err
	}

	for _, data := range storeData {
		if data.KeyInfo.Name == key {
			data, err := d.decrypt(data.Value, d.cryptoKey)
			if err != nil {
				return nil, fmt.Errorf("message authentication failed")
			}
			return data, nil
		}
	}
	return nil, fmt.Errorf("%s not found", key)
}

// List reads the store from file, and fetch all keys
func (d *FileStore) List(_ context.Context, _ *Profile) (keys []Key, err error) {
	storeData, err := d.getStore()
	if err != nil {
		return nil, err
	}
	for _, info := range storeData {
		keys = append(keys, info.KeyInfo)
	}
	return
}

// CheckExists checks if given key exists in the (file)store
func (d *FileStore) CheckExists(_ context.Context, _ *Profile, key string) (bool, error) {
	storeData, err := d.getStore()
	if err != nil {
		return false, err
	}

	for _, each := range storeData {
		if each.KeyInfo.Name == key {
			return true, nil
		}
	}
	return false, nil
}

// Put a new Key with encrypted password in the store. Put overwrites the entire store file with the updated store
func (d *FileStore) Put(_ context.Context, _ *Profile, key, value string) error {
	if err := d.createStoreIfNotExists(); err != nil {
		return err
	}
	encryptedData, err := d.encrypt([]byte(value), d.cryptoKey)
	if err != nil {
		return err
	}

	owner := ""
	currUser, err := user.Current()
	if err == nil {
		owner = currUser.Name
	}
	newStore := FileStoreEntry{
		Value: encryptedData,
		KeyInfo: Key{
			Name:      key,
			CreatedAt: time.Now(),
			Owner:     owner,
			Info:      "",
		},
	}

	var store []FileStoreEntry
	discStoreEntries, err := d.getStore()
	if err != nil {
		return err
	}
	if discStoreEntries != nil {
		store = append(store, discStoreEntries...)
	}
	store = append(store, newStore)
	data, err := json.Marshal(&store)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(d.storeLocation, data, 0600); err != nil {
		return err
	}
	return nil
}

// Delete a key from the store. Delete overwrites the entire store file with the updated store values
func (d *FileStore) Delete(_ context.Context, _ *Profile, key string) error {
	discStoreEntries, err := d.getStore()
	if err != nil {
		return err
	}
	var newDiscStore []FileStoreEntry
	for _, entry := range discStoreEntries {
		if entry.KeyInfo.Name != key {
			newDiscStore = append(newDiscStore, entry)
		}
	}

	data := []byte("")
	// prevents "nil" being written to file
	if len(newDiscStore) > 0 {
		data, err = json.Marshal(&newDiscStore)
		if err != nil {
			return err
		}
	}
	if err := ioutil.WriteFile(d.storeLocation, data, 0600); err != nil {
		return err
	}

	return nil
}

func (d *FileStore) Close() error {
	return nil
}

// encrypt data based on the argon2 hashing algorithm and xchacha20 cipher algorithm
func (d *FileStore) encrypt(data, pass []byte) ([]byte, error) {
	salt := makeNonce(16)
	key := argon2.Key(pass, salt, 3, 32*1024, 4, 32)
	cipher, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := makeNonce(24)
	cipherText := cipher.Seal(nil, nonce, data, nil)
	return append(append(salt, nonce...), cipherText...), nil
}

// decrypt data based on the argon2 hashing algorithm and xchacha20 cipher algorithm
func (d *FileStore) decrypt(data, pass []byte) ([]byte, error) {
	if len(data) < 40 {
		return nil, errors.New("data has incorrect format")
	}
	salt := data[:16]
	nonce := data[16:40]
	data = data[40:]

	key := argon2.Key(pass, salt, 3, 32*1024, 4, 32)
	cipher, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	plaintext, err := cipher.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// makeNonce generates a secure random nonce used for encryption of the passwords
func makeNonce(len int) []byte {
	salt := make([]byte, len)
	n, err := rand.Reader.Read(salt)
	if err != nil {
		panic(err)
	}
	if n != len {
		panic("An error occurred while generating salt")
	}
	return salt
}

// getStore loads the file based store from disc
func (d *FileStore) getStore() ([]FileStoreEntry, error) {
	if err := d.createStoreIfNotExists(); err != nil {
		return nil, err
	}
	data, err := ioutil.ReadFile(d.storeLocation)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}
	var store []FileStoreEntry
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, err
	}
	return store, nil
}

// secretStoreLocation calculates the path to the file based store
func (d *FileStore) secretStoreLocation(location, projectID string) string {
	if len(location) == 0 {
		location = path.Join(os.Getenv("HOME"), fmt.Sprintf("%s.secrets.kiya", projectID))
	}
	return location
}

// createStoreIfNotExists creates the file store on disc if it does not exists and initializes with an empty value
func (d *FileStore) createStoreIfNotExists() error {
	if _, err := os.Stat(d.storeLocation); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			err = ioutil.WriteFile(d.storeLocation, []byte(""), 0600)
			if err != nil {
				return err
			}
		}
		return err
	}
	return nil
}

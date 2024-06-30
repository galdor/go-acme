package acme

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"io/ioutil"
	"os"
	"path"
)

type FileSystemDataStore struct {
	rootPath    string
	accountPath string
}

func NewFileSystemDataStore(rootPath string) (*FileSystemDataStore, error) {
	if err := os.MkdirAll(rootPath, 0700); err != nil {
		return nil, fmt.Errorf("cannot create directory %q: %w", rootPath, err)
	}

	s := FileSystemDataStore{
		rootPath:    rootPath,
		accountPath: path.Join(rootPath, "account.json"),
	}

	return &s, nil
}

func (s *FileSystemDataStore) LoadAccountData() (*AccountData, error) {
	jsonAccountData, err := s.loadFile(s.accountPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrNoAccount
		}

		return nil, err
	}

	var accountData AccountData
	if err := json.Unmarshal(jsonAccountData, &accountData); err != nil {
		return nil, fmt.Errorf("cannot decode %q: %w", s.accountPath, err)
	}

	return &accountData, nil
}

func (s *FileSystemDataStore) loadFile(filePath string) ([]byte, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("cannot read %q: %w", filePath, err)
	}

	return data, nil
}

func (s *FileSystemDataStore) StoreAccountData(accountData *AccountData) error {
	jsonAccountData, err := json.Marshal(accountData)
	if err != nil {
		return fmt.Errorf("cannot encode account data: %w", err)
	}

	return s.storeFile(s.accountPath, jsonAccountData)
}

func (s *FileSystemDataStore) storeFile(filePath string, data []byte) error {
	tmpPath := filePath + ".tmp"

	if err := ioutil.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("cannot write %q: %w", tmpPath, err)
	}

	if err := os.Rename(tmpPath, filePath); err != nil {
		return fmt.Errorf("cannot rename %q to %q: %w", tmpPath, filePath, err)
	}

	return nil
}

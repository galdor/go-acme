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
	var data AccountData
	if err := s.loadJSONFile(s.accountPath, &data); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrAccountNotFound
		}

		return nil, err
	}

	return &data, nil
}

func (s *FileSystemDataStore) LoadCertificateData(name string) (*CertificateData, error) {
	var data CertificateData
	if err := s.loadJSONFile(s.certificatePath(name), &data); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrCertificateNotFound
		}

		return nil, err
	}

	return &data, nil
}

func (s *FileSystemDataStore) StoreAccountData(data *AccountData) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("cannot encode account data: %w", err)
	}

	return s.storeFile(s.accountPath, jsonData)
}

func (s *FileSystemDataStore) StoreCertificateData(data *CertificateData) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("cannot encode certificate data: %w", err)
	}

	return s.storeFile(s.certificatePath(data.Name), jsonData)
}

func (s *FileSystemDataStore) certificatePath(name string) string {
	return path.Join(s.rootPath, "certificates", name+".json")
}

func (s *FileSystemDataStore) loadFile(filePath string) ([]byte, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("cannot read %q: %w", filePath, err)
	}

	return data, nil
}

func (s *FileSystemDataStore) loadJSONFile(filePath string, dest any) error {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("cannot read %q: %w", filePath, err)
	}

	if err := json.Unmarshal(data, dest); err != nil {
		return fmt.Errorf("cannot decode %q: %w", filePath, err)
	}

	return nil
}

func (s *FileSystemDataStore) storeFile(filePath string, data []byte) error {
	tmpPath := filePath + ".tmp"

	dirPath := path.Dir(filePath)
	if err := os.MkdirAll(dirPath, 0700); err != nil {
		return fmt.Errorf("cannot create directory %q: %w", dirPath, err)
	}

	if err := ioutil.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("cannot write %q: %w", tmpPath, err)
	}

	if err := os.Rename(tmpPath, filePath); err != nil {
		return fmt.Errorf("cannot rename %q to %q: %w", tmpPath, filePath, err)
	}

	return nil
}

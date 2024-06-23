package acme

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"io/ioutil"
	"os"
	"path"
	"strconv"
	"time"
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
		accountPath: path.Join(rootPath, "account"),
	}

	return &s, nil
}

func (s *FileSystemDataStore) LoadAccountData() (*AccountData, error) {
	if _, err := os.Stat(s.accountPath); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrNoAccount
		}

		return nil, fmt.Errorf("cannot stat %q: %w", s.accountPath, err)
	}

	var data AccountData

	// Account URI
	uri, err := s.loadFile(path.Join(s.accountPath, "uri"))
	if err != nil {
		return nil, err
	}

	data.URI = string(uri)

	// Private key
	privateKeyData, err := s.loadFile(path.Join(s.accountPath, "private-key"))
	if err != nil {
		return nil, err
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(privateKeyData)
	if err != nil {
		return nil, fmt.Errorf("cannot parse PKCS #8 data: %w", err)
	}

	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key of type %T cannot be used to "+
			"sign data", privateKey)
	}

	data.PrivateKey = signer

	return &data, nil
}

func (s *FileSystemDataStore) loadFile(filePath string) ([]byte, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("cannot read %q: %w", filePath, err)
	}

	return data, nil
}

func (s *FileSystemDataStore) StoreAccountData(accountData *AccountData) error {
	suffix := strconv.FormatInt(time.Now().UnixNano(), 10)
	tmpDirPath := path.Join(s.rootPath, "account-"+suffix)
	tmpAccountPath := s.accountPath + ".tmp"

	if err := os.MkdirAll(tmpDirPath, 0700); err != nil {
		return fmt.Errorf("cannot create directory %q: %w", tmpDirPath, err)
	}

	if err := s.storeFiles(accountData, tmpDirPath); err != nil {
		os.RemoveAll(tmpDirPath)

		return err
	}

	if err := os.Symlink(path.Base(tmpDirPath), tmpAccountPath); err != nil {
		os.RemoveAll(tmpDirPath)

		return fmt.Errorf("cannot link %q to %q: %w",
			tmpAccountPath, tmpDirPath, err)
	}

	if err := os.Rename(tmpAccountPath, s.accountPath); err != nil {
		os.RemoveAll(tmpAccountPath)
		os.RemoveAll(tmpDirPath)

		return fmt.Errorf("cannot rename %q to %q: %w",
			tmpAccountPath, s.accountPath, err)
	}

	return nil
}

func (s *FileSystemDataStore) storeFiles(accountData *AccountData, dirPath string) error {
	var err error

	// Account URI
	err = s.storeFile(path.Join(dirPath, "uri"), []byte(accountData.URI))
	if err != nil {
		return err
	}

	// Private key
	privateKeyData, err := x509.MarshalPKCS8PrivateKey(accountData.PrivateKey)
	if err != nil {
		return fmt.Errorf("cannot encode private key: %w", err)
	}

	err = s.storeFile(path.Join(dirPath, "private-key"), privateKeyData)
	if err != nil {
		return err
	}

	return nil
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

package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

func readAdminCredentials(path string) ([]AdminAccount, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot read PF_ADMIN_CREDS_FILE")
	}
	defer file.Close()
	const maxBytes = 4096
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil || len(data) > maxBytes {
		return nil, errors.New("PF_ADMIN_CREDS_FILE cannot be read or exceeds 4096 bytes")
	}
	var accounts []AdminAccount
	for index, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimSuffix(line, []byte("\r"))
		if len(line) == 0 {
			continue
		}
		user, password, ok := strings.Cut(string(line), ":")
		if !ok || user == "" || password == "" || bytes.ContainsAny(line, "\r\x00") {
			return nil, fmt.Errorf("PF_ADMIN_CREDS_FILE line %d must contain user:password", index+1)
		}
		accounts = append(accounts, AdminAccount{User: user, Password: password})
	}
	if len(accounts) == 0 {
		return nil, errors.New("PF_ADMIN_CREDS_FILE must contain at least one user:password line")
	}
	return accounts, nil
}

package config

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
)

func readAdminCredentials(path string) (string, string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", "", errors.New("cannot read PF_ADMIN_CREDS_FILE")
	}
	defer file.Close()
	const maxBytes = 4096
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil || len(data) > maxBytes {
		return "", "", errors.New("PF_ADMIN_CREDS_FILE cannot be read or exceeds 4096 bytes")
	}
	data = bytes.TrimSuffix(data, []byte("\n"))
	data = bytes.TrimSuffix(data, []byte("\r"))
	user, password, ok := strings.Cut(string(data), ":")
	if !ok || user == "" || password == "" || bytes.ContainsAny(data, "\r\n\x00") {
		return "", "", errors.New("PF_ADMIN_CREDS_FILE must contain one user:password line")
	}
	return user, password, nil
}

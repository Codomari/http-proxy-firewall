package cve2026109619

import (
	"errors"
	"strings"
	"testing"
)

func TestCheck(t *testing.T) {
	tests := []struct {
		name   string
		fields []string
		custom []string
		block  bool
	}{
		{"default", []string{"title", DefaultUploadProgressName}, nil, true},
		{"default stays blocked", []string{DefaultUploadProgressName}, []string{"CUSTOM_PROGRESS"}, true},
		{"custom", []string{"CUSTOM_PROGRESS"}, []string{"CUSTOM_PROGRESS"}, true},
		{"multiple custom names", []string{"OTHER_PROGRESS"}, []string{"CUSTOM_PROGRESS", "OTHER_PROGRESS"}, true},
		{"no fields", nil, nil, false},
		{"unrelated duplicates", []string{"title", "title"}, nil, false},
		{"case sensitive default", []string{"php_session_upload_progress"}, nil, false},
		{"case sensitive custom", []string{"custom_progress"}, []string{"CUSTOM_PROGRESS"}, false},
		{"exact names", []string{DefaultUploadProgressName + "[]", DefaultUploadProgressName + "_other"}, nil, false},
		{"ignore empty config", []string{"", "title"}, []string{""}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Check(tt.fields, tt.custom)
			if tt.block {
				if !errors.Is(err, ErrUploadProgress) {
					t.Fatalf("expected upload progress rejection, got %v", err)
				}
			} else if err != nil {
				t.Fatalf("unexpected rejection: %v", err)
			}
		})
	}
}

func TestCheckDoesNotExposeFieldNames(t *testing.T) {
	name := "custom-progress\nforged-log-line"
	err := Check([]string{name}, []string{name})
	if err == nil || strings.Contains(err.Error(), name) || strings.ContainsAny(err.Error(), "\r\n") {
		t.Fatalf("expected a fixed rejection message, got %v", err)
	}
}

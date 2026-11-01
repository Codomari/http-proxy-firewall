// Package cve2026109619 reduces exposure to PHP's session upload progress
// consumer of stale request state described in CVE-2026-109619. Other lifecycle
// paths require a PHP update.
// See https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp.
package cve2026109619

import "errors"

const DefaultUploadProgressName = "PHP_SESSION_UPLOAD_PROGRESS"

var ErrUploadProgress = errors.New("CVE-2026-109619: session upload progress field blocked")

// Check rejects parsed non-file multipart fields that activate upload progress.
// Matching is exact and case sensitive, as in PHP's multipart callback. Supply
// additional names for deployment-specific session.upload_progress.name settings;
// the PHP default remains blocked and empty configured names are ignored.
func Check(fieldNames []string, additionalNames []string) error {
	for _, fieldName := range fieldNames {
		if fieldName == DefaultUploadProgressName {
			return ErrUploadProgress
		}
		for _, name := range additionalNames {
			if name != "" && fieldName == name {
				return ErrUploadProgress
			}
		}
	}
	return nil
}

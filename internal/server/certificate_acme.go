package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

type certificateACMETransport struct {
	guard *certificateGuard
	next  http.RoundTripper
}

func (t *certificateACMETransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Method == http.MethodPost && request.Body != nil {
		// ACME uses JWS. Inspect only the signed payload's DNS identifiers and
		// forward the original bytes unchanged; never expose account/key data.
		data, err := io.ReadAll(io.LimitReader(request.Body, (64<<10)+1))
		_ = request.Body.Close()
		if err != nil || len(data) > 64<<10 {
			return nil, errors.New("unable to inspect ACME request")
		}
		forward := request.Clone(request.Context())
		forward.Body = io.NopCloser(bytes.NewReader(data))
		var signed struct {
			Payload string `json:"payload"`
		}
		if err := json.Unmarshal(data, &signed); err != nil {
			return nil, errors.New("invalid ACME signed request")
		}
		if signed.Payload != "" {
			payload, err := base64.RawURLEncoding.DecodeString(signed.Payload)
			if err != nil {
				return nil, errors.New("invalid ACME payload")
			}
			var order struct {
				Identifiers []struct {
					Type  string `json:"type"`
					Value string `json:"value"`
				} `json:"identifiers"`
			}
			if err := json.Unmarshal(payload, &order); err != nil {
				return nil, errors.New("invalid ACME order")
			}
			for _, identifier := range order.Identifiers {
				if identifier.Type != "dns" {
					return nil, errors.New("only DNS certificates are allowed")
				}
				host, err := certificateHostname(identifier.Value)
				if err != nil {
					return nil, err
				}
				// Renewal uses the same gate. A recent admission proof may be
				// reused so one issuance does not repeat its three HTTP attempts.
				if err := t.guard.check(request.Context(), host); err != nil {
					return nil, err
				}
			}
		}
		request = forward
	}
	return t.next.RoundTrip(request)
}

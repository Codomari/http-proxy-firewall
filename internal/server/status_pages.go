package server

import (
	_ "embed"
	"encoding/json"
	"html"
	"strings"
)

//go:embed assets/status_messages.json
var statusMessagesJSON []byte

//go:embed assets/status_language.js
var statusLanguageJS string

//go:embed assets/status_language.css
var statusLanguageCSS string

type statusMessages struct {
	RestartTitle       string `json:"restart_title"`
	Reassurance        string `json:"reassurance"`
	Reconnecting       string `json:"reconnecting"`
	Ready              string `json:"ready"`
	ReadyPlaying       string `json:"ready_playing"`
	Noscript           string `json:"noscript"`
	Reload             string `json:"reload"`
	BlockedTitle       string `json:"blocked_title"`
	BlockedMessage     string `json:"blocked_message"`
	TLSHostnameTitle   string `json:"tls_hostname_title"`
	TLSHostnameMessage string `json:"tls_hostname_message"`
	BodyLimitTitle     string `json:"body_limit_title"`
	BodyLimitMessage   string `json:"body_limit_message"`
	InputLimitMessage  string `json:"input_limit_message"`
	ServerErrorTitle   string `json:"server_error_title"`
	ServerErrorMessage string `json:"server_error_message"`
	BadGatewayTitle    string `json:"bad_gateway_title"`
	BadGatewayMessage  string `json:"bad_gateway_message"`
	UnavailableTitle   string `json:"unavailable_title"`
	UnavailableMessage string `json:"unavailable_message"`
	GameTitle          string `json:"game_title"`
	GameRules          string `json:"game_rules"`
	RestartGame        string `json:"restart_game"`
	LanguageLabel      string `json:"language_label"`
	YourTurn           string `json:"your_turn"`
	ComputerTurn       string `json:"computer_turn"`
	Win                string `json:"win"`
	Lose               string `json:"lose"`
	Draw               string `json:"draw"`
	PlayAgain          string `json:"play_again"`
	Continue           string `json:"continue"`
	CellLabel          string `json:"cell_label"`
}

type statusPage struct{ language, restarting, blacklisted, tlsHostnameRequired, requestTooLarge, inputTooLarge, serverError, badGateway, unavailable string }

var statusPages = buildStatusPages()

func buildStatusPages() map[string]statusPage {
	var catalog map[string]statusMessages
	if err := json.Unmarshal(statusMessagesJSON, &catalog); err != nil {
		panic(err)
	}
	pages := make(map[string]statusPage, len(catalog))
	translations, err := json.Marshal(catalog)
	if err != nil {
		panic(err)
	}
	for language, messages := range catalog {
		var options strings.Builder
		for _, entry := range [][2]string{{"en", "English"}, {"az", "Azərbaycanca"}, {"tr", "Türkçe"}, {"ru", "Русский"}, {"uk", "Українська"}, {"de", "Deutsch"}, {"it", "Italiano"}, {"es", "Español"}, {"pt", "Português"}, {"kk-KZ", "Қазақша (Қазақстан)"}, {"ja", "日本語"}} {
			selected := ""
			if entry[0] == language {
				selected = " selected"
			}
			options.WriteString(`<option value="` + entry[0] + `"` + selected + `>` + html.EscapeString(entry[1]) + `</option>`)
		}
		replacer := strings.NewReplacer(
			"{{LANG}}", html.EscapeString(language),
			"{{RESTART_TITLE}}", html.EscapeString(messages.RestartTitle),
			"{{REASSURANCE}}", html.EscapeString(messages.Reassurance),
			"{{RECONNECTING}}", html.EscapeString(messages.Reconnecting),
			"{{NOSCRIPT}}", html.EscapeString(messages.Noscript),
			"{{RELOAD}}", html.EscapeString(messages.Reload),
			"{{GAME_TITLE}}", html.EscapeString(messages.GameTitle),
			"{{GAME_RULES}}", html.EscapeString(messages.GameRules),
			"{{RESTART_GAME}}", html.EscapeString(messages.RestartGame),
			"{{LANGUAGE_LABEL}}", html.EscapeString(messages.LanguageLabel),
			"{{LANGUAGE_OPTIONS}}", options.String(),
			"{{TRANSLATIONS}}", html.EscapeString(string(translations)),
			"{{LANGUAGE_SCRIPT}}", statusLanguageJS,
			"{{LANGUAGE_STYLE}}", statusLanguageCSS,
			"{{YOUR_TURN}}", html.EscapeString(messages.YourTurn),
			"{{PLAY_AGAIN}}", html.EscapeString(messages.PlayAgain),
			"{{CONTINUE}}", html.EscapeString(messages.Continue),
			"{{BLOCKED_TITLE}}", html.EscapeString(messages.BlockedTitle),
			"{{BLOCKED_MESSAGE}}", html.EscapeString(messages.BlockedMessage),
			"{{TLS_HOSTNAME_TITLE}}", html.EscapeString(messages.TLSHostnameTitle),
			"{{TLS_HOSTNAME_MESSAGE}}", html.EscapeString(messages.TLSHostnameMessage),
			"{{STYLE}}", restartingCSS, "{{SCRIPT}}", restartingJS,
		)
		errorPage := func(kind, status, titleKey, messageKey, title, message string) string {
			return replacer.Replace(strings.NewReplacer(
				"{{PAGE_TYPE}}", kind, "{{STATUS_CODE}}", status,
				"{{STATUS_TITLE_KEY}}", titleKey, "{{STATUS_MESSAGE_KEY}}", messageKey,
				"{{STATUS_TITLE}}", html.EscapeString(title), "{{STATUS_MESSAGE}}", html.EscapeString(message),
			).Replace(statusErrorPage))
		}
		pages[language] = statusPage{
			language: language, restarting: replacer.Replace(restartingHTML),
			blacklisted:         errorPage("blacklisted", "409", "blocked_title", "blocked_message", messages.BlockedTitle, messages.BlockedMessage),
			tlsHostnameRequired: errorPage("tls-hostname", "409", "tls_hostname_title", "tls_hostname_message", messages.TLSHostnameTitle, messages.TLSHostnameMessage),
			requestTooLarge:     errorPage("request-too-large", "413", "body_limit_title", "body_limit_message", messages.BodyLimitTitle, messages.BodyLimitMessage),
			inputTooLarge:       errorPage("request-too-large", "413", "body_limit_title", "input_limit_message", messages.BodyLimitTitle, messages.InputLimitMessage),
			serverError:         errorPage("server-error", "500", "server_error_title", "server_error_message", messages.ServerErrorTitle, messages.ServerErrorMessage),
			badGateway:          errorPage("bad-gateway", "502", "bad_gateway_title", "bad_gateway_message", messages.BadGatewayTitle, messages.BadGatewayMessage),
			unavailable:         errorPage("service-unavailable", "503", "unavailable_title", "unavailable_message", messages.UnavailableTitle, messages.UnavailableMessage),
		}
	}
	return pages
}

func statusPageForCountry(country string) statusPage {
	language := "en"
	switch strings.ToLower(strings.TrimSpace(country)) {
	case "azerbaijan", "az":
		language = "az"
	case "turkey", "türkiye", "turkiye", "tr":
		language = "tr"
	case "russia", "russian federation", "ru":
		language = "ru"
	case "ukraine", "ua":
		language = "uk"
	case "germany", "de":
		language = "de"
	case "italy", "it":
		language = "it"
	case "spain", "es":
		language = "es"
	case "portugal", "pt":
		language = "pt"
	case "kazakhstan", "kz":
		language = "kk-KZ"
	case "japan", "jp":
		language = "ja"
	}
	return statusPages[language]
}

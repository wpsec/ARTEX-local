package server

import (
	"encoding/json"
	"mime"
	"net/url"
	"strings"
)

const redactedDeliveryValue = "[REDACTED]"

func redactDeliveryPacket(packet string) string {
	separator := "\r\n\r\n"
	index := strings.Index(packet, separator)
	if index < 0 {
		separator = "\n\n"
		index = strings.Index(packet, separator)
	}
	if index < 0 {
		return redactDeliveryHead(packet)
	}
	originalHead := packet[:index]
	head := redactDeliveryHead(originalHead)
	body := redactDeliveryBody(packet[index+len(separator):], deliveryPacketContentType(originalHead))
	if head == "" {
		return body
	}
	return head + separator + body
}

func redactDeliveryHead(head string) string {
	lines := strings.Split(strings.ReplaceAll(head, "\r\n", "\n"), "\n")
	for i, line := range lines {
		if i == 0 {
			lines[i] = redactDeliveryRequestLine(line)
			continue
		}
		name, _, ok := strings.Cut(line, ":")
		if ok && sensitiveDeliveryField(name) {
			lines[i] = name + ": " + redactedDeliveryValue
		}
	}
	return strings.Join(lines, "\r\n")
}

func redactDeliveryRequestLine(line string) string {
	parts := strings.Fields(line)
	if len(parts) != 3 || !strings.HasPrefix(strings.ToUpper(parts[2]), "HTTP/") {
		return line
	}
	target, err := url.ParseRequestURI(parts[1])
	if err != nil || target.RawQuery == "" {
		return line
	}
	query := target.Query()
	for key := range query {
		if sensitiveDeliveryField(key) {
			query[key] = []string{redactedDeliveryValue}
		}
	}
	target.RawQuery = query.Encode()
	parts[1] = target.String()
	return strings.Join(parts, " ")
}

func deliveryPacketContentType(head string) string {
	for _, line := range strings.Split(strings.ReplaceAll(head, "\r\n", "\n"), "\n") {
		name, value, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(name), "content-type") {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func redactDeliveryBody(body, contentType string) string {
	var value any
	decoder := json.NewDecoder(strings.NewReader(body))
	decoder.UseNumber()
	if decoder.Decode(&value) == nil {
		redactDeliveryJSON(value)
		if encoded, err := json.Marshal(value); err == nil {
			return string(encoded)
		}
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		return body
	}
	if values, err := url.ParseQuery(body); err == nil && len(values) > 0 {
		for key := range values {
			if sensitiveDeliveryField(key) {
				values[key] = []string{redactedDeliveryValue}
			}
		}
		return values.Encode()
	}
	return body
}

func redactDeliveryJSON(value any) {
	switch item := value.(type) {
	case map[string]any:
		for key, nested := range item {
			if sensitiveDeliveryField(key) {
				item[key] = redactedDeliveryValue
			} else {
				redactDeliveryJSON(nested)
			}
		}
	case []any:
		for _, nested := range item {
			redactDeliveryJSON(nested)
		}
	}
}

func sensitiveDeliveryField(name string) bool {
	normalized := strings.ToLower(strings.NewReplacer("-", "", "_", "", ".", "").Replace(name))
	for _, marker := range []string{
		"authorization", "apikey", "password", "passwd", "secret", "token", "credential",
		"cookie", "session", "privatekey", "clientsecret", "csrf", "jwt",
	} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

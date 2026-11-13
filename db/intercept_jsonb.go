package db

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

const interceptNULMarker = "⟦NUL⟧"

// interceptJSONBSafe preserves NUL bytes as a visible, reversible marker because
// PostgreSQL jsonb cannot represent U+0000. Existing marker prefixes are escaped so
// literal marker text remains distinguishable from an encoded NUL in stored data.
func interceptJSONBSafe(raw []byte) ([]byte, error) {
	if !bytes.Contains(raw, []byte(`\u0000`)) {
		return raw, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, err
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, errors.New("multiple JSON values")
		}
		return nil, err
	}
	if !interceptHasNUL(value) {
		return raw, nil
	}
	return json.Marshal(interceptEncodeNUL(value))
}

func interceptHasNUL(value any) bool {
	switch v := value.(type) {
	case string:
		return strings.ContainsRune(v, '\x00')
	case []any:
		for _, item := range v {
			if interceptHasNUL(item) {
				return true
			}
		}
	case map[string]any:
		for key, item := range v {
			if strings.ContainsRune(key, '\x00') || interceptHasNUL(item) {
				return true
			}
		}
	}
	return false
}

func interceptEncodeNUL(value any) any {
	switch v := value.(type) {
	case string:
		return interceptEncodeNULString(v)
	case []any:
		for i := range v {
			v[i] = interceptEncodeNUL(v[i])
		}
		return v
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			out[interceptEncodeNULString(key)] = interceptEncodeNUL(item)
		}
		return out
	default:
		return value
	}
}

func interceptEncodeNULString(value string) string {
	var out strings.Builder
	for _, r := range value {
		switch r {
		case '\x00':
			out.WriteString(interceptNULMarker)
		case '⟦':
			out.WriteRune('⟦')
			out.WriteRune('⟦')
		default:
			out.WriteRune(r)
		}
	}
	return out.String()
}

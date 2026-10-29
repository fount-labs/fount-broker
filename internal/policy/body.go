package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
)

// Body says what a destination's request body may hold. The broker checks it
// before anything is sent.
type Body struct {
	Kind BodyKind
	// MaxBytes caps the body. Zero means the frame limit alone.
	MaxBytes int
	// Fields lists the top-level keys a BodyObject may have. Any other key
	// refuses the request.
	Fields map[string]Field
}

type BodyKind int

const (
	// BodyNone: the request has no body.
	BodyNone BodyKind = iota
	// BodyOpaque: any bytes, such as a chat request sealed to an enclave or
	// sent to a model provider.
	BodyOpaque
	// BodyObject: a JSON object with only the listed fields.
	BodyObject
)

// Field is one allowed key of a BodyObject.
type Field struct {
	// Types lists the JSON types the value may have: "string", "number",
	// "boolean", "object", "array" or "null".
	Types    []string
	Required bool
	// Pattern, when set, must match a string value in full.
	Pattern *regexp.Regexp
	// Fields, when set, is the rule for an object value: only these keys,
	// each checked like a top-level field.
	Fields map[string]Field
	// Items, when set, is the rule for each element of an array value, which
	// must have between MinItems and MaxItems elements.
	Items              *Field
	MinItems, MaxItems int
}

// Check reports why body breaks the rule, or nil.
func (b Body) Check(body []byte) error {
	if b.MaxBytes > 0 && len(body) > b.MaxBytes {
		return fmt.Errorf("body is %d bytes, over the %d byte limit", len(body), b.MaxBytes)
	}
	switch b.Kind {
	case BodyNone:
		if len(body) > 0 {
			return errors.New("this destination takes no body")
		}
		return nil
	case BodyOpaque:
		return nil
	case BodyObject:
		return b.checkObject(body)
	}
	return fmt.Errorf("unknown body kind %d", b.Kind)
}

func (b Body) checkObject(body []byte) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var obj map[string]json.RawMessage
	if err := dec.Decode(&obj); err != nil {
		return fmt.Errorf("body must be a JSON object: %w", err)
	}
	if obj == nil {
		return errors.New("body must be a JSON object")
	}
	if dec.More() {
		return errors.New("trailing data after the JSON body")
	}
	return checkFields(obj, b.Fields)
}

func checkFields(obj map[string]json.RawMessage, fields map[string]Field) error {
	for key, raw := range obj {
		field, ok := fields[key]
		if !ok {
			return fmt.Errorf("field %q is not allowed", key)
		}
		if err := field.check(raw); err != nil {
			return fmt.Errorf("field %q: %w", key, err)
		}
	}
	required := make([]string, 0)
	for key, field := range fields {
		if _, ok := obj[key]; field.Required && !ok {
			required = append(required, key)
		}
	}
	if len(required) > 0 {
		sort.Strings(required)
		return fmt.Errorf("missing required fields %q", required)
	}
	return nil
}

func (f Field) check(raw json.RawMessage) error {
	t := jsonType(raw)
	if !slices.Contains(f.Types, t) {
		return fmt.Errorf("a %s is not allowed, want %v", t, f.Types)
	}
	if f.Pattern != nil && t == "string" {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return err
		}
		if !f.Pattern.MatchString(s) {
			return fmt.Errorf("value doesn't match %s", f.Pattern)
		}
	}
	if f.Fields != nil && t == "object" {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(raw, &obj); err != nil {
			return err
		}
		return checkFields(obj, f.Fields)
	}
	if f.Items != nil && t == "array" {
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return err
		}
		if len(items) < f.MinItems || (f.MaxItems > 0 && len(items) > f.MaxItems) {
			return fmt.Errorf("has %d items, want %d to %d", len(items), f.MinItems, f.MaxItems)
		}
		for i, item := range items {
			if err := f.Items.check(item); err != nil {
				return fmt.Errorf("item %d: %w", i, err)
			}
		}
	}
	return nil
}

func jsonType(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return "invalid"
	}
	switch raw[0] {
	case '"':
		return "string"
	case '{':
		return "object"
	case '[':
		return "array"
	case 't', 'f':
		return "boolean"
	case 'n':
		return "null"
	default:
		return "number"
	}
}

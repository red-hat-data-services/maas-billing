package models

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/openai/openai-go/v3"
	"knative.dev/pkg/apis"
)

// Model extends openai.Model with additional fields.
type Model struct {
	openai.Model `json:",inline"`
	URL          *apis.URL `json:"url,omitempty"`
	Ready        bool      `json:"ready"`
}

// UnmarshalJSON implements custom JSON unmarshalling to work around openai.Model's
// custom unmarshalling that captures all unknown fields.
func (m *Model) UnmarshalJSON(data []byte) error {
	if err := m.Model.UnmarshalJSON(data); err != nil {
		return err
	}

	return m.extractFieldsFromExtraFields()
}

// extractFieldsFromExtraFields uses reflection to automatically populate all
// additional fields (beyond openai.Model) from the ExtraFields map.
func (m *Model) extractFieldsFromExtraFields() error {
	modelValue := reflect.ValueOf(m).Elem()
	modelType := modelValue.Type()

	for i := 0; i < modelType.NumField(); i++ {
		field := modelType.Field(i)
		fieldValue := modelValue.Field(i)

		// Skip the embedded openai.Model field and unexported fields
		if field.Name == "Model" || !fieldValue.CanSet() {
			continue
		}

		jsonTag := field.Tag.Get("json")
		if jsonTag == "" || jsonTag == "-" {
			continue
		}

		jsonFieldName := strings.Split(jsonTag, ",")[0]
		if jsonFieldName == "" {
			jsonFieldName = strings.ToLower(field.Name)
		}

		if extraField, exists := m.Model.JSON.ExtraFields[jsonFieldName]; exists {
			if err := m.setFieldFromExtraField(fieldValue, field.Type, extraField); err != nil {
				return fmt.Errorf("failed setting %s: %w", jsonFieldName, err)
			}
		}
	}

	return nil
}

func (m *Model) setFieldFromExtraField(fieldValue reflect.Value, fieldType reflect.Type, extraField any) error {
	rawValue := ""
	if rf, ok := extraField.(interface{ Raw() string }); ok {
		rawValue = rf.Raw()
	}

	newValue := reflect.New(fieldType)
	if err := json.Unmarshal([]byte(rawValue), newValue.Interface()); err != nil {
		return err
	}
	fieldValue.Set(newValue.Elem())

	return nil
}

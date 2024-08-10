package rdns

import (
	"bytes"
	"strings"
	"text/template"
)

type Template struct {
	textTemplate *template.Template
}

func NewTemplate(text string) (*Template, error) {
	funcMap := template.FuncMap{
		"replaceAll": strings.ReplaceAll,
		"trimPrefix": strings.TrimPrefix,
		"trimSuffix": strings.TrimSuffix,
		"split":      strings.Split,
		"join":       strings.Join,
	}
	textTemplate := template.New("template").Funcs(funcMap)
	textTemplate, err := textTemplate.Parse(text)
	if err != nil {
		return nil, err
	}

	return &Template{
		textTemplate: textTemplate,
	}, nil
}

// Data that is passed to any templates.
type templateInput struct {
	ID            uint16
	Question      string
	QuestionClass string
	QuestionType  string
	Blocklist     string // Only populated if this was blocked
	BlocklistRule string // Only populated if this was blocked
}

// Apply executes the template, e.g. replacing placeholders in the text
// with values from the Query.
func (t *Template) Apply(input templateInput) (string, error) {
	if t == nil {
		return "", nil
	}
	text := new(bytes.Buffer)
	err := t.textTemplate.Execute(text, input)
	return text.String(), err
}

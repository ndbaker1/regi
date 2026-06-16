package cli

import (
	"regexp"
	"strings"
)

type RegexpList []*regexp.Regexp

func (r *RegexpList) String() string {
	if r == nil {
		return ""
	}
	parts := make([]string, len(*r))
	for i, re := range *r {
		parts[i] = re.String()
	}
	return strings.Join(parts, ",")
}

func (r *RegexpList) Set(v string) error {
	re, err := regexp.Compile(v)
	if err != nil {
		return err
	}
	*r = append(*r, re)
	return nil
}

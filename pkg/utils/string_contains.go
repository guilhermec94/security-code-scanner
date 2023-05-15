package utils

import "strings"

func ContainsSubstrings(str string, substrings ...string) bool {
	matches := 0

	for _, sub := range substrings {
		if strings.Contains(str, sub) {
			matches++
		} else {
			break
		}
	}

	return matches == len(substrings)
}

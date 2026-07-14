package mitt

import "strings"

type filterReason uint8

const (
	filterOK filterReason = iota
	filterExtension
	filterSize
)

type filterResult struct {
	reason  filterReason
	pattern string
}

func checkFilter(filename string, size uint64, config ServerConfig) filterResult {
	if size > config.MaxSize {
		return filterResult{reason: filterSize}
	}
	for _, pattern := range config.Reject {
		if matchesGlob(filename, pattern) {
			return filterResult{reason: filterExtension, pattern: pattern}
		}
	}
	if len(config.Accept) > 0 {
		for _, pattern := range config.Accept {
			if matchesGlob(filename, pattern) {
				return filterResult{reason: filterOK}
			}
		}
		return filterResult{reason: filterExtension, pattern: "not in accept list"}
	}
	return filterResult{reason: filterOK}
}

func matchesGlob(filename, pattern string) bool {
	if strings.HasPrefix(pattern, "*.") {
		return strings.HasSuffix(filename, pattern[1:])
	}
	return filename == pattern
}

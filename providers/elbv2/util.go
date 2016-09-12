package awselbv2

import (
	"fmt"
	"hash/adler32"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type ByLengthDesc []string

func (s ByLengthDesc) Len() int {
	return len(s)
}
func (s ByLengthDesc) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
func (s ByLengthDesc) Less(i, j int) bool {
	return len(s[j]) < len(s[i])
}

// Sort the given slice by string length in descending order
func sortByLengthDesc(slice []string) {
	sort.Sort(ByLengthDesc(slice))
}

// returns sliceA string values that are not in sliceB.
func differenceStringSlice(sliceA []string, sliceB []string) []string {
	var diff []string

	for _, a := range sliceA {
		found := false
		for _, b := range sliceB {
			if a == b {
				found = true
				break
			}
		}
		if !found {
			diff = append(diff, a)
		}
	}

	return diff
}

// removes any duplicate string values and returns a new slice.
func removeDuplicates(in []string) (out []string) {
	m := map[string]bool{}
	for _, v := range in {
		if _, found := m[v]; !found {
			out = append(out, v)
			m[v] = true
		}
	}
	return
}

// sanitize the string according to the AWS ELBv2 naming constraints
// for target group and load balancer names:
// - must not have more than 32 chars
// - must consist of only alphanumeric characters or dashes.
// - must not have dashes at the beginning or end.
func sanitizeAwsName(name string) string {
	illegalChars := regexp.MustCompile(`[^[:alnum:]-]`)
	dashes := regexp.MustCompile(`[\-]+`)
	name = illegalChars.ReplaceAllString(name, "-")
	name = dashes.ReplaceAllString(name, "-")
	name = strings.Trim(name, "-")
	if len(name) > 32 {
		name = name[:32]
	}
	return name
}

// generates a name with max. 32 chars having the format:
// <prefix>-<service>-<stack>-<hash of targetPoolName>
// expects the target pool name to be in the format:
// servicename_stackname_environmentUUID
func makeTargetGroupName(targetPoolName string) string {
	adler32Int := adler32.Checksum([]byte(targetPoolName))
	suffix := strconv.FormatUint(uint64(adler32Int), 16)
	limit := 30 - len(PrefixTargetGroupName) - len(suffix)
	parts := strings.Split(targetPoolName, "_")
	service := fmt.Sprintf("%s-%s", parts[0], parts[1])
	if len(service) > limit {
		service = service[:limit]
	}

	return sanitizeAwsName(fmt.Sprintf(TemplateTargetGroupName,
		PrefixTargetGroupName, service, suffix))
}

// checks whether haystack map contains all k/v pairs in the needle.
func containsTags(needle, haystack map[string]string) bool {
	for k, v := range needle {
		found := false
		for k2, v2 := range haystack {
			if k2 == k && v2 == v {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// checks whether the haystack slice contains the needle.
func containsString(needle string, haystack []string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}

	return false
}

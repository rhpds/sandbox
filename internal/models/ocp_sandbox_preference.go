package models

import (
	"math/rand"
	"sort"
)

type ByWeight []OcpSharedClusterConfiguration

func (a ByWeight) Len() int           { return len(a) }
func (a ByWeight) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByWeight) Less(i, j int) bool { return a[i].Weight >= a[j].Weight }

// ApplyPriorityWeight function sorts the clusters by applying
// weight using the passed preferences.
// Then the list is sorted using the weight
func ApplyPriorityWeight(
	clusters []OcpSharedClusterConfiguration,
	preferences map[string]string,
	weight int,
) []OcpSharedClusterConfiguration {
	result := []OcpSharedClusterConfiguration{}
	for _, v := range clusters {
		for kp, vp := range preferences {
			if vl, ok := v.Annotations[kp]; ok {
				if vl == vp {
					v.Weight = v.Weight + weight
				}
			}
		}
		result = append(result, v)
	}
	rand.Shuffle(len(result), func(i, j int) {
		result[i], result[j] = result[j], result[i]
	})
	sort.Sort(ByWeight(result))
	return result
}

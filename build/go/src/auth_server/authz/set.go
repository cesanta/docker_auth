package authz

import (
	"sort"

	mapset "github.com/deckarep/golang-set"
)

func makeSet(ss []string) mapset.Set {
	set := mapset.NewSet()
	for _, s := range ss {
		set.Add(s)
	}
	return set
}

func StringSetIntersection(a, b []string) []string {
	as := makeSet(a)
	bs := makeSet(b)
	d := []string{}
	for s := range as.Intersect(bs).Iter() {
		d = append(d, s.(string))
	}
	sort.Strings(d)
	return d
}

//+build ignore

/*
   Copyright 2021 Cesanta Software Ltd.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       https://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/cooldrip/cstrftime" // strftime implemented with cgo
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
)

func main() {
	dir, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	r, err := git.PlainOpenWithOptions(dir, &git.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		log.Fatal(err)
	}

	t := time.Now()
	ts := cstrftime.Format("%Y%m%d-%H%M%S", t)

	head, err := r.Head()
	if err != nil {
		log.Fatal(err)
	}

	short := fmt.Sprintf("%s", head.Hash())[:8]

	w, err := r.Worktree()
	if err != nil {
		log.Fatal(err)
	}
	status, err := w.Status()
	if err != nil {
		log.Fatal(err)
	}

	is_dirty := ""
	if len(status) > 0 {
		is_dirty = "+"
	}

	branch_or_tag := head.Name().Short()
	if branch_or_tag == "HEAD" {
		branch_or_tag = "?"
	}

	tags, _ := r.Tags()
	tags.ForEach(func(ref *plumbing.Reference) error {
		if ref.Type() != plumbing.HashReference {
			return nil
		}

		if strings.HasPrefix(ref.String(), short) {
			tag := ref.String()
			branch_or_tag = trimRef(strings.Split(tag, " ")[1])
		}
		return nil
	})

	buildId := fmt.Sprintf("%s/%s@%s%s", ts, branch_or_tag, short, is_dirty)

	version := cstrftime.Format("%Y%m%d%H", t)
	if is_dirty != "" || branch_or_tag == "?" {
		version = branch_or_tag
	}

	fmt.Printf("%s\t%s\n", version, buildId)
}

func trimRef(ref string) string {
	ref = strings.TrimPrefix(ref, "refs/heads/")
	ref = strings.TrimPrefix(ref, "refs/tags/")
	return ref
}

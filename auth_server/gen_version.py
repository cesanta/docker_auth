#!/usr/bin/env python3

import datetime
import sys

# Debian/Ubuntu: apt-get install python-git
# PIP: pip install GitPython
import git

repo = git.Repo('.', search_parent_directories=True)


def get_tag_for_commit(repo, commit):
    for tag in repo.tags:
        if tag.commit == commit:
            return tag.name
    return None


if repo.head.is_detached:
    branch_or_tag = get_tag_for_commit(repo, repo.head.commit)
    if branch_or_tag is None:
        branch_or_tag = '?'
else:
    branch_or_tag = repo.active_branch

dirty = repo.is_dirty()

ts = datetime.datetime.utcnow()
build_id = '%s/%s@%s%s' % (ts.strftime('%Y%m%d-%H%M%S'),
                           branch_or_tag,
                           str(repo.head.commit)[:8],
                           '+' if dirty else '')

version = None
if not dirty:
    version = get_tag_for_commit(repo, repo.head.commit)
if version is None:
    version = ts.strftime('%Y%m%d%H')


if len(sys.argv) == 1 or sys.argv[1] == '-':
    f = sys.stdout
else:
    f = open(sys.argv[1], 'w')

with open('version.go', 'w') as f:
    f.write("""\
package main

const (
\tVersion = "{version}"
\tBuildId = "{build_id}"
)
""".format(version=version, build_id=build_id))

with open('version.txt', 'w') as f:
    f.write(version)

f.close()

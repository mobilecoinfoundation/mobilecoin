#!/bin/sh
set -e

ROOT=`git rev-parse --show-toplevel`

echo -n "Installing pre-commit hook..."

# symlink the precommit hook into .git/hooks
# see https://stackoverflow.com/questions/4592838/symbolic-link-to-a-hook-in-git
ln -s -f "$ROOT/hooks/pre-commit" "$ROOT/.git/hooks/pre-commit"
echo " Done."

echo -n "Installing 'theirs' merge driver..."
# define a 'theirs' merge driver which uses unix false utility to always choose
# theirs. In .gitattributes we apply this to Cargo.lock files
git config --local merge.theirs.driver false
echo " Done."

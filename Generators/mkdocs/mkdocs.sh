#!/bin/bash

# Resolve the script directory (./)
ScriptRoot=$(dirname -- "$(readlink --canonicalize -- "$BASH_SOURCE")")

# Resolve the repository root directory (../../)
RepoRoot=$(dirname -- "$(dirname -- "$ScriptRoot")")

# Copy CSS files
mkdir -p "$RepoRoot/docs/assets/stylesheets"
cp "$ScriptRoot/extra.css" "$RepoRoot/docs/assets/stylesheets/extra.css"

# Copy markdown and HTML files
mkdir -p "$RepoRoot/docs/ADDS"
cp "$RepoRoot/README.md" "$RepoRoot/docs/"
cp "$RepoRoot/ADDS/README.md" "$RepoRoot/docs/ADDS/"
cp "$RepoRoot/ADDS/GPOReport.html" "$RepoRoot/docs/ADDS/"

# Copy all images to the assets directory
mkdir -p "$RepoRoot/docs/assets/images"
rsync --archive --no-relative --exclude='*.md' "$RepoRoot/Images/"**/* "$RepoRoot/docs/assets/images"

# Fix image paths in markdown files
# Case 1: Replace paths like ../Images/Screenshots/ with ../assets/images/
find "$RepoRoot/docs" -name "*.md" -exec sed -i 's/\.\.\/Images\/\w\+\//..\/assets\/images\//g' {} \;

# Case 2: Replace paths like Images/Screenshots/ with assets/images/
find "$RepoRoot/docs" -name "*.md" -exec sed -i 's/(Images\/\w\+\//(assets\/images\//g' {} \;

# Normalize named anchors in markdown files by replacing 3 consecutive hyphens with a single one
# Example: Replace #active-directory-domain-controller---ldap-tcp-in with #active-directory-domain-controller-ldap-tcp-in
find "$RepoRoot/docs" -name "*.md" -exec sed -i 's/\(\w\)---\(\w\)/\1-\2/g' {} \;

# Update the requirements file. MkDocs itself must already be installed.
mkdocs get-deps --config-file="$ScriptRoot/mkdocs.yml" > "$ScriptRoot/requirements.txt"

# Install Python dependencies
pip install --quiet --requirement "$ScriptRoot/requirements.txt"

# Build the site
mkdocs build --config-file="$ScriptRoot/mkdocs.yml"

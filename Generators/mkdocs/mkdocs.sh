#!/bin/bash

# Resolve the script directory (./)
ScriptRoot=$(dirname -- "$(readlink --canonicalize -- "$BASH_SOURCE")")

# Resolve the repository root directory (../../)
RepoRoot=$(dirname -- "$(dirname -- "$ScriptRoot")")

# Copy CSS files
mkdir --parents --verbose "$RepoRoot/docs/assets/stylesheets"
cp "$ScriptRoot/extra.css" "$RepoRoot/docs/assets/stylesheets/extra.css"

# Copy markdown and HTML files
mkdir --parents --verbose "$RepoRoot/docs/ADDS"
cp --verbose "$RepoRoot/README.md" "$RepoRoot/docs/"
cp --verbose "$RepoRoot/ADDS/README.md" "$RepoRoot/docs/ADDS/"
cp --verbose "$RepoRoot/ADDS/GPOReport.html" "$RepoRoot/docs/ADDS/"

# Copy all images to the assets directory
mkdir --parents --verbose "$RepoRoot/docs/assets/images"
rsync --archive --no-relative --exclude='*.md' --verbose "$RepoRoot/Images/"**/* "$RepoRoot/docs/assets/images"

# Fix image paths in markdown files
# Case 1: Replace paths like ../Images/Screenshots/ with ../assets/images/
find "$RepoRoot/docs" -name "*.md" -exec sed --in-place 's/\.\.\/Images\/\w\+\//..\/assets\/images\//g' {} \;

# Case 2: Replace paths like Images/Screenshots/ with assets/images/
find "$RepoRoot/docs" -name "*.md" -exec sed  --in-place 's/(Images\/\w\+\//(assets\/images\//g' {} \;

# Normalize named anchors in markdown files by replacing 3 consecutive hyphens with a single one
# Example: Replace #active-directory-domain-controller---ldap-tcp-in with #active-directory-domain-controller-ldap-tcp-in
find "$RepoRoot/docs" -name "*.md" -exec sed --in-place 's/\(\w\)---\(\w\)/\1-\2/g' {} \;

# Update the requirements file
# Note: MkDocs itself must already be installed.
mkdocs get-deps --config-file="$ScriptRoot/mkdocs.yml" --verbose > "$ScriptRoot/requirements.txt"

# Install Python dependencies
pip install --quiet --requirement "$ScriptRoot/requirements.txt"

if [[ "$GITHUB_PAGES" != "true" ]]; then
    # Start a local web server if running outside of GitHub Workflows
    mkdocs serve --config-file="$ScriptRoot/mkdocs.yml"
else
    # Just build the site otherwise
    mkdocs build --config-file="$ScriptRoot/mkdocs.yml"
fi

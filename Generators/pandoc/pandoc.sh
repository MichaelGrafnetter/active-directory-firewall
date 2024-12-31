#!/bin/bash

pushd ../../

# Convert the Markdown file to PDF document using Pandoc
# (This action is also performed automatically by GitHub actions when the README file is changed.)
docker run --rm -v "$(pwd):/data" -u $(id -u):$(id -g) pandoc/extra:3.6.0 \
  --output='Domain_Controller_Firewall.pdf' \
  --pdf-engine=xelatex \
  --template=eisvogel \
  --resource-path=.:ADDS \
  --lua-filter=Generators/pandoc/pandoc.lua \
  --include-in-header=Generators/pandoc/header.tex \
  --metadata-file=Generators/pandoc/metadata.yml \
  --shift-heading-level-by=-1 \
  --top-level-division=section \
  --table-of-contents \
  --toc-depth=2 \
  --number-sections \
  --variable=linkcolor:"[HTML]{4077C0}" \
  --metadata date="`date '+%B %e, %Y'`" \
  ADDS/README.md

# Convert the Markdown file to Word document using Pandoc
docker run --rm -v "$(pwd):/data" -u $(id -u):$(id -g) pandoc/extra:3.6.0 \
  --output='Domain_Controller_Firewall.docx' \
  --resource-path=ADDS \
  --lua-filter=Generators/pandoc/pandoc.lua \
  --shift-heading-level-by=-1 \
  --table-of-contents \
  --toc-depth=2 \
  ADDS/README.md

popd

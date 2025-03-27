#!/bin/bash

pushd ../../

# Convert the Markdown files to PDF documents using Pandoc
# (These actions are also performed automatically by GitHub actions when the README files are changed.)
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

docker run --rm -v "$(pwd):/data" -u $(id -u):$(id -g) pandoc/extra:3.6.0 \
  --output='Certification_Authority_Firewall.pdf' \
  --pdf-engine=xelatex \
  --template=eisvogel \
  --resource-path=.:ADCS \
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
  ADCS/README.md

popd

#!/bin/sh

alias pandock='docker run --rm -v "$(pwd):/data" -u $(id -u):$(id -g) pandoc/extra:3.1.1'

pushd ../../

# Convert the Markdown file to PDF document using Pandoc
# (This action is also performed automatically by GitHub actions when the README file is changed.)
pandock \
  --output='Domain_Controller_Firewall.pdf' \
  --from=markdown \
  --to=pdf \
  --pdf-engine=xelatex \
  --shift-heading-level-by=-1 \
  --top-level-division=section \
  --table-of-contents \
  --toc-depth=2 \
  --number-sections \
  --template=eisvogel \
  --lua-filter=Generators/pandoc/pandoc.lua \
  --variable=lof:true \
  --variable=classoption:oneside \
  --variable=geometry:a4paper,margin=2cm \
  --variable=colorlinks:true \
  --variable=linkcolor:"[HTML]{4077C0}" \
  --variable=titlepage:true \
  --variable=titlepage-rule-color:de0000 \
  --variable=titlepage-rule-height:40 \
  --variable=header-includes:"\usepackage{sectsty} \sectionfont{\clearpage}" \
  --variable=caption-justification:centering \
  --variable=listings-disable-line-numbers:true \
  --metadata date="`date '+%B %e, %Y'`" \
  --resource-path=.:ADDS \
  ADDS/README.md

# Convert the Markdown file to Word document using Pandoc
pandock \
  --output='Domain_Controller_Firewall.docx' \
  --shift-heading-level-by=-1 \
  --table-of-contents \
  --toc-depth=2 \
  --resource-path=ADDS \
  --lua-filter=Generators/pandoc/pandoc.lua \
  ADDS/README.md

popd

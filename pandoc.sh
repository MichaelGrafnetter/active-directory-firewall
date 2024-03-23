#!/bin/bash

# Convert the Markdown file to PDF document using Pandoc
# (This action is also performed automatically by GitHub actions when the README file is changed.)
pandoc --output='Domain_Controller_Firewall.pdf' --shift-heading-level-by=-1 --top-level-division=section --variable=classoption:oneside --variable=papersize:a4 --variable=geometry:margin=2cm --variable=colorlinks:true --variable=lof:true --table-of-contents --toc-depth=2 --number-sections --resource-path=ADDS ADDS/README.md

# Convert the Markdown file to Word document using Pandoc
pandoc --output='Domain_Controller_Firewall.docx' --shift-heading-level-by=-1 --table-of-contents --toc-depth=2 --resource-path=ADDS ADDS/README.md

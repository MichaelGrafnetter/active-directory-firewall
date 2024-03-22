#!/bin/bash

# Convert the Markdown file to Word document using Pandoc
# (This action is also performed automatically by GitHub actions when the README file is changed.)
pandoc --output='Domain_Controller_Firewall.docx' --table-of-contents --toc-depth=2 --number-sections ADDS/README.md

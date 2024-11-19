# Convert the Markdown file to PDF document using Pandoc

[string] $date = Get-Date -Format 'MMMM d, yyyy'
[string] $repoRoot = Join-Path $PSScriptRoot '../../'

docker run --rm --volume "$repoRoot`:/data" pandoc/extra:3.5.0 `
  --output='Domain_Controller_Firewall.pdf' `
  --from=markdown `
  --to=pdf `
  --pdf-engine=xelatex `
  --shift-heading-level-by=-1 `
  --top-level-division=section `
  --table-of-contents `
  --toc-depth=2 `
  --number-sections `
  --template=eisvogel `
  --lua-filter=Generators/pandoc/pandoc.lua `
  --variable=lof:true `
  --variable=classoption:oneside `
  --variable=geometry:a4paper,margin=2cm `
  --variable=colorlinks:true `
  --variable=linkcolor:"[HTML]{4077C0}" `
  --variable=titlepage:true `
  --variable=titlepage-rule-color:de0000 `
  --variable=titlepage-rule-height:40 `
  --variable=header-includes:"\usepackage{sectsty} \sectionfont{\clearpage} \usepackage{Generators/pandoc/wrapfig}" `
  --variable=caption-justification:centering `
  --variable=listings-disable-line-numbers:true `
  --metadata date=$date `
  --resource-path=.:ADDS `
  ADDS/README.md

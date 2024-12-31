# Convert the Markdown file to PDF document using Pandoc

[string] $date = Get-Date -Format 'MMMM d, yyyy'
[string] $repoRoot = Join-Path $PSScriptRoot '../../'

docker run --rm --volume "$repoRoot`:/data" pandoc/extra:3.6.0 `
  --output='Domain_Controller_Firewall.pdf' `
  --pdf-engine=xelatex `
  --template=eisvogel `
  --resource-path=.:ADDS `
  --lua-filter=Generators/pandoc/pandoc.lua `
  --include-in-header=Generators/pandoc/header.tex `
  --metadata-file=Generators/pandoc/metadata.yml `
  --shift-heading-level-by=-1 `
  --top-level-division=section `
  --table-of-contents `
  --toc-depth=2 `
  --number-sections `
  --variable=linkcolor:"[HTML]{4077C0}" `
  --metadata date=$date `
  ADDS/README.md

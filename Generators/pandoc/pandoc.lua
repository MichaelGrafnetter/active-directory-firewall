-- This file contains custom LUA filters for Pandoc.

function Para(para)
  local firstWord = para.content[1].text
  local iconSize = { height = '12px' }

  if firstWord == '[!WARNING]' then
    -- Render the GitHub alert [!WARNING] with the ⚠️ icon.
    table.remove(para.content, 1)

    return pandoc.LineBlock {
      pandoc.Inlines {
        pandoc.Image({}, 'https://github.com/images/icons/emoji/unicode/26a0.png', 'Warning', iconSize),
        pandoc.Strong { pandoc.Str "\tWarning" }
      },
      para.content
    }
  elseif firstWord == '[!NOTE]' then
    -- Render the GitHub alert [!NOTE] with the ℹ icon.
    table.remove(para.content, 1)

    return pandoc.LineBlock {
      pandoc.Inlines {
        pandoc.Image({}, 'https://github.com/images/icons/emoji/unicode/2139.png', 'Note', iconSize),
        pandoc.Strong { pandoc.Str "\tNote" }
      },
      para.content
    }
  elseif firstWord == '[!TIP]' then
    -- Render the GitHub alert [!TIP] with the 💡 icon.
    table.remove(para.content, 1)

    return pandoc.LineBlock {
      pandoc.Inlines {
        pandoc.Image({}, 'https://github.com/images/icons/emoji/unicode/1f4a1.png', 'Tip', iconSize),
        pandoc.Strong { pandoc.Str "\tTip" }
      },
      para.content
    }
  elseif firstWord == '[!IMPORTANT]' then
    -- Render the GitHub alert [!IMPORTANT] with the ❗ icon.
    table.remove(para.content, 1)

    return pandoc.LineBlock {
      pandoc.Inlines {
        pandoc.Image({}, 'https://github.com/images/icons/emoji/unicode/2757.png', 'Important', iconSize),
        pandoc.Strong { pandoc.Str "\tImportant" }
      },
      para.content
    }
  elseif firstWord == '[!CAUTION]' then
    -- Render the GitHub alert [!CAUTION] with the 🛑 icon.
    table.remove(para.content, 1)

    return pandoc.LineBlock {
      pandoc.Inlines {
        pandoc.Image({}, 'https://github.com/images/icons/emoji/unicode/1f6d1.png', 'Caution', iconSize),
        pandoc.Strong { pandoc.Str "\tCaution" }
      },
      para.content
    }
  end
end

if FORMAT:match 'latex' then
  function Image(img)
    -- Apply image alignment.
    if img.attributes.align == "left" or img.attributes.align == "right" then
      -- The option is either 'l' or 'r'.
      local floatfltOption = img.attributes.align:sub(1, 1)
      
      -- Get the actual image width.
      local imageWidth = img.attributes.width

      -- Wrap the image in a floatingfigure environment.
      return {
        pandoc.RawInline('latex', '\\begin{floatingfigure}[' .. floatfltOption .. ']{' .. imageWidth .. '}'),
        img,
        pandoc.RawInline('latex', '\\end{floatingfigure}')
      }
    end
  end

  function RawInline (el)
    -- Transform inline HTML `<br>` elements into format-indepentent line breaks.
    if el.format:match '^html' and el.text:match '%<br ?/?%>' then
      return pandoc.LineBreak()
    end
  end
end

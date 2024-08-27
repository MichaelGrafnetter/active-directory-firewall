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
  
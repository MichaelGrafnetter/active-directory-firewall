-- This file contains custom LUA filters for Pandoc.

function Para(para)
  local firstWord = para.content[1].text

  if firstWord == '[!WARNING]' then
    -- Replace GitHub alert [!WARNING] with **Warning:**
    para.content[1] = pandoc.Strong { pandoc.Str "Warning:" }
    return para
  elseif firstWord == '[!NOTE]' then
    -- Replace GitHub alert [!NOTE] with **Note:**
    para.content[1] = pandoc.Strong { pandoc.Str "Note:" }
    return para
  elseif firstWord == '[!TIP]' then
    -- Replace GitHub alert [!TIP] with **Tip:**
    para.content[1] = pandoc.Strong { pandoc.Str "Tip:" }
    return para
  elseif firstWord == '[!IMPORTANT]' then
    -- Replace GitHub alert [!IMPORTANT] with **Important:**
    para.content[1] = pandoc.Strong { pandoc.Str "Important:" }
    return para
  elseif firstWord == '[!CAUTION]' then
    -- Replace GitHub alert [!CAUTION] with **Caution:**
    para.content[1] = pandoc.Strong { pandoc.Str "Caution:" }
    return para
  end
end
  
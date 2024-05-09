-- This file contains custom LUA filters for Pandoc.

function Para(para)
  if para.content[1].text == '[!WARNING]' then
    -- Replace GitHub alert [!WARNING] with **Warning:**
    para.content[1] = pandoc.Strong { pandoc.Str "Warning:" }
    return para
  elseif para.content[1].text == '[!NOTE]' then
    -- Replace GitHub alert [!NOTE] with **Note:**
    para.content[1] = pandoc.Strong { pandoc.Str "Note:" }
    return para
  elseif para.content[1].text == '[!TIP]' then
    -- Replace GitHub alert [!TIP] with **Tip:**
    para.content[1] = pandoc.Strong { pandoc.Str "Tip:" }
    return para
  elseif para.content[1].text == '[!IMPORTANT]' then
    -- Replace GitHub alert [!IMPORTANT] with **Important:**
    para.content[1] = pandoc.Strong { pandoc.Str "Important:" }
    return para
  elseif para.content[1].text == '[!CAUTION]' then
    -- Replace GitHub alert [!CAUTION] with **Caution:**
    para.content[1] = pandoc.Strong { pandoc.Str "Caution:" }
    return para
  end
end
  
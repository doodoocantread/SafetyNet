/* Loaded synchronously in <head> of every page, BEFORE the stylesheet paints anything.
   The pages are separate documents, so without this the saved theme/language were only applied
   after React rendered (ThemeToggle's effect) — and each menu click flashed the default light
   theme first when the saved choice was dark. Keys are shared with shared.jsx / about.html. */
(function () {
  try {
    var root = document.documentElement;
    var theme = localStorage.getItem("sn-theme");
    if (theme === "dark" || theme === "light") root.setAttribute("data-theme", theme);
    var lang = localStorage.getItem("sn-lang");
    if (lang === "en" || lang === "vi") root.lang = lang;
  } catch (e) { /* storage blocked: fall back to the CSS prefers-color-scheme default */ }
})();

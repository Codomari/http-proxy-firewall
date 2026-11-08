(() => {
  "use strict";
  const page = document.getElementById("status-page");
  const catalog = JSON.parse(page.dataset.translations);
  const selector = document.getElementById("status-language");
  const messages = {...catalog[document.documentElement.lang]};
  window.pfStatusLanguage = {messages};

  function selectLanguage(language, remember) {
    if (!Object.prototype.hasOwnProperty.call(catalog, language)) return;
    Object.assign(messages, catalog[language]);
    document.documentElement.lang = language;
    selector.value = language;
    document.querySelectorAll("[data-i18n]").forEach(element => {
      const key = element.dataset.i18n;
      if (Object.prototype.hasOwnProperty.call(messages, key)) element.textContent = messages[key];
    });
    const titleKey = page.dataset.page === "restart" ? "restart_title" : document.querySelector("h1[data-i18n]").dataset.i18n;
    document.title = (page.dataset.page === "restart" ? "" : `${page.dataset.status} — `) + messages[titleKey];
    if (remember) {
      try { window.localStorage.setItem("pf-status-language", language); } catch (_) { /* Storage may be disabled. */ }
    }
    document.dispatchEvent(new Event("pf-status-language-change"));
  }

  let language = document.documentElement.lang;
  try {
    const saved = window.localStorage.getItem("pf-status-language");
    if (Object.prototype.hasOwnProperty.call(catalog, saved)) language = saved;
  } catch (_) { /* Keep the country-based default. */ }
  selectLanguage(language, false);
  selector.addEventListener("change", () => selectLanguage(selector.value, true));
  document.getElementById("status-language-picker").hidden = false;
})();

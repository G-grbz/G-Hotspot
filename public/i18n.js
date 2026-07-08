(function () {
  const DEFAULT_LANGUAGES = [
    { code: 'en', label: 'EN', name: 'English', locale: 'en-US', file: '/i18n/en.json' },
    { code: 'tr', label: 'TR', name: 'Turkish', locale: 'tr-TR', file: '/i18n/tr.json' }
  ];

  const dictionaries = new Map();
  const inverseDictionaries = new Map();
  let languages = DEFAULT_LANGUAGES;
  let language = 'en';

  function storageKey() {
    return document.documentElement.dataset.i18nStorage ||
      document.body?.dataset.i18nStorage ||
      'gh_language';
  }

  function storageGet(key) {
    try {
      return localStorage.getItem(key);
    } catch {
      return null;
    }
  }

  function storageSet(key, value) {
    try {
      localStorage.setItem(key, value);
    } catch {}
  }

  function manualStorageKey(key = storageKey()) {
    return `${key}_manual`;
  }

  function hasManualLanguage(key = storageKey()) {
    return storageGet(manualStorageKey(key)) === '1' &&
      Boolean(normalizeLanguage(storageGet(key), ''));
  }

  function normalizeLanguage(value, fallback = 'en') {
    const code = String(value || '').trim().toLowerCase().split(/[-_,;]/u)[0];
    return languages.some(item => item.code === code) ? code : fallback;
  }

  function browserLanguage(fallback = 'en') {
    const candidates = [
      ...(navigator.languages || []),
      navigator.language,
      navigator.userLanguage
    ];
    for (const candidate of candidates) {
      const code = normalizeLanguage(candidate, '');
      if (code) return code;
    }
    return normalizeLanguage(fallback);
  }

  function preferredLanguage(fallback = 'en', key = storageKey()) {
    const stored = hasManualLanguage(key) ? normalizeLanguage(storageGet(key), '') : '';
    return stored || browserLanguage(fallback);
  }

  function languageDefinition(code = language) {
    return languages.find(item => item.code === code) || languages[0] || DEFAULT_LANGUAGES[0];
  }

  async function fetchJson(url) {
    const response = await fetch(url, { cache: 'no-store' });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return response.json();
  }

  async function loadLanguages() {
    try {
      const items = await fetchJson('/i18n/languages.json');
      if (Array.isArray(items) && items.length) {
        languages = items
          .filter(item => item?.code && item?.file)
          .map(item => ({
            code: String(item.code).toLowerCase(),
            label: item.label || String(item.code).toUpperCase(),
            name: item.name || item.label || item.code,
            locale: item.locale || `${String(item.code).toLowerCase()}-${String(item.code).toUpperCase()}`,
            file: item.file
          }));
      }
    } catch {
      languages = DEFAULT_LANGUAGES;
    }
    if (!languages.some(item => item.code === 'en')) {
      languages.unshift(DEFAULT_LANGUAGES[0]);
    }
  }

  async function loadDictionary(code) {
    const normalized = normalizeLanguage(code);
    if (dictionaries.has(normalized)) return dictionaries.get(normalized);
    const definition = languageDefinition(normalized);
    let dictionary = {};
    try {
      dictionary = await fetchJson(definition.file);
    } catch {
      dictionary = {};
    }
    dictionaries.set(normalized, dictionary);
    inverseDictionaries.set(
      normalized,
      new Map(Object.entries(dictionary).map(([source, translated]) => [translated, source]))
    );
    return dictionary;
  }

  function interpolate(value, variables) {
    return String(value).replace(/\{(\w+)\}/g, (match, key) =>
      Object.hasOwn(variables || {}, key) ? variables[key] : match
    );
  }

  function sourceText(text) {
    const value = String(text);
    return inverseDictionaries.get(language)?.get(value) || value;
  }

  function t(text, variables = {}) {
    const source = sourceText(text);
    const dictionary = dictionaries.get(language) || {};
    return interpolate(dictionary[source] || source, variables);
  }

  function populateLanguageSelects(root = document) {
    const selects = [
      ...(root.querySelectorAll?.('[data-i18n-language-select], #languageSelect, #adminLanguage, #loginLanguage') || [])
    ];
    for (const select of selects) {
      const currentCodes = [...select.options].map(option => option.value).join(',');
      const nextCodes = languages.map(item => item.code).join(',');
      if (currentCodes !== nextCodes) {
        select.replaceChildren(...languages.map(item => {
          const option = document.createElement('option');
          option.value = item.code;
          option.textContent = item.label;
          return option;
        }));
      }
      select.value = language;
    }
  }

  function translateDom(root = document) {
    document.documentElement.lang = language;
    populateLanguageSelects(root);

    const treeRoot = root.body || root;
    const walker = document.createTreeWalker(treeRoot, NodeFilter.SHOW_TEXT);
    for (let node = walker.nextNode(); node; node = walker.nextNode()) {
      if (!node.parentElement || ['SCRIPT', 'STYLE', 'TEXTAREA'].includes(node.parentElement.tagName)) continue;
      const raw = node.nodeValue;
      const trimmed = raw.trim();
      if (!trimmed) continue;
      node.parentElement.dataset.i18nSource ||= sourceText(trimmed);
      node.nodeValue = raw.replace(trimmed, t(node.parentElement.dataset.i18nSource));
    }

    for (const element of root.querySelectorAll?.('[placeholder]') || []) {
      element.dataset.i18nPlaceholder ||= sourceText(element.placeholder);
      element.placeholder = t(element.dataset.i18nPlaceholder);
    }

    for (const element of root.querySelectorAll?.('[aria-label]') || []) {
      element.dataset.i18nAria ||= sourceText(element.getAttribute('aria-label'));
      element.setAttribute('aria-label', t(element.dataset.i18nAria));
    }
  }

  async function applyLanguage(next, { nextStorageKey = storageKey(), store = false } = {}) {
    language = normalizeLanguage(next);
    if (store) {
      storageSet(nextStorageKey, language);
      storageSet(manualStorageKey(nextStorageKey), '1');
    }
    await loadDictionary(language);
    translateDom();
    document.dispatchEvent(new CustomEvent('gh:language', { detail: { language } }));
    return language;
  }

  async function setLanguage(next, nextStorageKey = storageKey()) {
    return applyLanguage(next, { nextStorageKey, store: true });
  }

  async function setAutomaticLanguage(fallback = 'en', nextStorageKey = storageKey()) {
    if (hasManualLanguage(nextStorageKey)) return language;
    return applyLanguage(preferredLanguage(fallback, nextStorageKey), {
      nextStorageKey,
      store: false
    });
  }

  function reveal() {
    document.body?.classList.remove('i18n-loading');
  }

  const ready = (async function initI18n() {
    await loadLanguages();
    language = preferredLanguage(document.documentElement.lang || 'en');
    await loadDictionary(language);
    translateDom();
  })();

  window.GH_I18N = {
    ready,
    t,
    setLanguage,
    setAutomaticLanguage,
    translateDom,
    reveal,
    hasStoredLanguage(key = storageKey()) {
      return hasManualLanguage(key);
    },
    get language() { return language; },
    get languages() { return [...languages]; },
    get locale() { return languageDefinition(language).locale; }
  };
})();

(() => {
  const supported = Object.freeze({
    en: { label: 'English' },
    de: { label: 'Deutsch' },
    fr: { label: 'Français' },
    nl: { label: 'Nederlands' },
    es: { label: 'Español' },
  });
  const dictionaries = { en: Object.create(null) };
  const docs = { en: Object.create(null) };
  const pending = new Map();
  const textSources = new WeakMap();
  const attrSources = new WeakMap();

  const normalizeLanguage = (value) => {
    const code = String(value || '').toLowerCase().split(/[-_]/)[0];
    return supported[code] ? code : 'en';
  };
  let lang = normalizeLanguage(localStorage.getItem('zentproxy.language') || navigator.language || 'en');

  function register(code, dictionary, localizedDocs = null) {
    code = normalizeLanguage(code);
    if (code === 'en') return;
    dictionaries[code] = Object.freeze({ ...(dictionary || {}) });
    if (localizedDocs) docs[code] = Object.freeze({ ...localizedDocs });
  }

  function load(code) {
    code = normalizeLanguage(code);
    if (code === 'en' || dictionaries[code]) return Promise.resolve();
    if (pending.has(code)) return pending.get(code);
    const promise = new Promise((resolve, reject) => {
      const script = document.createElement('script');
      script.src = `/lang/${code}.js`;
      script.async = true;
      script.onload = () => dictionaries[code] ? resolve() : reject(new Error(`Language pack ${code} did not register`));
      script.onerror = () => reject(new Error(`Could not load language pack ${code}`));
      document.head.appendChild(script);
    }).catch((err) => {
      console.warn(err);
      if (lang === code) lang = 'en';
    }).finally(() => pending.delete(code));
    pending.set(code, promise);
    return promise;
  }

  const t = (source) => dictionaries[lang]?.[source] || source;

  function translateTextNode(node) {
    if (!node.nodeValue || !node.nodeValue.trim()) return;
    if (!textSources.has(node)) textSources.set(node, node.nodeValue);
    const raw = textSources.get(node);
    const trimmed = raw.trim();
    node.nodeValue = raw.replace(trimmed, t(trimmed));
  }

  function apply(root = document) {
    document.documentElement.lang = lang;
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
      acceptNode(n) {
        return n.parentElement && !['SCRIPT', 'STYLE', 'PRE', 'CODE'].includes(n.parentElement.tagName)
          ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT;
      },
    });
    const nodes = [];
    while (walker.nextNode()) nodes.push(walker.currentNode);
    nodes.forEach(translateTextNode);
    root.querySelectorAll?.('[placeholder],[title],[aria-label]').forEach((el) => {
      if (!attrSources.has(el)) attrSources.set(el, {
        placeholder: el.getAttribute('placeholder'),
        title: el.getAttribute('title'),
        ariaLabel: el.getAttribute('aria-label'),
      });
      const src = attrSources.get(el);
      if (src.placeholder !== null) el.setAttribute('placeholder', t(src.placeholder));
      if (src.title !== null) el.setAttribute('title', t(src.title));
      if (src.ariaLabel !== null) el.setAttribute('aria-label', t(src.ariaLabel));
    });
    const ls = document.querySelector('#language-select'); if (ls) ls.value = lang;
    const lls = document.querySelector('#login-language'); if (lls) lls.value = lang;
  }

  async function setLanguage(next) {
    const requested = normalizeLanguage(next);
    await load(requested);
    lang = dictionaries[requested] || requested === 'en' ? requested : 'en';
    localStorage.setItem('zentproxy.language', lang);
    apply(document);
    return lang;
  }

  const ready = load(lang).then(() => {
    if (!dictionaries[lang] && lang !== 'en') lang = 'en';
    document.documentElement.lang = lang;
  });

  window.ZentI18n = { t, apply, setLanguage, register, supported, ready, getDocs(code = lang) { return docs[normalizeLanguage(code)] || null; }, get language() { return lang; } };

  document.addEventListener('DOMContentLoaded', async () => {
    await ready;
    apply(document);
    new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        for (const node of mutation.addedNodes) {
          if (node.nodeType === Node.ELEMENT_NODE) apply(node);
          else if (node.nodeType === Node.TEXT_NODE) translateTextNode(node);
        }
      }
    }).observe(document.body, { childList: true, subtree: true });
  });
})();

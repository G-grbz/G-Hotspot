(function () {
  const DEFAULT_TERMS_TEXT = 'By continuing, you accept the terms of use for this guest network.';
  const DEFAULT_TERMS_MARKDOWN = [
    '## Terms of Use',
    '',
    'By using this guest network, you agree to use the internet connection lawfully and responsibly.',
    '',
    '- Do not attempt to access systems or data without authorization.',
    '- Do not disrupt network service for other users.',
    '- The network owner may limit, monitor, or terminate access when necessary.'
  ].join('\n');
  const DEFAULT_POLICY_MARKDOWN = [
    '## Safe Internet Policy',
    '',
    'This guest network is provided with safety controls intended to keep internet access lawful and appropriate.',
    '',
    '- Do not use the connection for illegal, harmful, abusive, or disruptive activity.',
    '- Some websites, content categories, or services may be restricted by network policy.',
    '- Contact the network administrator if you believe access has been blocked incorrectly.'
  ].join('\n');
  const DEFAULT_PRIVACY_MARKDOWN = [
    '## Privacy Notice',
    '',
    'Personal data shared during verification is processed for guest network access, security, logging, and legal compliance purposes.',
    '',
    '- Verification details may include contact information, device address, IP address, access time, and session records.',
    '- Records are retained only for operational, security, and legal requirements.',
    '- Contact the network administrator for privacy requests related to this guest network.'
  ].join('\n');
  const CLOSE_ANIMATION_MS = 220;
  const DOCUMENT_NAMES = new Set(['terms', 'policy', 'privacy']);

  const state = {
    config: null,
    closeTimer: null,
    lastFocus: null,
    currentDocument: 'terms',
    documentEventsBound: false
  };

  function t(text, variables) {
    if (window.GH_I18N?.t) return window.GH_I18N.t(text, variables);
    return String(text).replace(/\{(\w+)\}/g, (match, key) =>
      Object.hasOwn(variables || {}, key) ? variables[key] : match
    );
  }

  function escapeHtml(value) {
    return String(value ?? '')
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#039;');
  }

  function normalizeDocumentName(value) {
    return DOCUMENT_NAMES.has(String(value || '').toLowerCase()) ? String(value).toLowerCase() : 'terms';
  }

  function linkedDocumentName(value) {
    const raw = String(value || '').trim();
    if (!raw || raw.startsWith('//') || /^[a-z][a-z0-9+.-]*:/iu.test(raw)) return '';
    const normalized = raw
      .replace(/^[#]+/u, '')
      .replace(/^\.?\//u, '')
      .replace(/[?#].*$/u, '')
      .replace(/\/+$/u, '')
      .toLowerCase();
    return DOCUMENT_NAMES.has(normalized) ? normalized : '';
  }

  function safeMarkdownHref(value) {
    const raw = String(value || '').trim();
    if (!raw || raw.startsWith('//')) return '';
    try {
      const url = new URL(raw, location.origin);
      if (url.origin === location.origin && !/^[a-z][a-z0-9+.-]*:/iu.test(raw)) {
        return `${url.pathname}${url.search}${url.hash}`;
      }
      if (['http:', 'https:', 'mailto:', 'tel:'].includes(url.protocol)) return url.href;
    } catch {}
    return '';
  }

  function renderBasicInlineMarkdown(value) {
    return escapeHtml(value)
      .replace(/\*\*([^*\n]+)\*\*/gu, '<strong>$1</strong>')
      .replace(/\*([^*\n]+)\*/gu, '<em>$1</em>');
  }

  function renderInlineMarkdown(value) {
    const placeholders = [];
    const stash = html => {
      placeholders.push(html);
      return `\u0000${placeholders.length - 1}\u0000`;
    };
    let source = String(value ?? '');
    source = source.replace(/`([^`\n]+)`/gu, (match, code) =>
      stash(`<code>${escapeHtml(code)}</code>`)
    );
    source = source.replace(/\[([^\]\n]+)\]\(([^)\s]+)\)/gu, (match, label, href) => {
      const documentName = linkedDocumentName(href);
      if (documentName) {
        return stash(
          `<a href="#${documentName}" data-terms-document="${documentName}">${renderBasicInlineMarkdown(label)}</a>`
        );
      }
      const safeHref = safeMarkdownHref(href);
      if (!safeHref) return match;
      return stash(
        `<a href="${escapeHtml(safeHref)}" target="_blank" rel="noopener noreferrer">${renderBasicInlineMarkdown(label)}</a>`
      );
    });
    return renderBasicInlineMarkdown(source)
      .replace(/\u0000(\d+)\u0000/gu, (match, index) => placeholders[Number(index)] || '');
  }

  function markdownToSafeHtml(markdown) {
    const lines = String(markdown || '').replace(/\r\n?/gu, '\n').split('\n');
    const blocks = [];
    let paragraph = [];
    const flushParagraph = () => {
      const html = paragraph.map((item, itemIndex) => {
        const rendered = renderInlineMarkdown(item.text);
        if (itemIndex >= paragraph.length - 1) return rendered;
        return `${rendered}${item.hardBreak ? '<br>' : ' '}`;
      }).join('').trim();
      if (html) blocks.push(`<p>${html}</p>`);
      paragraph = [];
    };
    let index = 0;
    while (index < lines.length) {
      const rawLine = lines[index];
      const line = rawLine.trim();
      if (!line) {
        flushParagraph();
        index += 1;
        continue;
      }
      const heading = line.match(/^(#{1,3})\s+(.+)$/u);
      if (heading) {
        flushParagraph();
        const level = heading[1].length;
        blocks.push(`<h${level}>${renderInlineMarkdown(heading[2])}</h${level}>`);
        index += 1;
        continue;
      }
      if (/^[-*]\s+/u.test(line)) {
        flushParagraph();
        const items = [];
        while (index < lines.length && /^[-*]\s+/u.test(lines[index].trim())) {
          items.push(`<li>${renderInlineMarkdown(lines[index].trim().replace(/^[-*]\s+/u, ''))}</li>`);
          index += 1;
        }
        blocks.push(`<ul>${items.join('')}</ul>`);
        continue;
      }
      if (/^\d+\.\s+/u.test(line)) {
        flushParagraph();
        const items = [];
        while (index < lines.length && /^\d+\.\s+/u.test(lines[index].trim())) {
          items.push(`<li>${renderInlineMarkdown(lines[index].trim().replace(/^\d+\.\s+/u, ''))}</li>`);
          index += 1;
        }
        blocks.push(`<ol>${items.join('')}</ol>`);
        continue;
      }
      paragraph.push({ text: line, hardBreak: /\s{2,}$/u.test(rawLine) });
      index += 1;
    }
    flushParagraph();
    return blocks.join('') || `<p>${escapeHtml(t('No terms have been configured yet.'))}</p>`;
  }

  function configuredNoticeMarkdown() {
    const value = state.config?.terms?.text || DEFAULT_TERMS_TEXT;
    return value === DEFAULT_TERMS_TEXT ? t(DEFAULT_TERMS_TEXT) : value;
  }

  function documentDefinition(documentName) {
    const normalized = normalizeDocumentName(documentName);
    if (normalized === 'policy') {
      return {
        title: 'Safe Internet Policy',
        markdown: state.config?.terms?.policyMarkdown,
        fallback: DEFAULT_POLICY_MARKDOWN
      };
    }
    if (normalized === 'privacy') {
      return {
        title: 'Privacy Notice',
        markdown: state.config?.terms?.privacyMarkdown,
        fallback: DEFAULT_PRIVACY_MARKDOWN
      };
    }
    return {
      title: 'Terms of Use',
      markdown: state.config?.terms?.markdown,
      fallback: DEFAULT_TERMS_MARKDOWN
    };
  }

  function modalElement() {
    return document.querySelector('#termsModal');
  }

  function configuredDocumentMarkdown(documentName) {
    const definition = documentDefinition(documentName);
    const value = definition.markdown || definition.fallback;
    return value === definition.fallback ? t(definition.fallback) : value;
  }

  function updateNotice() {
    const button = document.querySelector('#termsButton');
    if (!button) return;
    button.innerHTML = markdownToSafeHtml(configuredNoticeMarkdown());
    const hasLinks = Boolean(button.querySelector('a[href]'));
    button.classList.toggle('has-document-links', hasLinks);
    if (hasLinks) {
      button.removeAttribute('role');
      button.removeAttribute('tabindex');
    } else {
      button.setAttribute('role', 'button');
      button.setAttribute('tabindex', '0');
    }
  }

  function updateModal(documentName = state.currentDocument) {
    const content = document.querySelector('#termsModalContent');
    const title = document.querySelector('#termsModalTitle');
    const definition = documentDefinition(documentName);
    if (title) title.textContent = t(definition.title);
    if (content) content.innerHTML = markdownToSafeHtml(configuredDocumentMarkdown(documentName));
  }

  function update() {
    updateNotice();
    updateModal();
  }

  function focusableElements(modal) {
    return [...modal.querySelectorAll([
      'a[href]',
      'button:not([disabled])',
      'textarea:not([disabled])',
      'input:not([disabled])',
      'select:not([disabled])',
      '[tabindex]:not([tabindex="-1"])'
    ].join(','))].filter(element =>
      element.offsetWidth || element.offsetHeight || element.getClientRects().length
    );
  }

  function trapFocus(event) {
    const modal = modalElement();
    if (!modal || modal.classList.contains('hidden')) return;
    const focusable = focusableElements(modal);
    if (!focusable.length) return;
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }

  function open(documentName = 'terms') {
    const modal = modalElement();
    if (!modal) return;
    state.currentDocument = normalizeDocumentName(documentName);
    updateNotice();
    updateModal(state.currentDocument);
    clearTimeout(state.closeTimer);
    state.lastFocus = document.activeElement;
    modal.classList.remove('hidden');
    modal.setAttribute('aria-hidden', 'false');
    document.body.classList.add('terms-modal-open');
    requestAnimationFrame(() => {
      modal.classList.add('is-open');
      (modal.querySelector('#termsClose') || focusableElements(modal)[0])?.focus({ preventScroll: true });
    });
  }

  function close() {
    const modal = modalElement();
    if (!modal || modal.classList.contains('hidden')) return;
    clearTimeout(state.closeTimer);
    modal.classList.remove('is-open');
    modal.setAttribute('aria-hidden', 'true');
    document.body.classList.remove('terms-modal-open');
    state.closeTimer = setTimeout(() => {
      modal.classList.add('hidden');
    }, CLOSE_ANIMATION_MS);
    if (
      state.lastFocus &&
      document.contains(state.lastFocus) &&
      typeof state.lastFocus.focus === 'function'
    ) {
      state.lastFocus.focus({ preventScroll: true });
    }
  }

  function openFromNotice(event) {
    const documentLink = event.target.closest?.('[data-terms-document]');
    if (documentLink && event.currentTarget.contains(documentLink)) {
      event.preventDefault();
      event.stopPropagation();
      open(documentLink.dataset.termsDocument);
      return;
    }
    if (event.target.closest?.('a[href]') || event.currentTarget.querySelector('a[href]')) return;
    open('terms');
  }

  function handleNoticeKeyboard(event) {
    if (!['Enter', ' '].includes(event.key)) return;
    event.preventDefault();
    open('terms');
  }

  function openFromTrigger(event) {
    open(event.currentTarget?.dataset.termsDocument || 'terms');
  }

  function bindElement(element, eventName, handler, flag) {
    if (!element || element.dataset[flag]) return;
    element.dataset[flag] = 'true';
    element.addEventListener(eventName, handler);
  }

  function bindEvents() {
    const termsButton = document.querySelector('#termsButton');
    if (termsButton) {
      bindElement(termsButton, 'click', openFromNotice, 'termsNoticeBound');
      bindElement(termsButton, 'keydown', handleNoticeKeyboard, 'termsNoticeKeyBound');
    }
    document.querySelectorAll('[data-terms-trigger]').forEach(element => {
      bindElement(element, 'click', openFromTrigger, 'termsTriggerBound');
    });
    document.querySelectorAll('[data-terms-close]').forEach(element => {
      bindElement(element, 'click', close, 'termsCloseBound');
    });
    if (state.documentEventsBound) return;
    state.documentEventsBound = true;
    document.addEventListener('keydown', event => {
      if (event.key === 'Escape') close();
      if (event.key === 'Tab') trapFocus(event);
    });
    document.addEventListener('click', event => {
      const documentLink = event.target.closest?.('[data-terms-document]');
      if (!documentLink || documentLink.closest('#termsButton')) return;
      event.preventDefault();
      open(documentLink.dataset.termsDocument);
    });
    document.addEventListener('gh:language', update);
  }

  function init({ config = null } = {}) {
    state.config = config || state.config;
    bindEvents();
    update();
  }

  window.GH_TERMS = {
    init,
    update,
    open,
    close
  };
})();

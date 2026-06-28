'use strict';

function decodeSqlValue(input) {
  let result = input;
  try {
    result = decodeURIComponent(result.replace(/\+/g, ' '));
  } catch (_) {}
  return decodeHtmlEntities(result, { hex: false });
}

function decodeXssValue(input) {
  let result = input;
  for (let i = 0; i < 3; i++) {
    try {
      const next = decodeURIComponent(result.replace(/\+/g, ' '));
      if (next === result) break;
      result = next;
    } catch (_) {
      break;
    }
  }
  result = result.replace(/[\u200B-\u200D\uFEFF\u00AD]/g, '');
  return decodeHtmlEntities(result, { hex: true });
}

function decodeHtmlEntities(input, options = {}) {
  let result = input
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#x27;/gi, "'")
    .replace(/&#(\d+);/gi, (_, c) => String.fromCharCode(Number(c)));

  if (options.hex) {
    result = result.replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCharCode(parseInt(h, 16)));
  }

  return result;
}

module.exports = { decodeSqlValue, decodeXssValue, decodeHtmlEntities };

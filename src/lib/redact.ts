export const MAX_INPUT = 500_000;
export type Format = 'auto' | 'json' | 'env' | 'text';
type Span = { start: number; end: number; quoted?: boolean };
export type Result = { text: string; count: number; format: Exclude<Format, 'auto'> };

function metadata(key: string): boolean {
  return /(?:^|[^a-z])(?:enabled|length|ttl|expiry|expiration|timeout|url|endpoint|authority|domain)(?:$|[^a-z])/i.test(key.replace(/([a-z])([A-Z])/g, '$1_$2'));
}

function sensitive(key: string): boolean {
  const words = key.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase().split(/[^a-z0-9]+/);
  const compact = words.join('');
  if (/(?:publickey|partitionkey|rowkey|sortkey|cachekey|idempotencykey|tokenendpoint|tokenurl|tokenexpiry|tokenexpiration|tokentype|secretname|secretpath|secretid)$/.test(compact)) return false;
  if (metadata(key)) return false;
  return /(?:password|passwd|passphrase|pwd)$/.test(compact) || words.some(word => /^(?:password|passwd|pwd|pass|secret|secrets|token|tokens|credential|credentials|authorization|auth|auths)$/.test(word)) ||
    words.at(-1) === 'key' || /(?:apikey|accesskey|privatekey|signingkey|encryptionkey|clientsecret|accountkey|sharedaccesssignature|sastoken|keydata)$/.test(compact);
}

export function redact(input: string, requested: Format = 'auto'): Result {
  if (input.length > MAX_INPUT) throw new Error('Text exceeds 500,000 characters. Use a smaller snippet.');
  if (input.includes('\0')) throw new Error('Binary files are not supported. Choose a plain-text file.');
  const format = requested === 'auto' ? (/^\s*(?:\uFEFF)?\s*(?:[\[{]|\/\/|\/\*)/.test(input) ? 'json' : /^\s*(?:export\s+)?[\w.-]+\s*=/m.test(input) ? 'env' : 'text') : requested;
  for (const marker of input.matchAll(/-----BEGIN ((?:[A-Z0-9]+ )*PRIVATE KEY)-----/g)) {
    if (!input.includes(`-----END ${marker[1]}-----`, marker.index! + marker[0].length)) {
      throw new Error('Incomplete private key block. Remove it or include its closing marker before exporting.');
    }
  }
  const spans: Span[] = [];
  const add = (start: number, end: number, quoted = false) => {
    if (end > start) spans.push({ start, end, quoted });
  };

  const connectionKey = /\b(?:password|pwd|accountkey|sharedaccesskey|sharedaccesssignature|clientsecret|access_token)[\t ]*=[\t ]*/gi;
  const urlCredential = /\b[a-z][a-z0-9+.-]*:\/\/([^\s/@:]{0,256}):([^\s/"'<>]{1,2048})@(?=[^\s@/]*(?:[\s/?#]|$))/gi;
  const patterns = [
    /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----/g,
    /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16}|ASIA[A-Z0-9]{16}|sk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}|[rs]k_(?:live|test)_[A-Za-z0-9]{10,}|glpat-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[A-Za-z0-9_-]{35})\b/g,
    /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,
    /\bBearer[\t ]+([^\s"'`,;]+)/gi,
    /\bBasic[\t ]+([A-Za-z0-9+/]{8,}={0,2})/g,
  ];
  function known(start: number, end: number) {
    for (const pattern of patterns) {
      for (const match of input.slice(start, end).matchAll(pattern)) {
        const offset = match[1] ? match[0].length - match[1].length : 0;
        add(start + match.index! + offset, start + match.index! + match[0].length);
      }
    }
  }
  // Source spans keep every byte outside replacements, including JSONC comments.
  function inspect(start: number, end: number, whole: boolean, bounded = true) {
    const value = input.slice(start, end);
    let partial = false;
    for (const match of value.matchAll(connectionKey)) {
      let local = match.index! + match[0].length;
      const opener = value[local];
      const closer = opener === '{' ? '}' : opener === '"' || opener === "'" ? opener : '';
      if (closer) local++;
      let finish = local;
      while (finish < value.length) {
        if (closer ? value[finish] === closer : (bounded ? /[;\r\n]/ : /[;\r\n"']/).test(value[finish])) break;
        if (!bounded && value[finish] === '#' && (finish === local || /\s/.test(value[finish - 1]))) break;
        finish++;
      }
      // Preserve braces/quotes, but redact semicolons inside ODBC braced passwords.
      while (finish > local && /\s/.test(value[finish - 1])) finish--;
      if (finish > local) { add(start + local, start + finish); partial = true; }
    }
    for (const match of value.matchAll(urlCredential)) {
      const passwordStart = match.index! + match[0].indexOf('://') + 3 + match[1].length + 1;
      add(start + passwordStart, start + passwordStart + match[2].length);
      partial = true;
    }
    if (whole && !partial && value.trim()) add(start, end);
  }

  if (format === 'json') {
    let pos = input.charCodeAt(0) === 0xfeff ? 1 : 0;
    const fail = () => { throw new Error('Invalid JSON/JSONC. Fix syntax or select Plain text for best-effort scanning.'); };
    const skip = () => {
      while (pos < input.length) {
        if (/\s/.test(input[pos])) { pos++; continue; }
        if (input.startsWith('//', pos)) { const start = pos; const end = input.indexOf('\n', pos); pos = end < 0 ? input.length : end; inspect(start, pos, false, false); known(start, pos); continue; }
        if (input.startsWith('/*', pos)) { const start = pos; const end = input.indexOf('*/', pos + 2); if (end < 0) fail(); pos = end + 2; inspect(start, end, false, false); known(start, end); continue; }
        break;
      }
    };
    function string(): { start: number; end: number; decoded: string } {
      const begin = pos++;
      while (pos < input.length) {
        if (input[pos] === '\\') { pos += 2; continue; }
        if (input[pos++] === '"') {
          try { return { start: begin + 1, end: pos - 1, decoded: JSON.parse(input.slice(begin, pos)) }; } catch { return fail(); }
        }
      }
      return fail();
    }
    function value(secret: boolean, depth: number) {
      if (depth > 100) throw new Error('JSON nesting exceeds 100 levels. Use a smaller snippet.');
      skip();
      const char = input[pos];
      if (char === '{' || char === '[') {
        const object = char === '{';
        const close = object ? '}' : ']';
        pos++; skip();
        if (input[pos] === close) { pos++; return; }
        while (pos < input.length) {
          let childSecret = secret;
          if (object) {
            if (input[pos] !== '"') fail();
            const key = string().decoded;
            childSecret = (secret || sensitive(key)) && !metadata(key);
            skip(); if (input[pos++] !== ':') fail();
          }
          value(childSecret, depth + 1); skip();
          if (input[pos] === close) { pos++; return; }
          if (input[pos++] !== ',') fail();
          skip(); if (input[pos] === close) { pos++; return; }
        }
        fail();
      } else if (char === '"') {
        const token = string();
        const raw = input.slice(token.start, token.end);
        const before = spans.length;
        inspect(token.start, token.end, secret);
        known(token.start, token.end);
        const escapedSpan = spans.slice(before).some(span => input.slice(Math.max(token.start, span.start - 1), Math.min(token.end, span.end + 1)).includes('\\'));
        const decodedCredential = raw !== token.decoded && [connectionKey, urlCredential, ...patterns].some(pattern => new RegExp(pattern.source, pattern.flags).test(token.decoded));
        // ponytail: escaped secret spans or hidden credential syntax redact whole string; add source mapping if needed.
        if (escapedSpan || (spans.length === before && decodedCredential)) add(token.start, token.end);
      } else {
        const match = /^(?:-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null)/.exec(input.slice(pos));
        if (!match) return fail();
        if (secret && match[0] !== 'null') add(pos, pos + match[0].length, true);
        pos += match[0].length;
      }
    }
    value(false, 0); skip(); if (pos !== input.length) fail();
  } else {
    const assignment = /^[\t ]*(?:export[\t ]+)?([\w.-]+)[\t ]*[:=][\t ]*/gm;
    for (const match of input.matchAll(assignment)) {
      const start = match.index! + match[0].length;
      const quote = input[start];
      let end = start;
      if (quote === '"' || quote === "'" || quote === '`') {
        end++;
        while (end < input.length) {
          if (input[end] === '\\' && quote !== "'") { end += 2; continue; }
          if (input[end] === quote) break;
          end++;
        }
        if (end >= input.length) {
          if (format !== 'text') throw new Error('Unclosed quoted value. Fix syntax before exporting.');
          const newline = input.indexOf('\n', start);
          end = newline < 0 ? input.length : newline;
        }
        inspect(start + 1, end, sensitive(match[1]));
      } else {
        while (end < input.length && input[end] !== '\n' && input[end] !== '\r') end++;
        const raw = input.slice(start, end);
        const comment = /(?:^|\s)#/.exec(raw);
        if (comment) end = start + comment.index;
        while (end > start && /\s/.test(input[end - 1])) end--;
        inspect(start, end, sensitive(match[1]));
      }
    }
  }

  if (format !== 'json') {
    known(0, input.length);
    // Whole-text pass uses quote delimiters; bounded assignments above allow password punctuation.
    inspect(0, input.length, false, false);
    // ponytail: ambiguous escaped passwords in generic text redact through line end; structured JSON keeps context.
    for (const match of input.matchAll(connectionKey)) {
      const start = match.index! + match[0].length;
      const newline = input.slice(start).search(/[\r\n]/);
      const end = newline < 0 ? input.length : start + newline;
      if (input.slice(start, end).includes('\\')) add(start, end);
    }
  }
  spans.sort((a, b) => a.start - b.start || b.end - a.end);
  const merged: Span[] = [];
  for (const span of spans) {
    const last = merged.at(-1);
    if (last && span.start < last.end) { last.end = Math.max(last.end, span.end); last.quoted ||= span.quoted; }
    else merged.push({ ...span });
  }
  const identities = new Map<string, string>();
  const reserved = new Set([...input.matchAll(/\[REDACTED_\d+\]/g)].map(match => match[0]));
  let nextIdentity = 1;
  let text = '', cursor = 0;
  for (const span of merged) {
    const secret = input.slice(span.start, span.end);
    if (!identities.has(secret)) {
      while (reserved.has(`[REDACTED_${nextIdentity}]`)) nextIdentity++;
      identities.set(secret, `[REDACTED_${nextIdentity++}]`);
    }
    const replacement = identities.get(secret)!;
    text += input.slice(cursor, span.start) + (span.quoted ? JSON.stringify(replacement) : replacement);
    cursor = span.end;
  }
  return { text: text + input.slice(cursor), count: merged.length, format };
}

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { redact, MAX_INPUT } from '../src/lib/redact.ts';

test('dotenv preserves quotes, export, comments, CRLF and ordinary settings', () => {
  const input = 'export API_KEY="abc-secret" # keep\r\nPORT=3000\r\nPASSWORD=abc-secret\r\nPUBLIC_KEY=public-data\r\nTOKEN_URL=https://login.example/token\r\n';
  assert.equal(redact(input).text, 'export API_KEY="[REDACTED_1]" # keep\r\nPORT=3000\r\nPASSWORD=[REDACTED_1]\r\nPUBLIC_KEY=public-data\r\nTOKEN_URL=https://login.example/token\r\n');
});
test('JSONC preserves comments, arrays, trailing commas and scalar types outside secrets', () => {
  const input = '{\n // comment\n "ApiKey": "secret",\n "Port": 3000, "Enabled": true,\n "Auth": {"ClientSecret": "secret"},\n "Tokens": ["other", 123, null],\n}';
  const result = redact(input);
  assert.equal(result.text, '{\n // comment\n "ApiKey": "[REDACTED_1]",\n "Port": 3000, "Enabled": true,\n "Auth": {"ClientSecret": "[REDACTED_1]"},\n "Tokens": ["[REDACTED_2]", "[REDACTED_3]", null],\n}');
  assert.equal(result.count, 4);
});
test('connection strings and URLs keep useful context', () => {
  assert.equal(redact('DATABASE_URL=postgres://app:secret@localhost:5432/demo\nCONNECTION_STRING="Server=db;Database=demo;Password=other;Encrypt=True;"').text,
    'DATABASE_URL=postgres://app:[REDACTED_1]@localhost:5432/demo\nCONNECTION_STRING="Server=db;Database=demo;Password=[REDACTED_2];Encrypt=True;"');
  assert.equal(redact('{"ConnectionStrings":{"Default":"Server=db;Password=secret;Database=app;"}}').text,
    '{"ConnectionStrings":{"Default":"Server=db;Password=[REDACTED_1];Database=app;"}}');
});
test('known tokens, bearer credentials and private keys in arbitrary text', () => {
  const token = 'ghp_' + 'x'.repeat(36);
  assert.equal(redact(`deploy ${token}\nAuthorization: Bearer opaque-value`, 'text').text, 'deploy [REDACTED_1]\nAuthorization: [REDACTED_2]');
  assert.equal(redact('-----BEGIN PRIVATE KEY-----\nabc\ndef\n-----END PRIVATE KEY-----', 'text').text, '[REDACTED_1]');
});
test('dotenv multiline secrets retain surrounding structure', () => {
  assert.equal(redact('PRIVATE_KEY="line1\nline2"\nPORT=80').text, 'PRIVATE_KEY="[REDACTED_1]"\nPORT=80');
});
test('empty, public fields and placeholders do not produce accidental output changes', () => {
  assert.equal(redact('').text, '');
  const clean = '{"PublicKey":"public","TokenEndpoint":"https://example.test","SecretName":"vault-reference","Port":80}';
  assert.equal(redact(clean).text, clean);
  assert.equal(redact('NOTE=[REDACTED_1]\nPASSWORD=abc').text, 'NOTE=[REDACTED_1]\nPASSWORD=[REDACTED_2]');
});
test('escaped JSON tokens redact and result remains valid JSON', () => {
  const input = '{"Note":"\\u0067hp_' + 'x'.repeat(36) + '"}';
  assert.equal(JSON.parse(redact(input).text).Note, '[REDACTED_1]');
});
test('invalid JSON, binary, oversized and too-deep input block scans', () => {
  for (const input of ['{"password":"abc"', '{"password":no}', '{"x":01}', '{"x":"bad\\q"}', '{/*', '{"x":1} trailing']) assert.throws(() => redact(input));
  assert.throws(() => redact('abc\0def'));
  assert.throws(() => redact('x'.repeat(MAX_INPUT + 1)));
  assert.throws(() => redact('['.repeat(102) + '0' + ']'.repeat(102)));
  assert.throws(() => redact('PASSWORD="unclosed'));
});
test('lowercase password names, key fields and quoted connection passwords redact', () => {
  assert.equal(redact('{"dbpassword":"abc","Key":"xyz","Connection":"Server=db;Password=\\"secret\\";Database=app"}').text,
    '{"dbpassword":"[REDACTED_1]","Key":"[REDACTED_2]","Connection":"[REDACTED_3]"}');
});
test('incomplete private key blocks cannot escape detection', () => {
  assert.throws(() => redact('-----BEGIN RSA PRIVATE KEY-----\\nsecret-material', 'text'));
});
test('many unique findings do not need repeated full-input searches', () => {
  const input = Array.from({ length: 5000 }, (_, i) => `PASSWORD_${i}=secret-${i}`).join('\n');
  const result = redact(input);
  assert.equal(result.count, 5000);
  assert.ok(result.text.endsWith('PASSWORD_4999=[REDACTED_5000]'));
});
test('review regressions: punctuation, ODBC, Redis and URL at signs', () => {
  for (const password of ['Xy7}kL9', 'ab]cd', "a'b", 'a\\b']) {
    const result = JSON.parse(redact(JSON.stringify({ Db: `Server=db;Password=${password};Database=app` })).text);
    assert.ok(!result.Db.includes(password));
    if (!password.includes('\\')) assert.ok(result.Db.includes('Database=app'));
  }
  assert.equal(redact('DB="Server=db;Pwd={a;b};Database=app"').text, 'DB="Server=db;Pwd={[REDACTED_1]};Database=app"');
  assert.equal(redact('REDIS_URL=redis://:secret@host:6379').text, 'REDIS_URL=redis://:[REDACTED_1]@host:6379');
  assert.equal(redact('DATABASE_URL=postgres://user:p@ss@host/db').text, 'DATABASE_URL=postgres://user:[REDACTED_1]@host/db');
});
test('review regressions: JSONC comments and common credential names', () => {
  const comments = '{\n// "Db": "Server=x;Password=comment-secret"\n/* redis://:another-secret@host */\n"Port":80\n}';
  const result = redact(comments).text;
  assert.ok(!result.includes('comment-secret'));
  assert.ok(!result.includes('another-secret'));
  for (const key of ['PGPASSWORD', 'MYSQLPASSWORD', 'DB_PASS', 'PASSPHRASE', 'STRIPE_KEY', 'APP_KEY', 'JWT_KEY']) {
    assert.equal(redact(`${key}=credential`).text, `${key}=[REDACTED_1]`);
  }
  assert.equal(redact('note sk_live_abcdefghijklmnop', 'text').text, 'note [REDACTED_1]');
});
test('review regressions: .NET host context, escaped tokens and bearer escapes', () => {
  const dotnet = { Db: 'Server=(localdb)\\MSSQLLocalDB;Database=app;Password=secret' };
  assert.equal(JSON.parse(redact(JSON.stringify(dotnet)).text).Db, 'Server=(localdb)\\MSSQLLocalDB;Database=app;Password=[REDACTED_1]');
  for (const token of ['github_pat_' + 'x'.repeat(30), 'ASIA' + 'X'.repeat(16), 'Bearer abc"tail']) {
    const result = JSON.parse(redact(JSON.stringify({ Note: token })).text);
    assert.ok(!result.Note.includes(token));
  }
  assert.equal(redact("Note: 'twas fine", 'text').text, "Note: 'twas fine");
});
test('review regressions: auth sections retain non-secret flags', () => {
  const input = '{"Auth":{"Enabled":true,"Authority":"https://login.example","ClientSecret":"secret"},"PASSWORD_MIN_LENGTH":8,"TOKEN_TTL":3600}';
  assert.equal(redact(input).text, input.replace('"secret"', '"[REDACTED_1]"'));
});
test('second review: empty assignments never consume next line or comments', () => {
  for (const input of ['PASSWORD=\nPORT=3000', 'PASSWORD=\r\nPORT=3000', 'PASSWORD=   # set me\nPORT=80']) assert.equal(redact(input).text, input);
});
test('second review: Docker/npm auth and kubeconfig key data', () => {
  const docker = '{"auths":{"https://index.docker.io/v1/":{"auth":"dXNlcjpwYXNz"}}}';
  assert.equal(redact(docker).text, docker.replace('dXNlcjpwYXNz', '[REDACTED_1]'));
  assert.equal(redact('_auth=dXNlcjpwYXNz').text, '_auth=[REDACTED_1]');
  assert.equal(redact('client-key-data: LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVkt', 'text').text, 'client-key-data: [REDACTED_1]');
  const input = '{"Auth":{"Enabled":true,"Authority":"https://example.test","Password":"secret"}}';
  assert.equal(redact(input).text, input.replace('"secret"', '"[REDACTED_1]"'));
});
test('second review: escaped token tails, generic fallback and Basic prose', () => {
  const input = '{"Note":"ghp_' + 'x'.repeat(30) + '\\u002Dtail"}';
  assert.equal(JSON.parse(redact(input).text).Note, '[REDACTED_1]');
  assert.equal(redact('// basic configuration\nDescription: Basic auth for admin', 'text').text, '// basic configuration\nDescription: Basic auth for admin');
  const escaped = String.raw`"Default": "Server=x;Password=ab\"cd;"`;
  assert.ok(!redact(escaped, 'text').text.includes('cd'));
});
test('large plain text stays unchanged', () => {
  const text = 'ordinary configuration line\n'.repeat(15000);
  assert.equal(redact(text, 'text').text, text);
});

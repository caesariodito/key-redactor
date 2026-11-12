import { MAX_INPUT, redact, type Format } from '../lib/redact';

const source = document.querySelector<HTMLTextAreaElement>('#source')!;
const output = document.querySelector<HTMLTextAreaElement>('#output')!;
const format = document.querySelector<HTMLSelectElement>('#format')!;
const file = document.querySelector<HTMLInputElement>('#file')!;
const copy = document.querySelector<HTMLButtonElement>('#copy')!;
const download = document.querySelector<HTMLButtonElement>('#download')!;
const status = document.querySelector<HTMLElement>('#status')!;
const info = document.querySelector<HTMLElement>('#result-info')!;
const sourceInfo = document.querySelector<HTMLElement>('#source-info')!;
let revision = 0;
let filename = 'config.txt';

function message(text: string, error = false) {
  if (status.textContent !== text) status.textContent = text;
  status.classList.toggle('error', error);
  source.setAttribute('aria-invalid', String(error));
}
function scan() {
  revision++;
  output.value = '';
  copy.disabled = download.disabled = true;
  sourceInfo.textContent = `${source.value.length.toLocaleString()} characters`;
  info.textContent = 'Waiting for input';
  if (!source.value) { message(''); return; }
  try {
    const result = redact(source.value, format.value as Format);
    output.value = result.text;
    info.textContent = `${result.count} replacement${result.count === 1 ? '' : 's'} · ${result.format === 'env' ? '.env' : result.format.toUpperCase()}`;
    copy.disabled = download.disabled = false;
    message(result.count ? 'Preview updated. Review before sharing.' : 'No known secrets detected. Review carefully before sharing.');
  } catch (error) {
    info.textContent = 'Scan blocked';
    message(error instanceof Error ? error.message : 'Unable to scan this text.', true);
  }
}
async function openFile(selected: File) {
  const version = ++revision;
  output.value = '';
  copy.disabled = download.disabled = true;
  info.textContent = 'Reading file…';
  message('');
  try {
    if (selected.size > 1024 * 1024) throw new Error('File exceeds 1 MiB. Choose a smaller file.');
    const bytes = await selected.arrayBuffer();
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    if (text.length > MAX_INPUT) throw new Error('Text exceeds 500,000 characters. Use a smaller snippet.');
    if (text.includes('\0')) throw new Error('Binary files are not supported. Choose a plain-text file.');
    if (revision !== version) return;
    source.value = text;
    filename = selected.name;
    scan();
  } catch (error) {
    if (revision !== version) return;
    // Keep existing input; block exporting an unrelated previous result on file failure.
    output.value = '';
    copy.disabled = download.disabled = true;
    info.textContent = 'File not loaded';
    message(error instanceof TypeError ? 'File is not valid UTF-8 text.' : error instanceof Error ? error.message : 'Unable to read this file.', true);
  }
}
source.addEventListener('input', () => { filename = 'config.txt'; scan(); });
format.addEventListener('change', scan);
file.addEventListener('change', () => { if (file.files?.[0]) void openFile(file.files[0]); file.value = ''; });
const dropZone = document.querySelector<HTMLElement>('#drop-zone')!;
dropZone.addEventListener('dragover', event => {
  if (event.dataTransfer?.types.includes('Files')) { event.preventDefault(); dropZone.classList.add('dragging'); }
});
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragging'));
dropZone.addEventListener('drop', event => {
  dropZone.classList.remove('dragging');
  if (event.dataTransfer?.files[0]) { event.preventDefault(); void openFile(event.dataTransfer.files[0]); }
});
for (const type of ['dragover', 'drop']) document.addEventListener(type, event => {
  if ((event as DragEvent).dataTransfer?.types.includes('Files')) event.preventDefault();
});
document.querySelector('#clear')!.addEventListener('click', () => {
  source.value = ''; file.value = ''; filename = 'config.txt'; scan(); source.focus();
});
document.querySelector('#example')!.addEventListener('click', () => {
  source.value = '{\n  // Keep useful context. Replace credentials.\n  "ConnectionStrings": {\n    "Default": "Server=localhost;Database=demo;User Id=app;Password=demo-password;"\n  },\n  "ApiKey": "demo-api-key",\n  "Logging": { "LogLevel": { "Default": "Information" } },\n  "AllowedHosts": "*"\n}\n';
  format.value = 'auto'; filename = 'appsettings.json'; scan();
});
copy.addEventListener('click', async () => {
  if (copy.disabled) return;
  const version = revision;
  try {
    await navigator.clipboard.writeText(output.value);
    if (version === revision) message('Redacted text copied. Review before pasting elsewhere.');
  } catch {
    if (version === revision) message('Clipboard unavailable. Select and copy the preview manually.', true);
  }
});
download.addEventListener('click', () => {
  if (download.disabled) return;
  try {
    const url = URL.createObjectURL(new Blob([output.value], { type: 'text/plain;charset=utf-8' }));
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `redacted-${filename.replace(/[\\/\u0000-\u001f\u007f]/g, '_')}`;
    anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    message('Redacted download prepared. Original file unchanged.');
  } catch { message('Download unavailable. Copy the preview instead.', true); }
});
// Clear restored form values after back/forward navigation; never restore secret history.
window.addEventListener('pageshow', () => { source.value = ''; file.value = ''; scan(); });

import { defineConfig } from 'astro/config';

export default defineConfig({
  output: 'static',
  markdown: { syntaxHighlight: false },
  security: {
    csp: {
      directives: ["default-src 'none'", "connect-src 'none'", "img-src 'self'", "font-src 'self'", "base-uri 'none'", "form-action 'none'", "object-src 'none'"],
    },
  },
});

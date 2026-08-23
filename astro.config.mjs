import { defineConfig } from 'astro/config';

export default defineConfig({
  site: 'https://sigma.hishamtariq.com',
  // Fully static: there is no server, and there is never going to be one.
  output: 'static',
  build: { inlineStylesheets: 'auto' },
});

/* Prefs boot. Runs before first paint, so it is a blocking script in <head>
   rather than inline — that lets the Content-Security-Policy stay strict
   (no script-src 'unsafe-inline'), which is what makes the "nothing leaves
   your browser" claim checkable rather than just stated.

   Same keys and the same fx-class pattern hishamtariq.com uses. Note that
   localStorage is per-origin: a subdomain does not inherit the main site's
   choice. The keys and defaults match; they do not sync. */
(function () {
      var h = document.documentElement;
      var prefs = {};
      try { prefs = JSON.parse(localStorage.getItem('site-prefs') || '{}'); } catch (e) {}
      var theme = prefs.theme;
      if (!theme) { try { theme = localStorage.getItem('theme'); } catch (e) {} }
      h.setAttribute('data-theme', theme === 'light' ? 'light' : 'dark');
      /* Five presets, and site.config.js sets accent: 'sulfur' as the default. */
      var ACCENTS = ['cyan', 'oxide', 'phosphor', 'violet', 'sulfur'];
      h.setAttribute('data-accent', ACCENTS.indexOf(prefs.accent) > -1 ? prefs.accent : 'sulfur');

      /* Same fx defaults as site.config.js. */
      var fx = Object.assign(
        { cursor: true, reveal: true, spotlight: true, grain: true, drift: true, scramble: true },
        prefs.fx || {}
      );
      if (matchMedia('(prefers-reduced-motion: reduce)').matches) {
        fx.drift = false; fx.cursor = false; fx.scramble = false;
      }
      for (var k in fx) { if (fx[k]) h.classList.add('fx-' + k); }
    })();

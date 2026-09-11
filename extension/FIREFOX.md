# Firefox support

Status: **implemented but unverified** - I don't have a Firefox instance to
actually test this in, so treat this as "should work" rather than "confirmed
working." Please test and report back what breaks.

## What was done

- All `chrome.*` API calls in `background.js`, `content.js`, and `popup.js`
  were replaced with a `browserAPI` alias:
  ```js
  const browserAPI = typeof browser !== 'undefined' ? browser : chrome;
  ```
  Firefox has always provided a native, Promise-based `browser` global;
  Chrome's MV3 `chrome.*` APIs also return Promises when called without a
  callback (which is the only way this codebase calls them), so this one
  line is enough for both - no bundled polyfill needed.
- `manifest.firefox.json` - a Firefox-specific manifest with a
  `browser_specific_settings.gecko` block (required by Firefox, ignored by
  Chrome) and `strict_min_version: "121.0"`.

## How to load it in Firefox

1. `about:debugging#/runtime/this-firefox` → **Load Temporary Add-on**.
2. You need `manifest.json` to actually be Firefox's manifest for a
   temporary load (Firefox doesn't support pointing at an alternate
   manifest filename directly) - so either:
   - Copy `extension/` to a separate folder and rename
     `manifest.firefox.json` → `manifest.json` in that copy, or
   - Temporarily swap the files locally when testing Firefox, swap back
     for Chrome.
3. Select the resulting `manifest.json` (or any file inside the folder -
   Firefox will find it).
4. Open the **Console** tab in about:debugging for this extension and
   check for errors, especially around the background script loading.

## The part I'm genuinely unsure about

`background.js` uses `import { CONFIG } from './config.js'` - a real ES
module import. That requires Firefox to support `"type": "module"`
alongside `"service_worker"` in the background manifest key, which Firefox
added as part of ongoing MV3 compatibility work. I don't have a reliable
way to confirm the exact minimum version this is stable at, or whether
it's fully stable in whatever Firefox version you're testing with.

**If the background script fails to load** (check the console - you'll
likely see something like a manifest warning about an unsupported
background key, or the extension icon never activates): the fix is to
stop using an ES module for the background script. Tell me and I'll:
1. Convert `config.js` from `export const CONFIG` back to a plain script
   that sets a global (`self.PHISHING_GUARD_CONFIG = {...}`), and
2. Change the manifest to `"background": {"scripts": ["config.js", "background.js"]}`
   (no `"type": "module"`), which has been reliably supported in Firefox
   for far longer.

I didn't make this change preemptively because it would mean giving up
real ES modules for no reason if your Firefox version already supports
the service_worker key - better to find out first.

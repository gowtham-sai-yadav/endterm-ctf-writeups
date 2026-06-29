# Challenge 2 — Brand Spotlight

**Category:** Client-Side · **Points:** 5
**Vulnerability:** Reflected Cross-Site Scripting (XSS) in the Brand filter
**Tools used:** Browser, DevTools (Console + Elements), the in-app bug-report bot

---

## 1. Vulnerability Title

Reflected XSS via the `brand` parameter on the Products page — code I craft executes in another logged-in user's browser.

## 2. Description

The Products page lets me filter by brand. The selected brand name is reflected back into the HTML inside a hidden input field, and the app prints it **without HTML-encoding** (it uses the template `safe` filter):

```html
<input type="hidden" name="brand" value="MY_INPUT">
```

Because my input lands inside an attribute with no escaping, I can close the attribute and the tag with `">` and inject a brand-new element carrying a JavaScript event handler. When a victim opens my crafted link, the script runs in *their* session on the ScalerKart origin.

The app has a built-in "report a bug" bot that visits any URL I submit while logged in as another user (`customer2`), which is exactly the victim I need.

## 3. Steps to Reproduce

1. Log in as the customer account. Open the Products page with a test value in the `brand` parameter to find where it reflects:

   ```
   http://localhost:3000/products?brand=zzzTEST
   ```

   In **DevTools → Elements**, search the page and confirm `zzzTEST` appears inside `value="zzzTEST"` of the hidden input.

![alt text](<Screenshot 2026-06-29 at 2.10.22 PM.png>)


2. Build a payload that breaks out of the attribute and runs JavaScript. For scoring, the script calls the app's proof endpoint, which confirms execution in the victim's session:

   ```
   "><img src=x onerror="fetch('/proof/reflect_brand')">
   ```

   The full URL (URL-encoded) is:

   ```
   http://localhost:3000/products?brand=%22%3E%3Cimg%20src%3Dx%20onerror%3D%22fetch('/proof/reflect_brand')%22%3E
   ```
![alt text](<Screenshot 2026-06-29 at 2.11.28 PM.png>)


3. Confirm execution in your own browser first — replace the `fetch(...)` with `alert(document.domain)` and load the URL; the alert proves the script runs.

4. Deliver the real (proof) URL to the victim. The app exposes a bug-report queue that the victim bot visits. Submit it from **DevTools → Console** while logged in:

5. Within a few seconds the bot (logged in as the victim) loads the page, the `onerror` fires `fetch('/proof/reflect_brand')` in the victim's session.

## 4. Impact

Reflected XSS lets an attacker run arbitrary JavaScript in a victim's authenticated session by tricking them into opening a link (phishing). That enables session/cookie theft, performing actions as the victim, credential capture, and data exfiltration — all from the trusted ScalerKart origin.

## 5. Remediation

- Remove the `safe` filter and let the template auto-escape the value, or explicitly HTML-attribute-encode it.
- Validate `brand` against an allow-list of real brands (`Logitech`, `Decathlon`).
- Add a Content-Security-Policy that forbids inline scripts and event handlers.

## 6. CVSS 3.1 Score

**6.1 — Medium**
`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`

Network, requires the victim to open a link (UI:R), scope changes into the victim's browser.

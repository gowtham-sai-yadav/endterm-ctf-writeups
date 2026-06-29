# Challenge 3 — Unsigned Reset

**Category:** Authorization · **Points:** 5
**Vulnerability:** JWT `alg:none` signature bypass in the password-reset flow
**Tools used:** Browser, DevTools, Burp Suite (Repeater), jwt.io (or terminal `base64`)

---

## 1. Vulnerability Title

Password-reset takeover via a forged JWT with `"alg":"none"` — reset any user's password without their token or credentials.

## 2. Description

The forgot-password page issues a reset token as a **JWT** that encodes the target `user_id`. The reset endpoint is supposed to verify this token's signature. Instead, it inspects the token's own header and, if the header says `"alg":"none"`, it **skips signature verification entirely** and trusts the payload as-is.

A JWT is three Base64url parts: `header.payload.signature`. Since the server honours `alg:none`, I can take a legitimate reset token, change the header to `{"alg":"none"}`, edit the payload to point at any victim's `user_id`, and drop the signature. The server accepts it and resets that user's password to whatever I choose.

## 3. Steps to Reproduce

1. Go to **Forgot Password** (`/account/forgot-password`) — it's reachable without logging in. Enter the victim's email:

   ```
   customer2@scalerkart.test
   ```

   The page shows a reset link containing a `token=` JWT (dev mode prints it instead of emailing).
![alt text](<Screenshot 2026-06-29 at 2.14.28 PM.png>)

2. Copy the token and paste it into **jwt.io** (or decode each part with `base64` in a terminal). Note the payload, e.g.:

   ```json
   { "user_id": 3, "purpose": "reset", "exp": 1782721106 }
   ```
![alt text](<Screenshot 2026-06-29 at 2.15.17 PM.png>)

3. Forge a new token:
   - **Header:** `{"alg":"none","typ":"JWT"}`
   - **Payload:** keep `user_id` set to the victim (3), `purpose` = `reset`, and a future `exp`.
   - **Signature:** empty (the token ends with a trailing dot).

   The result looks like `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjozLCJwdXJwb3NlIjoicmVzZXQiLCJleHAiOjE3ODI3MjYyNjd9.` (note the trailing dot, empty signature).

![alt text](<Screenshot 2026-06-29 at 2.17.11 PM.png>)
   

4. Submit the forged token to the reset endpoint. Easiest path: open the reset page with your forged token in the URL, type a new password, and submit — or replay the request in **Burp Repeater**:

![alt text](<Screenshot 2026-06-29 at 2.18.18 PM.png>)

5. Log in as the victim (`customer2 / Hacked123!`) to prove takeover. The challenge solves on the successful `alg:none` reset.
![alt text](<Screenshot 2026-06-29 at 2.19.20 PM.png>)

## 4. Impact

Complete account takeover of **any** user — including high-privilege accounts — with no credentials and no valid token. The signature is the entire security of a JWT, and `alg:none` throws it away.

## 5. Remediation

- **Pin the accepted algorithm** server-side and never trust the token's own header:
  ```python
  jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
  ```
- Explicitly reject `none`. Use a library setting that disallows unsigned tokens.
- Make reset tokens single-use, short-lived, and tied to a server-side nonce.

## 6. CVSS 3.1 Score

**8.1 — High**
`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`

Unauthenticated takeover of arbitrary accounts (rises toward 9.1+ if admin accounts are reachable).

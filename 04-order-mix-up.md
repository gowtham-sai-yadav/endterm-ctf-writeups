# Challenge 4 — Order Mix-up

**Category:** Authorization · **Points:** 5
**Vulnerability:** Broken Object Level Authorization (BOLA / IDOR) on the order API
**Tools used:** Browser, DevTools (Network), Burp Suite (Repeater)

---

## 1. Vulnerability Title

BOLA / IDOR on `/api/orders/<id>` — read the full details of any order, including ones that don't belong to me.

## 2. Description

My orders page is backed by an API endpoint, `GET /api/orders/<id>`. The endpoint checks that I'm *logged in*, but it never checks that the order actually *belongs to me*. The `<id>` is a simple incrementing integer, so by changing it I can read any other customer's order — their shipping address, the card's last four digits, items and totals.

The hint sums it up: "The lock is on the front door. Not every door has one." Authentication is enforced; object-level authorization is not.

## 3. Steps to Reproduce

1. Log in as the customer account and open **Orders**. With **DevTools → Network** open, note the request your own order is loaded from (and find your order id).

![alt text](<Screenshot 2026-06-29 at 2.21.38 PM.png>)

2. Directly request another order id. In the browser address bar (or by sending the request to **Burp Repeater** and changing the number), open:

   ```
   http://localhost:3000/api/orders/2
   ```

   Order #2 belongs to a different customer — but the API returns it in full.

![alt text](<Screenshot 2026-06-29 at 2.22.14 PM.png>)

3. Enumerate. Step the id through `1, 2, 3, …` in Burp Repeater (or Intruder) to confirm you can read every order in the system.

![alt text](<Screenshot 2026-06-29 at 2.23.00 PM.png>)

4. Accessing an order that isn't yours triggers the solve. Refresh the status page to confirm.

## 4. Impact

Any logged-in user can harvest every order in the platform by walking the id range: shipping addresses, partial card numbers, purchased items, and totals. That's a mass PII and financial-data breach from a single trivial parameter change. BOLA is the #1 risk on the OWASP API Security Top 10.

## 5. Remediation

- Enforce ownership on every object access:
  ```python
  if order is None or order["user_id"] != session["user_id"]:
      abort(404)
  ```
- Return `404` (not `403`) for objects the user may not access, so existence isn't confirmed.
- Consider unguessable identifiers (UUIDs) as defence-in-depth — but the real fix is the authorization check.

## 6. CVSS 3.1 Score

**6.5 — Medium**
`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`

(Frequently rated 7.5 High given the volume of PII exposed across all users.)

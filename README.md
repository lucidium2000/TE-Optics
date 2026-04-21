# TE Optics

**TE Optics** is a free sidebar tool for [ThousandEyes](https://www.thousandeyes.com/) that runs in your browser on **`app.thousandeyes.com`**. It helps you **bulk-create tests**, **bulk-edit tests**, and **back up or restore dashboards**—using the login you already have. **No API tokens** and no extra server.

> **Not official.** This is independent community software. It is not sponsored, endorsed, or affiliated with Cisco or ThousandEyes.

---

## Easiest way to get started

1. **Open the installer (one page, everything you need)**  
   **[https://lucidium2000.github.io/TE-Optics/](https://lucidium2000.github.io/TE-Optics/)**

2. **Sign in to ThousandEyes** in another tab:  
   [https://app.thousandeyes.com](https://app.thousandeyes.com)

3. **Install the bookmarklet**  
   On the installer page, **drag the “TE Optics” button** to your bookmarks bar.  
   (If the bar is hidden: **Ctrl+Shift+B** on Windows, or **Cmd+Shift+B** on Mac—in most browsers.)

4. **Go back to `app.thousandeyes.com` and click the bookmark**  
   A panel opens on the side of the ThousandEyes app.

That’s it—you’re using TE Optics.

---

## What you can do (in plain English)

| Where you are in ThousandEyes | What TE Optics gives you |
|-------------------------------|---------------------------|
| **Most of the app** (tests, synthetics, etc.) | **Create Tests** — add many tests at once (paste targets, one per line). **Manage Tests** — load tests, filter, bulk enable/disable, change interval, delete, etc. |
| **A dashboard** (URL contains `/dashboard`) | **Backup / Restore** — pull dashboard JSON from the app, save a file, re-import later; optional cleanup of widget filters; bulk dashboard list helpers and diagnostics. |

The panel **figures out your session** from the page (cookies, storage, or headers from normal TE traffic). You don’t paste secrets into a third-party site.

---

## Updating

Bookmarklets **save a copy of the code when you create the bookmark**. To get a new version:

1. Delete the old **TE Optics** bookmark.  
2. Open the **[installer page](https://lucidium2000.github.io/TE-Optics/)** again and drag a **new** bookmark to the bar.

The installer page shows a **small build number** next to the title; the same number appears in the panel footer so you can confirm you’re on the latest build.

---

## Source code

- **Repository:** [github.com/lucidium2000/TE-Optics](https://github.com/lucidium2000/TE-Optics)  
- **Main script:** `panel.js` (also embedded in `index.html` so the installer works from a simple static site)

---

## Disclaimer

Use TE Optics only in line with **your organization’s policies** and **Cisco / ThousandEyes terms of service**. The software is provided **“as is”**, without warranty; see the license headers in the source files for details.

If something breaks after a ThousandEyes UI change, open a **GitHub issue**—there’s no guarantee of a fix or response time, but reports help.

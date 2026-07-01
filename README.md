# ⚡ CA Identity Manager (CAIM) Tools Suite
[![Architecture: Serverless](https://img.shields.io/badge/architecture-serverless-brightgreen)](#)
[![Stack: Vanilla JS / HTML](https://img.shields.io/badge/stack-vanilla_js-blue)](#)
[![Build: Zero Config](https://img.shields.io/badge/build-zero_config-orange)](#)

The **CA Identity Manager Tools Suite** is a ruthlessly efficient, zero-dependency browser automation toolkit. We drop the bloat. We eliminate build steps. We generate self-contained, high-performance bookmarklets that inject directly into your CAIM administrative workflows.

Run it locally. Run it anywhere. Open [`index.html`](index.html) and start automating.

## 🏗️ The Meta-Builder Architecture

This is not a Node project. There is no `package.json`. There are no Webpack bundles.
This repository leverages a **meta-builder pattern**: static HTML files that serve as both the Configuration UI and the Code Generator.

1. **You configure the tool visually** using the Tailwind-powered UI.
2. **The meta-builder serializes and minifies** the internal logic.
3. **A self-contained `javascript:` URI is generated**—ready to be dragged to your bookmarks bar.

Everything runs entirely client-side. No data ever leaves your browser.

## 🧰 The Arsenal

### 1. The Quick Utilities (`caim_bookmarklets.html`)
Pre-compiled, instantly deployable bookmarklets for immediate CAIM automation. These target isolated, high-friction tasks to get you in and out instantly.
* **User Search Helper:** Injects a persistent floating search panel. Utilizes the native `TreeWalker` API for ultra-fast DOM traversal to execute real-time regex matching and dynamic highlighting across massive text nodes without blocking the main thread.
* **Bulk Action Form:** Renders a floating checklist panel for batch operations. Paste a block of newline-separated usernames, select your target operation (unlock, reset, or dual-action), and power through bulk provisioning without clicking through repetitive sub-menus.
* **Password Expiry Scanner:** Scans the active DOM against complex date formats (`\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}`). Automatically flags and applies a hard visual alert (orange background) to any expiry date falling within a critical 30-day window.
* **Page Data Extractor:** Radically accelerates auditing. Executes pattern-matching to scrape usernames, emails, and full names, then serializes all active HTML `<table>` elements into a clean, pipe-delimited text format ready for instant terminal or CSV piping.
* **Quick Actions Panel:** Provides instantaneous DOM manipulation. Includes features to temporarily outline all forms in red (for quick structural mapping), grab hidden page metadata, spotlight all clickable elements with orange borders, and download serialized table data straight to disk.
* **Form Auto-Filler:** A heuristic-driven payload that scans `name`, `placeholder`, and `id` attributes for identity-centric keywords ("user"). It maps hardcoded values directly to selects and inputs, flashing the mutated fields green for immediate visual confirmation.

### 2. The Preset Form Filler (`caim_preset_filler.html`)
The heavy artillery. An advanced, stateful automation engine featuring hierarchical preset support and Excel-based bulk import via SheetJS. Built specifically to survive hostile, multi-page reload workflows.

* **Phase 1: Field Mapping (The Recon):** Injects a targeted scanner directly onto the CAIM page. It discovers complex form structures, auto-detects `select[name$=".Options"]` duallists, and designates primary keys (e.g., username) to establish absolute session validation. Every mapped field is highlighted green.
* **Phase 2: Preset Generation (The Build):** Download generated `.xlsx` templates. Fill them with matrixed preset data. Upload the sheets directly to the builder (parsed client-side by SheetJS). The builder handles conditional states like "Clear Unspecified" and "Add All" for complex duallists, then stacks the presets hierarchically via a drag-and-drop UI for deterministic override priorities.
* **Phase 3: Stateful Execution (The Strike):** The final, compressed bookmarklet encodes the entire configuration matrix inline. Once executed, it maintains strict cross-reload tracking via `sessionStorage`, mapping current page state against intended preset values. It executes actions sequentially, safely surviving CAIM's mandatory full-page reloads when interacting with duallist components, until the entire matrix is resolved.

## 🚀 Execution & Automation Flow

1. Open `index.html` in your browser.
2. Select your weapon (Quick Utilities or Preset Filler).
3. Follow the UI to drag the generated bookmarklet to your bookmarks bar.
4. Navigate to your CA Identity Manager instance.
5. Click the bookmarklet to inject and execute the automation payload.

## 🛠️ Stack & Dependencies
Zero local dependencies. We rely exclusively on battle-tested CDN libraries to maintain an ephemeral, client-side footprint:
* **Tailwind CSS** (`cdn.tailwindcss.com`)
* **Google Fonts - Inter**
* **SheetJS / XLSX** (v0.18.5)

## 🔮 Roadmap
Track active development and future architectural variations in [ROADMAP.md](ROADMAP.md).

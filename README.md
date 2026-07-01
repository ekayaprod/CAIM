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
Pre-compiled, instantly deployable bookmarklets for immediate CAIM automation:
* **User Search Helper:** Real-time DOM traversal and text highlighting.
* **Bulk Action Form:** Batch process usernames for resets and unlocks.
* **Password Expiry Scanner:** Regex-driven DOM highlighting for imminent expirations.
* **Page Data Extractor:** Serialize target HTML tables directly to pipe-delimited text.
* **Form Auto-Filler:** Intelligently match and fill forms by attribute heuristics.

### 2. The Preset Form Filler (`caim_preset_filler.html`)
The heavy artillery. An advanced, stateful automation engine featuring hierarchical preset support and Excel-based bulk import via SheetJS.

* **Phase 1: Field Mapping:** Injects a scanner onto your target CAIM page to map DOM nodes, auto-detect duallists, and establish session validation keys.
* **Phase 2: Preset Generation:** Import `.xlsx` templates. Assign hierarchical override priorities via drag-and-drop.
* **Phase 3: Stateful Execution:** The generated bookmarklet manages cross-reload execution state via `sessionStorage`, seamlessly navigating CAIM's multi-step refresh flows.

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

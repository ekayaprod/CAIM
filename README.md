# CA Identity Manager (CAIM) Local Automation Suite

## 1. Project Title & Brief Description

A personal, serverless web utility suite containing browser bookmarklets that
I built to automate my repetitive data entry tasks within CA Identity Manager.
It generates self-contained scripts that run locally in the browser to instantly
map, fill, and process complex identity forms.

## 2. The Operational Bottleneck

I created this tool because navigating CA Identity Manager manually was a
massive drain on my time. My daily workflow involved heavy manual processing
and clicking through complex duallist fields that constantly required full-page
reloads. This slow, repetitive data entry not only bottlenecked my productivity
but also introduced a high risk of human error during repetitive account
provisions and audits.

## 3. Tech Stack & Architecture

* **HTML5 & Vanilla JavaScript:** Core logic and UI, operating purely
  client-side with no build steps or backend servers.
* **Browser Bookmarklets (`javascript:` URIs):** Used as the delivery
  mechanism to inject my automation scripts directly into the active CAIM
  session.
* **Tailwind CSS (via CDN):** For quickly styling the configuration interfaces.
* **SheetJS / XLSX (via CDN):** To parse my Excel preset files locally for bulk
  data processing.
* **Native DOM APIs:** Leveraging `TreeWalker` and `sessionStorage` for fast
  DOM parsing and state persistence across page reloads.

## 4. Key Features & Workflow

* **Instant Configuration:** I open the local `index.html` file, select either
  the Quick Utilities or the Preset Form Filler, and configure my mapping
  options.
* **Bookmarklet Generation:** The tool compresses my configuration into a single,
  draggable bookmarklet.
* **Automated Form Execution:** When I click the bookmarklet in CAIM, it uses
  a heuristic payload to auto-detect fields, highlights them in green, and
  maps my preset data to inputs.
* **Stateful Continuity:** For complex tasks, the tool uses session storage
  to remember where it left off, surviving CAIM's mandatory full-page reloads
  and executing actions sequentially until complete.
* **Quick Diagnostics:** I included utilities to instantly extract page data
  into CSV format, highlight expiring passwords, and process bulk checklists.

## 5. Localized Impact

Building this personal utility radically optimized my day-to-day operations.
It completely eliminated my manual data entry errors, reduced my ticket
resolution time from minutes per user to mere seconds, and allowed me to
effortlessly handle massive bulk account provisions without clicking through
endless sub-menus. It transformed a tedious administrative chore into a fast,
single-click operation.

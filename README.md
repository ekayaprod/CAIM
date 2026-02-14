# CA Identity Manager Tools Suite

## Overview

The CA Identity Manager (CAIM) Tools Suite is a browser-based automation toolkit designed to streamline identity management workflows. The suite consists of standalone HTML applications that generate bookmarklets—JavaScript-based browser tools that can be dragged to the bookmarks bar and executed on any CAIM web page.

To get started, open [`index.html`](index.html) in your browser.

All tools run entirely client-side in the browser with no external dependencies beyond CDN-hosted libraries (Tailwind CSS, SheetJS). No data is transmitted to external servers.

## Project Architecture

### File Structure

```
/
├── index.html                    # Main landing page and navigation hub
├── caim_bookmarklets.html        # Ready-to-use bookmarklet collection
└── caim_preset_filler.html       # Advanced form automation builder
```

### Core Design Pattern: Meta-Builder Architecture

This project employs a **meta-builder pattern** where static HTML files serve dual purposes:

1. **Configuration UI**: User-facing interface for customizing tool behavior
2. **Code Generator**: Dynamic generation of self-contained bookmarklet code

Each builder page contains:
- A visual configuration interface (using Tailwind CSS)
- Embedded JavaScript logic that will be injected into the target page
- A build/generation system that encodes the configured logic into bookmarklet format

The generated bookmarklets are completely self-contained—they include all necessary logic and data inline, requiring no external references after generation.

## Components

### 1. Landing Page (`index.html`)

**Purpose**: Navigation hub and introduction to the suite.

**Key Features**:
- Responsive card-based layout
- Tool categorization and recommendations
- Getting started guide

**Technical Details**:
- Static HTML with Tailwind CSS via CDN
- No JavaScript logic required
- Serves as documentation and wayfinding interface

---

### 2. Quick Bookmarklets (`caim_bookmarklets.html`)

**Purpose**: Provides a library of pre-built, immediately usable bookmarklets for common CAIM administrative tasks.

#### Architecture

The file uses an embedded template system where each bookmarklet's source code is stored in `<script type="text/template">` tags with IDs following the pattern `{bookmarkletId}-src`. On page load, a build function:

1. Extracts the template content
2. Minifies the JavaScript (removes comments, newlines, excess whitespace)
3. Encodes it into a `javascript:` URI
4. Sets the `href` attribute of the corresponding anchor tag

#### Available Bookmarklets

**User Search Helper**
- **Type**: Floating panel with search input
- **Functionality**: Real-time text highlighting across the page
- **Technical Approach**: TreeWalker API to traverse text nodes, regex matching, dynamic span wrapping
- **State Guard**: Uses `window.caim_search_active` flag to prevent duplicate instances

**Bulk Action Form**
- **Purpose**: Batch operation planning for multiple users
- **Input**: Newline-separated usernames
- **Output**: Generates action checklist based on selected operation type (unlock, reset, both)
- **DOM Injection**: Creates persistent floating panel with textarea and dropdown

**Password Expiry Scanner**
- **Purpose**: Identifies password expiry dates within a 30-day window
- **Detection Method**: Regex pattern matching for date formats (`\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}`)
- **Highlighting**: Applies orange background to detected dates that fall within threshold

**Page Data Extractor**
- **Functions**:
  - `extractTableData()`: Serializes all `<table>` elements to pipe-delimited text
  - `extractUserData()`: Pattern matching for usernames, emails, and names
- **Pattern Library**: Three regex patterns for common identity formats
- **Output**: Monospace text display, truncated to 50 results

**Quick Actions Panel**
- **UI**: Vertical floating panel with action buttons
- **Actions**:
  - **Highlight Forms**: Temporary red outline on all form elements (5-second duration)
  - **Page Info**: Alert with page metadata (title, URL, element counts)
  - **Find Buttons**: Temporary orange border on all clickable elements
  - **Export Data**: Generates `.txt` file with serialized table data, triggers download

**Form Auto-Filler**
- **Purpose**: Quick-fill forms with predefined username and action values
- **Matching Logic**: Searches for form fields by `name`, `placeholder`, or `id` attributes containing "user"
- **Action Mapping**: Attempts to match select option text/value with chosen action
- **Visual Feedback**: Green background flash on filled fields (3-second duration)

#### Build System

```javascript
buildBookmarklet(linkId, sourceId) {
    // Extract source from template tag
    const code = srcElement.textContent;
    
    // Minify: remove comments and normalize whitespace
    code = code.replace(/\/\*[\s\S]*?\*\/|\/\/.*$/gm, '')
               .replace(/\n\s*/g, ' ')
               .trim();
    
    // Encode as bookmarklet
    const bookmarklet = 'javascript:' + encodeURIComponent(code);
    
    // Assign to link href
    link.setAttribute('href', bookmarklet);
}
```

---

### 3. Preset Form Filler (`caim_preset_filler.html`)

**Purpose**: Advanced tool for creating intelligent, stateful form fillers with hierarchical preset support and Excel-based bulk import.

This is the most sophisticated component in the suite, implementing a two-phase workflow with persistent state management.

#### Architecture Overview

The Preset Form Filler consists of three distinct execution contexts:

1. **Builder UI** (the HTML page itself): Configuration interface where users define mappings, import presets, and generate bookmarklets
2. **Field Mapper Tool** (Phase 1 bookmarklet): Injected onto target CAIM pages to capture form structure
3. **Form Filler Runtime** (Phase 2 bookmarklet): The generated bookmarklet that executes the actual form-filling logic

#### Phase 1: Field Mapping Tool

**Purpose**: Discover and map form field relationships on the target CAIM page.

**Key Object: Field Mapping**
```javascript
{
    sourceId: "fieldName.Options",           // Source selector (for duallists)
    sourceOptions: ["opt1", "opt2", ...],    // Available options
    format: "text" | "code:description",     // Value format detection
    destinations: [{
        id: "fieldName",                      // Target element ID/name
        type: "text" | "select" | "duallist" // Input type
    }]
}
```

**Mapping Modes**:

- **Simple Mode**: Maps standard input/select fields (1:1 mapping)
- **Duallist Mode**: Maps dual-list selectors (source list → destination list with Add/Remove buttons)
- **Constant Mode**: Designates a "key field" used for session validation (typically username)

**Auto-Detection**: `scanDuallists()` function automatically finds all fields matching the pattern `select[name$=".Options"]` and maps them to their corresponding destination selects.

**Format Detection**: `aF()` function analyzes option text patterns to determine if format is plain text or `code:description` (e.g., "123:Description").

**Visual Feedback**: Mapped fields receive green background (`#e6fffa`) and green border, key field receives orange border.

**Output**: JSON object containing `keyField` and `mappings` array.

#### Phase 2: Preset Configuration & Generation

**State Management**

Uses `localStorage` with key `caimPresetFillerState_v11` to persist:
- Field mappings
- Key field designation
- Preset groups (hierarchical structure)
- Field configurations (special behaviors)

**Data Structures**

**Preset Group**:
```javascript
{
    name: "Group Name",
    clearUnspecified: boolean,  // Whether to clear unmapped fields
    data: {
        "Preset Name 1": {
            fieldId: "value",
            fieldId2: "value2",
            __clearUnspecified: true  // Per-preset override
        },
        "Preset Name 2": { ... }
    }
}
```

**Field Config**:
```javascript
{
    fieldId: {
        isAddAll: boolean  // For duallists: add all options instead of specific one
    }
}
```

**Excel Import System**

Uses SheetJS (xlsx.js) to parse uploaded Excel files.

**Expected Format**:
- First column: "Name" (preset identifier)
- Subsequent columns: Field IDs matching the mapping JSON
- Each row represents one preset configuration

**Import Behavior**:
- Empty cells are ignored (field remains unchanged)
- Non-empty cells set the field value
- Optional "Clear Unspecified" flag causes all unmapped fields to be cleared

**Template Generation**: `downloadXlsxTemplate()` creates an Excel file with proper column headers from the current mappings.

**Preset Hierarchy**

Groups can be reordered via drag-and-drop to control merge priority. When multiple groups are selected during form filling:

1. Groups are processed bottom-to-top (later groups override earlier ones)
2. Within each group, the selected preset's values are merged
3. If `clearUnspecified` is true, unmapped fields are cleared first

#### Phase 3: Generated Bookmarklet Logic

The final bookmarklet is a fully self-contained script with all mappings, presets, and field configurations embedded inline.

**Stateful Execution Model**

The filler uses `sessionStorage` to maintain state across page reloads, which is necessary because duallist operations trigger page refreshes in CAIM.

**Session State Object**:
```javascript
{
    D: [                    // Pending duallist actions queue
        {i: fieldId, c: 'set'|'clear', v: value}
    ],
    kV: "keyFieldValue"    // Key field value for session validation
}
```

**Execution Flow**:

1. **Initial Click**: 
   - Check for existing session state
   - If no state OR key field value changed → Fresh start
   - Display preset selection modal (if multiple presets exist per group)
   - Generate action plan (`pl()` function)
   - Execute all non-reloading actions immediately
   - Execute first reloading action (duallist operation)
   - Save remaining actions to sessionStorage
   - Display progress overlay

2. **Subsequent Clicks** (after page reload):
   - Detect valid session state (matching key field value)
   - Load next action from queue
   - Execute action
   - Update session state
   - Display progress overlay

3. **Completion**:
   - When action queue is empty
   - Display "Complete!" message
   - Clear session state
   - Auto-fade overlay after 1.5 seconds

**Action Planning: `pl()` Function**

Compares current page state with desired preset values and generates minimal action list.

**Logic**:
1. If preset has `__clearUnspecified`, queue clear actions for all populated fields not in preset
2. For each preset field:
   - Get current value via `gV()` (handles different input types)
   - Render target value via `render()` (applies format transformations)
   - Compare normalized values
   - If different, queue appropriate action

**Action Types**:
- `{i: fieldId, c: 'clear'}`: Clear field value
- `{i: fieldId, c: 'set', v: value}`: Set field to specific value

**Special Handling**:
- **Add All Duallists**: If field config has `isAddAll` and preset has any non-empty value, queues `{v: '__ADDALL__'}` action
- **Duallist Clearing**: Only queues clear if current value is non-empty
- **Format Matching**: For `code:description` format, only compares the code portion

**Action Execution: `x()` Function**

Executes a single action against the DOM.

**Clear Action**:
```javascript
if (type === "duallist") {
    // Select all destination options
    Array.from(element.options).forEach(o => o.selected = true);
    // Click remove button
    removeButton.click();
} else {
    element.value = "";
    trigger(element, "input");
    trigger(element, "change");
}
```

**Set Action for Duallist**:
```javascript
if (isAddAll) {
    // Click "Add All" button
    addAllButton.click();
} else {
    // Find option in source list
    sourceElement.options.forEach(option => {
        if (matchesTarget(option.text, targetValue)) {
            option.selected = true;
        }
    });
    // Click "Add" button
    addButton.click();
}
```

**Set Action for Select**:
```javascript
// Try exact match on value, then text
for (let option of element.options) {
    if (option.value === targetValue || option.text === targetValue) {
        element.value = option.value;
        matched = true;
        break;
    }
}
trigger(element, "change");
```

**Set Action for Text/Input**:
```javascript
element.value = renderedValue;
trigger(element, "input");
trigger(element, "change");
```

**DOM Helper Functions**

- `getEl(id)`: Finds element by ID or name attribute, searches input/select/textarea/div
- `trigger(element, eventType)`: Dispatches native browser events to ensure CAIM's event listeners fire
- `gA/gAA/gR()`: Find Add/AddAll/Remove buttons for duallist controls by traversing parent elements
- `gV()`: Gets current value from any input type, handles duallist multi-value serialization

**Key Field Validation**

Before executing any actions, the bookmarklet checks:
```javascript
const keyElement = getEl(KEY_FIELD_ID);
const sessionState = getSessionState();

if (sessionState && keyElement && sessionState.kV !== keyElement.value) {
    // Key field changed - restart flow
    clearState();
}
```

This prevents applying the wrong preset if the user navigates to a different record.

**Preset Selection Modal**

Dynamically generates a modal UI when user clicks the bookmarklet (if needed):
- One dropdown per preset group
- Auto-selects if group only has one preset
- Skips modal entirely if all groups have exactly one preset
- Dark mode support via `prefers-color-scheme` media query
- Cancel button clears state and removes modal
- Continue button merges selected presets and begins execution

**Progress Overlay**

Displays execution status between page reloads:
- Shows remaining action count
- Updates message based on progress
- "Complete!" message on final action
- Semi-transparent backdrop to prevent user interaction during reloads

#### Minification Strategy

The generated bookmarklet undergoes aggressive minification to stay within browser URL length limits:

1. Variable name shortening (`C` for config object, `M` for mappings)
2. Property key abbreviation (`t` for type, `f` for format, `i` for id, `c` for command)
3. Comment removal
4. Whitespace normalization
5. Function expression shorthand

Embedded data is JSON-stringified and inserted via template literal replacement:
```javascript
const completeLogic = UTILITIES + FILLER_LOGIC
    .replace('__LOOKUP_DATA__', JSON.stringify(lookup))
    .replace('__FIELDMETA_DATA__', JSON.stringify(fieldMeta))
    .replace('__PRESETS_DATA__', JSON.stringify(presets))
    .replace('__KEY_FIELD_ID__', JSON.stringify(keyField));
```

#### Error Handling and User Feedback

**Modal System**

The builder uses a promise-based modal system for all user interactions:
```javascript
showModal({
    title: "Modal Title",
    message: "Optional message",
    inputs: [{label, type, options, value}],  // Optional form fields
    buttons: [{text, value, class}]
})
```

**Safe Execution Wrapper**

All potentially failing operations are wrapped in `safely()`:
```javascript
async safely(fn, errorContext) {
    try {
        return await fn();
    } catch (e) {
        await showError(`${errorContext}: ${e.message}`);
        return null;
    }
}
```

**Validation**

- Duplicate field ID detection during mapping load
- Required field checks (group name, bookmarklet name)
- File format validation for Excel uploads
- Session state validation via key field

## Technical Dependencies

### External Libraries (CDN)

- **Tailwind CSS** (via `cdn.tailwindcss.com`): Utility-first styling framework
- **Google Fonts - Inter**: Typography
- **SheetJS/XLSX** (v0.18.5): Excel file parsing for preset import

### Browser APIs

- `localStorage`: Persistent state storage for builder configuration
- `sessionStorage`: Cross-reload state for generated bookmarklets
- `TreeWalker`: DOM traversal for text search functionality
- `Blob` + `URL.createObjectURL`: Client-side file generation for data export
- `FileReader`: Excel file upload processing
- Drag and Drop API: Preset group reordering
- `CustomEvent` / `dispatchEvent`: Synthetic event triggering for CAIM forms

## Browser Compatibility

**Minimum Requirements**:
- ES6 support (arrow functions, template literals, destructuring)
- Modern DOM APIs (querySelector, classList, dataset)
- CSS Grid and Flexbox
- FileReader API
- Clipboard API (for JSON copy functionality)

**Tested Browsers**:
- Chrome/Edge 90+
- Firefox 88+
- Safari 14+

## Security Considerations

### Data Privacy

- All processing occurs client-side
- No data transmission to external servers
- localStorage/sessionStorage data scoped to origin
- Generated bookmarklets are self-contained (no external fetches)

### XSS Prevention

The builder implements HTML escaping via `escapeHtml()` utility for all user-supplied content rendered in the UI:
```javascript
escapeHtml: str => String(str || '')
    .replace(/[&<>"']/g, m => ({
        '&':'&amp;', '<':'&lt;', '>':'&gt;', 
        '"':'&quot;', "'":"&#39;"
    })[m])
```

### Bookmarklet Scope

Generated bookmarklets run in the context of the target page (CAIM) and have access to:
- Page DOM
- Page JavaScript context
- SessionStorage (shared with page)

They cannot access:
- Other origins (same-origin policy)
- Browser storage from other sites
- System resources

## Usage Workflow

### Quick Bookmarklets

1. Open `caim_bookmarklets.html` in browser
2. Drag desired bookmarklet link to bookmarks bar
3. Navigate to CAIM page
4. Click bookmarklet from bookmarks bar
5. Interact with injected UI (panel, search box, etc.)

### Preset Form Filler

**One-Time Setup**:
1. Open `caim_preset_filler.html`
2. Drag "Field Mapper Tool" to bookmarks bar
3. Navigate to target CAIM form
4. Click Field Mapper bookmarklet
5. Use mapping modes to capture form structure:
   - Click "Map Key Field" → Click username field
   - Click "Scan Duallists" → Auto-map all duallist fields
   - Click "Map Simple" → Click standard fields
6. Click "Generate & Copy JSON"
7. Return to builder page, paste JSON into "Field Mappings JSON" textarea
8. Click "Load Mappings"

**Preset Configuration**:
9. (Optional) Configure field behaviors (e.g., "Add All" for duallists)
10. Click "Download Template" to get Excel template
11. Fill template with preset data (one row per preset)
12. Upload Excel file, name the group, click "Import Group"
13. Repeat for additional preset groups (locations, roles, etc.)
14. Drag groups to set merge priority

**Bookmarklet Generation**:
15. Enter bookmarklet name
16. Click "Generate Bookmarklet"
17. Drag generated link to bookmarks bar

**Form Filling**:
18. Navigate to CAIM form
19. Click form filler bookmarklet
20. Select presets (if prompted)
21. Bookmarklet fills standard fields and performs first duallist action
22. After page reload, click bookmarklet again
23. Repeat until "Complete!" message appears

## Maintenance and Extensibility

### Adding New Quick Bookmarklets

1. Add a new section to `caim_bookmarklets.html` with the card markup
2. Create a `<script type="text/template" id="{name}-src">` tag with the bookmarklet logic
3. Add the anchor tag with matching ID
4. Add the `buildBookmarklet(linkId, sourceId)` call in the DOMContentLoaded listener

### Modifying Field Mapping Logic

The Field Mapper Tool's core logic is in the `BUILDER_TOOL.BUILDER_LOGIC` string within `caim_preset_filler.html`. Key functions:
- `gId()`: Element ID extraction strategy
- `aF()`: Format auto-detection heuristics
- `add()`: Validation rules for new mappings

### Extending Form Filler Capabilities

The generated bookmarklet's logic is in the `FILLER_LOGIC` string. Key extension points:
- `gV()`: Add support for new input types
- `x()`: Add new action types beyond 'set' and 'clear'
- `pl()`: Add new comparison strategies or action planning rules

## Troubleshooting

### Common Issues

**Bookmarklet Does Nothing**:
- Check browser console for errors
- Verify the bookmarklet code is properly encoded
- Ensure target page has finished loading

**Field Mapper Can't Find Fields**:
- CAIM fields may lack both `id` and `name` attributes
- Custom CAIM implementations may use different selectors
- Modify `gEl()` function to handle custom selectors

**Form Filler Applies Wrong Values**:
- Key field may not be properly mapped
- Preset values may not match exact format (check code:description vs text)
- Clear browser sessionStorage and retry

**Preset Import Fails**:
- Verify Excel column headers exactly match field IDs (case-sensitive)
- Ensure "Name" column exists and is spelled correctly
- Check for duplicate field IDs in mappings JSON

**Page Reloads Indefinitely**:
- SessionStorage may be corrupted
- Clear sessionStorage and restart
- Verify key field exists and is correctly mapped

### Debug Mode

To inspect generated bookmarklet code:
1. Right-click generated bookmarklet link
2. Copy link address
3. Decode using `decodeURIComponent()`
4. Paste into console or code editor

To inspect session state:
```javascript
// In browser console on CAIM page
JSON.parse(sessionStorage.getItem('_caim_fill_s'))
```

## Version History

**Current Version**: v9.9 (caim_preset_filler.html)

This version includes:
- Enhanced Field Mapper with visual highlighting (green backgrounds for mapped fields)
- "Scan Duallists" auto-detection feature
- "Map Key Field" for session validation
- "Add All" field configuration for duallists
- "Clear Unspecified" option for preset groups
- Auto-skip preset selection modal when only one preset per group
- Drag-and-drop preset group prioritization
- Dark mode support in preset selection modal

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the current status of features and future plans.

## License and Attribution

This suite was developed for internal use with CA Identity Manager (CAIM) environments. All code runs client-side and is self-contained within the HTML files. External dependencies are loaded via CDN and remain under their respective licenses.

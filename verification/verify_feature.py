import os
import time
import json
from playwright.sync_api import sync_playwright

def verify_feature(page):
    print("Navigating...")
    page.goto("http://localhost:8000/caim_preset_filler.html", wait_until="load", timeout=10000)
    print("Navigated.")

    # Define a complex mapping with potential XSS in field IDs
    mappings = {
        "keyField": "userId",
        "mappings": [
            {
                "sourceId": "s1",
                "sourceOptions": ["opt1", "opt2"],
                "format": "text",
                "destinations": [{"id": "<b>NormalField</b>", "type": "duallist"}]
            }
        ]
    }

    page.evaluate(f"""async () => {{
        while (typeof app === 'undefined') {{
            await new Promise(r => setTimeout(r, 100));
        }}
        app.showStep(2);
        document.getElementById('mappings-json').value = '{json.dumps(mappings)}';
        await app.renderPresetUI();
    }}""")

    time.sleep(2)

    # Check if <b>NormalField</b> is rendered literally (escaped) or as bold (injected)
    label_text = page.evaluate("document.querySelector('#field-configs-container label').innerText")
    print(f"Label text: {label_text}")

    page.screenshot(path="verification/verification.png")
    time.sleep(1)

if __name__ == "__main__":
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        os.makedirs("verification/video", exist_ok=True)
        context = browser.new_context(record_video_dir="verification/video")
        page = context.new_page()
        # Mock CDNs
        page.route("https://cdn.tailwindcss.com", lambda route: route.fulfill(content_type="text/javascript", body=""))
        page.route("https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js", lambda route: route.fulfill(content_type="text/javascript", body="window.XLSX={};"))
        page.route("https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap", lambda route: route.fulfill(content_type="text/css", body=""))

        try:
            verify_feature(page)
        finally:
            context.close()
            browser.close()

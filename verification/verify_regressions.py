import os
import time
import json
from playwright.sync_api import sync_playwright

def verify_regressions(page):
    print("Navigating...")
    page.goto("http://localhost:8000/caim_preset_filler.html", wait_until="load", timeout=10000)

    # Wait for app
    page.evaluate("while (typeof app === 'undefined') {}")

    # Trigger Mapper Tool to see the arrow and CSS
    page.evaluate("app.BUILDER_TOOL.getMinifiedScript()") # Just to ensure it's loaded

    # We can't easily "see" the bookmarklet UI in this test without clicking the link,
    # but we can check the BUILDER_LOGIC string directly.
    logic = page.evaluate("app.BUILDER_TOOL.BUILDER_LOGIC")

    if "border-top:1Gpx" in logic:
        print("CSS Typo STILL PRESENT")
    else:
        print("CSS Typo fixed.")

    if "eH(m.sId+' &rarr; '+m.destinations[0].id)" in logic:
        print("Arrow bug STILL PRESENT")
    else:
        print("Arrow bug fixed (arrow is not escaped).")

if __name__ == "__main__":
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        try:
            verify_regressions(page)
        finally:
            browser.close()

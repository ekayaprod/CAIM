import os
import time
import json
from playwright.sync_api import sync_playwright

def test_xss():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()

        page.route("https://cdn.tailwindcss.com", lambda route: route.fulfill(content_type="text/javascript", body=""))
        page.route("https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js", lambda route: route.fulfill(content_type="text/javascript", body="window.XLSX={};"))
        page.route("https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap", lambda route: route.fulfill(content_type="text/css", body=""))

        print("Loading page...")
        try:
            page.goto("http://localhost:8000/caim_preset_filler.html", wait_until="load", timeout=10000)
            print("Page loaded.")

            page.evaluate("""async () => {
                window.xss_triggered = false;
                app.confirmAction = () => Promise.resolve(true);

                const mappingsJson = document.getElementById("mappings-json");

                const payload = {
                    "keyField": "test",
                    "mappings": [
                        {
                            "sourceId": "s1",
                            "sourceOptions": [],
                            "format": "text",
                            "destinations": [
                                {"id": '"><img src=x onerror="window.xss_triggered=true">', "type": "duallist"}
                            ]
                        }
                    ]
                };

                mappingsJson.value = JSON.stringify(payload);
                await app.renderPresetUI();
            }""")

            time.sleep(2)
            triggered = page.evaluate("window.xss_triggered")
            print(f"XSS Triggered: {triggered}")

            has_img = page.evaluate('!!document.querySelector("img[onerror=\\"window.xss_triggered=true\\"]")')
            print(f"Injected tag found in DOM: {has_img}")

            if not triggered and not has_img:
                print("FIX VERIFIED FOR renderFieldConfigsUI")
            else:
                print("VULNERABILITY STILL PRESENT")

        except Exception as e:
            print(f"Error: {e}")
        finally:
            browser.close()

if __name__ == "__main__":
    test_xss()

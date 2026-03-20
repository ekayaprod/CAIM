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

            # Test deleteGroup XSS
            # Since confirmAction calls showModal which uses innerHTML for the message,
            # and we passed the message as `Delete the "${this.escapeHtml(groupName)}" group?`,
            # it should be safe now.

            # Use evaluate to track triggers
            page.evaluate("window.xss_triggered_any = false;")

            print("Testing deleteGroup XSS...")
            page.evaluate("""async () => {
                app.state.presets.groups = [{name: '"><img src=x onerror="window.xss_triggered_any=true">', data: {}}];
                // We'll let showModal run naturally and see if the injected tag triggers.
                await app.deleteGroup(0);
            }""")
            time.sleep(1)

            print("Testing modal fields XSS...")
            page.evaluate("""async () => {
                await app.showModal({
                    title: 'Test',
                    inputs: [{label: '"><img src=x onerror="window.xss_triggered_any=true">', type: 'text'}]
                });
            }""")
            time.sleep(1)

            triggered = page.evaluate("window.xss_triggered_any")
            print(f"Any XSS Triggered: {triggered}")

            if not triggered:
                print("ALL ADDITIONAL FIXES VERIFIED")
            else:
                print("VULNERABILITIES STILL PRESENT")

        except Exception as e:
            print(f"Error: {e}")
        finally:
            browser.close()

if __name__ == "__main__":
    test_xss()

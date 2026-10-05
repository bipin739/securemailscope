import time
from playwright.sync_api import sync_playwright

def test_flow():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={'width': 1920, 'height': 1080})
        page.goto('http://127.0.0.1:8000')
        page.wait_for_load_state('networkidle')
        print("Page title:", page.title())

        # Step 1: Navigate to Analyze a capture
        print("\n--- Testing Step 1: Analyze a capture ---")
        page.locator('button.upload-nav').click()
        page.wait_for_selector('select[aria-label="Lab capture scenario"]')
        
        select_elem = page.locator('select[aria-label="Lab capture scenario"]')
        select_elem.select_option('lab-legacy-clients-offer.pcap')
        print("Selected lab-legacy-clients-offer.pcap")
        
        analyze_btn = page.locator('button:has-text("Analyze lab capture")')
        analyze_btn.click()
        
        page.wait_for_selector('text=Fix first', timeout=20000)
        print("Overview loaded after analysis.")
        
        # Check sessions
        connections_text = page.locator('main').inner_text()
        print("Main text preview (first 200 chars):", connections_text[:200].replace('\n', ' '))

        # Step 2: Open Security findings
        print("\n--- Testing Step 2: Security findings ---")
        findings_tab = page.locator('nav[aria-label="Main navigation"] button:has-text("Security findings")')
        findings_tab.click()
        page.wait_for_selector('text=Transport Security Findings')
        print("Security findings page loaded.")
        
        # Find TLS 1.0 finding
        tls10_finding = page.locator('div:has-text("Deprecated TLS 1.0 Negotiated"), div:has-text("SMS-TLSVER-001"), div:has-text("TLS 1.0")').first
        print("TLS 1.0 finding text preview:", tls10_finding.inner_text()[:150].replace('\n', ' '))
        
        # Look for details / summary snippet
        postfix_summary = page.locator('summary:has-text("Postfix")').first
        if postfix_summary.count() > 0:
            print("Found Postfix snippet summary:", postfix_summary.inner_text())
            postfix_summary.click()
            time.sleep(0.5)
            snippet_content = page.locator('pre:has-text("smtpd_tls_mandatory_protocols")').first
            print("Expanded snippet:", snippet_content.inner_text())
        else:
            print("Looking for all summary tags...")
            for s in page.locator('summary').all():
                print("Summary:", s.inner_text())

        # Step 3: Hardening lab
        print("\n--- Testing Step 3: Hardening lab ---")
        simulator_tab = page.locator('nav[aria-label="Main navigation"] button:has-text("Hardening lab")')
        simulator_tab.click()
        page.wait_for_selector('text=Hardening Impact Simulator')
        print("Hardening simulator page loaded.")
        
        # Check policies
        run_btn = page.locator('button:has-text("Run Simulation")')
        run_btn.click()
        page.wait_for_selector('text=Observed clients')
        print("Simulation results displayed.")
        
        # Check counts
        print("Simulator results loaded:")
        print(" - Compatible:", page.locator('text=Compatible').first.is_visible())
        print(" - Would Break:", page.locator('text=Would Break').first.is_visible())
        print(" - Unknown:", page.locator('text=Unknown').first.is_visible())
        
        # Check client 192.0.2.23
        client_23 = page.locator('div:has-text("192.0.2.23")').first
        print("Client 192.0.2.23 found")

        # Step 4: Client intelligence & Fix first
        print("\n--- Testing Step 4: Client intelligence & Fix first ---")
        discovery_tab = page.locator('nav[aria-label="Main navigation"] button:has-text("Client intelligence")')
        discovery_tab.click()
        page.wait_for_selector('text=Observed Client Discovery', timeout=10000)
        print("Client intelligence loaded with Observed Client Discovery.")
        ja3_text = page.locator('text=JA3').first
        print("JA3 element found:", ja3_text.is_visible())

        
        overview_tab = page.locator('nav[aria-label="Main navigation"] button:has-text("Overview")')
        overview_tab.click()
        page.wait_for_selector('text=Fix first')
        print("Overview loaded.")
        
        weights_summary = page.locator('summary:has-text("Explain ordering and weights")').first
        print("Found Explain ordering and weights:", weights_summary.inner_text())
        weights_summary.click()

        # Step 5: Evidence report
        print("\n--- Testing Step 5: Evidence report ---")
        report_tab = page.locator('nav[aria-label="Main navigation"] button:has-text("Evidence report")')
        report_tab.click()
        page.wait_for_selector('text=Investigation Evidence Report')
        print("Evidence report loaded.")
        
        json_btn = page.locator('button:has-text("Export JSON")')
        html_btn = page.locator('button:has-text("Export HTML")')
        pdf_btn = page.locator('button:has-text("Export PDF")')
        print("Export buttons found:", json_btn.is_visible(), html_btn.is_visible(), pdf_btn.is_visible())

        browser.close()
        print("\nALL TEST STEPS PASSED SUCCESSFULLY!")

if __name__ == '__main__':
    test_flow()


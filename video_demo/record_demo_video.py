import os
import sys
import time
import math
import glob
import subprocess
import imageio_ffmpeg
from playwright.sync_api import sync_playwright

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FFMPEG = imageio_ffmpeg.get_ffmpeg_exe()


CURSOR_JS = """
(() => {
    if (document.getElementById('virtual-cursor')) return;
    
    // Inject subtle frame ticker to ensure 60fps continuous rendering
    const ticker = document.createElement('div');
    ticker.id = 'sms-frame-tick';
    ticker.style.position = 'fixed';
    ticker.style.top = '0px';
    ticker.style.left = '0px';
    ticker.style.width = '1px';
    ticker.style.height = '1px';
    ticker.style.opacity = '0.99';
    ticker.style.pointerEvents = 'none';
    ticker.style.zIndex = '999998';
    document.body.appendChild(ticker);

    // Inject Cursor
    const cursor = document.createElement('div');
    cursor.id = 'virtual-cursor';
    cursor.innerHTML = `
        <svg width="28" height="28" viewBox="0 0 24 24" fill="none" style="filter: drop-shadow(0 3px 6px rgba(0,0,0,0.85));">
            <path d="M5.5 3.5L18.5 11.5L12 13.5L9.5 20L5.5 3.5Z" fill="#38bdf8" stroke="#ffffff" stroke-width="1.8" stroke-linejoin="round"/>
        </svg>
        <div id="cursor-pulse" style="position: absolute; top: 0; left: 0; width: 32px; height: 32px; border-radius: 50%; border: 2.5px solid #38bdf8; transform: translate(-10px, -10px) scale(0); opacity: 0; pointer-events: none; transition: transform 0.4s ease-out, opacity 0.4s ease-out;"></div>
    `;
    cursor.style.position = 'fixed';
    cursor.style.top = '0px';
    cursor.style.left = '0px';
    cursor.style.zIndex = '1000000';
    cursor.style.pointerEvents = 'none';
    cursor.style.transform = 'translate(400px, 300px)';
    document.body.appendChild(cursor);

    // Inject Caption Box
    const caption = document.createElement('div');
    caption.id = 'sms-caption-box';
    caption.style.position = 'fixed';
    caption.style.bottom = '40px';
    caption.style.left = '40px';
    caption.style.zIndex = '999999';
    caption.style.background = 'rgba(11, 16, 22, 0.94)';
    caption.style.border = '1.5px solid rgba(56, 189, 248, 0.45)';
    caption.style.backdropFilter = 'blur(16px)';
    caption.style.webkitBackdropFilter = 'blur(16px)';
    caption.style.boxShadow = '0 16px 40px rgba(0, 0, 0, 0.75), 0 0 25px rgba(56, 189, 248, 0.2)';
    caption.style.color = '#ffffff';
    caption.style.fontFamily = 'Inter, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif';
    caption.style.fontSize = '28px';
    caption.style.fontWeight = '600';
    caption.style.padding = '16px 28px';
    caption.style.borderRadius = '14px';
    caption.style.maxWidth = '940px';
    caption.style.lineHeight = '1.35';
    caption.style.pointerEvents = 'none';
    caption.style.opacity = '0';
    caption.style.transform = 'translateY(12px)';
    caption.style.transition = 'opacity 0.35s cubic-bezier(0.16, 1, 0.3, 1), transform 0.35s cubic-bezier(0.16, 1, 0.3, 1)';
    document.body.appendChild(caption);

    // Continuous Animation Loop (lerp mouse & subtle background breath)
    window.__curX = 400;
    window.__curY = 300;
    window.__targetX = 400;
    window.__targetY = 300;

    function animLoop() {
        window.__curX += (window.__targetX - window.__curX) * 0.22;
        window.__curY += (window.__targetY - window.__curY) * 0.22;
        
        cursor.style.transform = `translate(${window.__curX}px, ${window.__curY}px)`;
        
        const t = performance.now() / 1000;
        ticker.style.opacity = (0.95 + Math.sin(t * 10) * 0.04).toFixed(3);
        requestAnimationFrame(animLoop);
    }
    requestAnimationFrame(animLoop);

    window.__setCursor = (x, y) => {
        window.__targetX = x;
        window.__targetY = y;
    };

    window.__triggerClickPulse = () => {
        const pulse = document.getElementById('cursor-pulse');
        if (!pulse) return;
        pulse.style.transition = 'none';
        pulse.style.transform = 'translate(-10px, -10px) scale(0.2)';
        pulse.style.opacity = '1';
        setTimeout(() => {
            pulse.style.transition = 'transform 0.45s ease-out, opacity 0.45s ease-out';
            pulse.style.transform = 'translate(-10px, -10px) scale(2.0)';
            pulse.style.opacity = '0';
        }, 20);
    };

    window.__setCaption = (text) => {
        if (!text) {
            caption.style.opacity = '0';
            caption.style.transform = 'translateY(12px)';
        } else {
            caption.innerText = text;
            caption.style.opacity = '1';
            caption.style.transform = 'translateY(0px)';
        }
    };

    window.__showEndCard = () => {
        let card = document.getElementById('sms-end-card');
        if (!card) {
            card = document.createElement('div');
            card.id = 'sms-end-card';
            card.style.position = 'fixed';
            card.style.inset = '0';
            card.style.background = '#0b1016';
            card.style.zIndex = '9999999';
            card.style.display = 'flex';
            card.style.flexDirection = 'column';
            card.style.alignItems = 'center';
            card.style.justifyContent = 'center';
            card.style.textAlign = 'center';
            card.style.fontFamily = 'Inter, system-ui, sans-serif';
            card.style.opacity = '0';
            card.style.transition = 'opacity 0.8s ease';
            card.innerHTML = `
                <div style="width: 84px; height: 84px; border-radius: 24px; background: rgba(52, 211, 153, 0.12); border: 2px solid rgba(52, 211, 153, 0.45); display: flex; align-items: center; justify-content: center; margin-bottom: 28px; box-shadow: 0 0 50px rgba(52, 211, 153, 0.25);">
                    <svg width="46" height="46" viewBox="0 0 24 24" fill="none" stroke="#34d399" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                        <path d="m9 12 2 2 4-4"/>
                    </svg>
                </div>
                <h1 style="font-size: 58px; font-weight: 800; color: #ffffff; letter-spacing: -0.02em; margin: 0 0 14px 0;">SecureMailScope</h1>
                <p style="font-size: 26px; font-weight: 600; color: #6ee7b7; margin: 0 0 32px 0; letter-spacing: -0.01em;">
                    SecureMailScope | SIH 2026 | PS 26159 | Offline. Passive. Evidence-labelled.
                </p>
                <div style="padding: 14px 34px; border-radius: 12px; background: rgba(15, 23, 42, 0.95); border: 1.5px solid rgba(52, 211, 153, 0.4); font-size: 22px; font-family: monospace; color: #93c5fd; box-shadow: 0 10px 30px rgba(0,0,0,0.6);">
                    github.com/bipin739/securemailscope
                </div>
                <p style="font-size: 15px; color: #64748b; margin-top: 28px; letter-spacing: 0.06em; text-transform: uppercase;">
                    Cryptographic Security Posture Assessment for Email Communications
                </p>
            `;
            document.body.appendChild(card);
        }
        setTimeout(() => {
            card.style.opacity = '1';
        }, 50);
    };
})();
"""

class RecordingController:
    def __init__(self, page):
        self.page = page
        self.cur_x = 400
        self.cur_y = 300

    def inject_helpers(self):
        self.page.evaluate(CURSOR_JS)
        self.page.evaluate(f"window.__setCursor({self.cur_x}, {self.cur_y});")
        self.page.evaluate("document.body.style.zoom = '90%';")

    def set_caption(self, text):
        self.page.evaluate(f"window.__setCaption({repr(text)});")

    def show_end_card(self):
        self.page.evaluate("window.__showEndCard();")

    def move_to(self, target_x, target_y, duration_s=0.6, steps=25):
        start_x = self.cur_x
        start_y = self.cur_y
        dt = duration_s / steps
        for i in range(1, steps + 1):
            t = i / steps
            ease_t = 0.5 - 0.5 * math.cos(math.pi * t)
            x = start_x + (target_x - start_x) * ease_t
            y = start_y + (target_y - start_y) * ease_t
            self.cur_x = x
            self.cur_y = y
            self.page.evaluate(f"window.__setCursor({x}, {y});")
            self.page.mouse.move(x, y)
            time.sleep(dt)

    def click_element(self, selector, pre_move_duration=0.6, post_wait=0.4):
        elem = self.page.locator(selector).first
        elem.wait_for(state="visible", timeout=10000)
        box = elem.bounding_box()
        if not box:
            return
        
        target_x = (box['x'] + box['width'] / 2) * 0.90
        target_y = (box['y'] + box['height'] / 2) * 0.90
        
        self.move_to(target_x, target_y, duration_s=pre_move_duration)
        self.page.evaluate("window.__triggerClickPulse();")
        elem.click()
        time.sleep(post_wait)

    def smooth_scroll(self, delta_y, duration_s=1.0, steps=25):
        step_dy = delta_y / steps
        dt = duration_s / steps
        for _ in range(steps):
            self.page.evaluate(f"window.scrollBy(0, {step_dy});")
            self.cur_x += (math.sin(time.time() * 3) * 1.5)
            self.page.evaluate(f"window.__setCursor({self.cur_x}, {self.cur_y});")
            time.sleep(dt)

    def continuous_motion(self, duration_s=1.0, steps=25):
        dt = duration_s / steps
        for _ in range(steps):
            self.cur_x += (math.sin(time.time() * 2.5) * 3.0)
            self.cur_y += (math.cos(time.time() * 2.5) * 2.0)
            self.page.evaluate(f"window.__setCursor({self.cur_x}, {self.cur_y});")
            time.sleep(dt)

def prewarm_app():
    print("--- Pre-warming app & caching API responses ---")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={'width': 1920, 'height': 1080})
        page.goto('http://127.0.0.1:8000')
        page.wait_for_load_state('networkidle')
        
        # Analyze lab capture
        page.locator('button.upload-nav').click()
        page.wait_for_selector('select[aria-label="Lab capture scenario"]')
        page.locator('select[aria-label="Lab capture scenario"]').select_option('lab-legacy-clients-offer.pcap')
        page.locator('button:has-text("Analyze lab capture")').click()
        page.wait_for_selector('text=Fix first', timeout=20000)
        
        # Pre-warm other tabs
        page.locator('nav[aria-label="Main navigation"] button:has-text("Security findings")').click()
        time.sleep(0.3)
        page.locator('nav[aria-label="Main navigation"] button:has-text("Hardening lab")').click()
        time.sleep(0.3)
        page.locator('button:has-text("Run Simulation")').click()
        time.sleep(0.3)
        page.locator('nav[aria-label="Main navigation"] button:has-text("Client intelligence")').click()
        time.sleep(0.3)
        page.locator('nav[aria-label="Main navigation"] button:has-text("Evidence report")').click()
        time.sleep(0.8)
        
        browser.close()
        print("--- Pre-warming complete ---")

def execute_single_pass_recording():
    prewarm_app()
    
    rec_dir = os.path.join(BASE_DIR, "recordings")
    os.makedirs(rec_dir, exist_ok=True)
    
    # Clean old webm recordings
    for old_file in glob.glob(os.path.join(rec_dir, "*.webm")):
        try:
            os.remove(old_file)
        except Exception:
            pass

    print("\n=======================================================")
    print("STARTING CONTINUOUS SINGLE-PASS DEMO RECORDING")
    print("=======================================================")

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            args=[
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--hide-scrollbars',
                '--disable-infobars',
                '--window-size=1920,1080',
                '--force-device-scale-factor=1',
            ]
        )
        
        context = browser.new_context(
            viewport={'width': 1920, 'height': 1080},
            record_video_dir=rec_dir,
            record_video_size={"width": 1920, "height": 1080}
        )
        
        page = context.new_page()
        page.goto('http://127.0.0.1:8000')
        page.wait_for_load_state('networkidle')
        time.sleep(0.3)
        
        ctrl = RecordingController(page)
        ctrl.inject_helpers()
        page.on("framenavigated", lambda frame: ctrl.inject_helpers())

        start_time = time.time()
        print("Recording clock started at t=0.00s")

        # ---------------------------------------------------------------------
        # 0:00 - 0:10 (Analyze capture lab)
        # ---------------------------------------------------------------------
        print("[0:00 - 0:10] Section 1: Analyze capture lab")
        ctrl.set_caption("Real packet bytes in, TShark pipeline, fully offline.")
        ctrl.move_to(450, 320, duration_s=0.6)
        
        ctrl.click_element('button.upload-nav', pre_move_duration=0.6, post_wait=0.3)
        ctrl.inject_helpers()
        
        ctrl.move_to(650, 240, duration_s=0.6)
        select_elem = page.locator('select[aria-label="Lab capture scenario"]')
        select_elem.select_option('lab-legacy-clients-offer.pcap')
        time.sleep(0.2)
        
        ctrl.click_element('button:has-text("Analyze lab capture")', pre_move_duration=0.6, post_wait=0.4)
        page.wait_for_selector('text=Fix first', timeout=15000)
        ctrl.inject_helpers()
        
        ctrl.move_to(750, 420, duration_s=0.8)
        ctrl.smooth_scroll(160, duration_s=0.8)
        
        # Pad to exactly 10.0s
        elapsed = time.time() - start_time
        if elapsed < 10.0:
            ctrl.continuous_motion(duration_s=(10.0 - elapsed))

        # ---------------------------------------------------------------------
        # 0:10 - 0:30 (Security findings & Postfix fix snippet)
        # ---------------------------------------------------------------------
        print(f"[0:10 - 0:30] Section 2: Security findings (current t={time.time() - start_time:.2f}s)")
        ctrl.set_caption("Evidence + RULE-based fix guidance. Never auto-applied.")
        
        ctrl.smooth_scroll(-160, duration_s=0.6)
        ctrl.click_element('nav[aria-label="Main navigation"] button:has-text("Security findings")', pre_move_duration=0.6, post_wait=0.4)
        ctrl.inject_helpers()
        
        ctrl.move_to(650, 220, duration_s=0.8)
        ctrl.smooth_scroll(240, duration_s=1.0)
        ctrl.move_to(1050, 420, duration_s=1.0)
        
        # Expand Postfix snippet
        postfix_summary = page.locator('summary:has-text("Postfix")').first
        if postfix_summary.count() > 0:
            box = postfix_summary.bounding_box()
            if box:
                ctrl.move_to((box['x'] + box['width']/2)*0.90, (box['y'] + box['height']/2)*0.90, duration_s=0.8)
                postfix_summary.click()
                time.sleep(0.3)
        
        ctrl.smooth_scroll(220, duration_s=1.2)
        ctrl.move_to(1050, 680, duration_s=1.2)
        
        # Pad to exactly 30.0s
        elapsed = time.time() - start_time
        if elapsed < 30.0:
            ctrl.continuous_motion(duration_s=(30.0 - elapsed))

        # ---------------------------------------------------------------------
        # 0:30 - 0:55 (Hardening lab & WOULD_BREAK breakdown)
        # ---------------------------------------------------------------------
        print(f"[0:30 - 0:55] Section 3: Hardening lab (current t={time.time() - start_time:.2f}s)")
        ctrl.set_caption("Know what breaks BEFORE you harden.")
        
        ctrl.smooth_scroll(-440, duration_s=0.8)
        ctrl.click_element('nav[aria-label="Main navigation"] button:has-text("Hardening lab")', pre_move_duration=0.6, post_wait=0.4)
        ctrl.inject_helpers()
        
        ctrl.move_to(600, 340, duration_s=0.8)
        ctrl.move_to(950, 340, duration_s=0.8)
        
        ctrl.click_element('button:has-text("Run Simulation")', pre_move_duration=0.6, post_wait=0.6)
        ctrl.inject_helpers()
        
        ctrl.smooth_scroll(200, duration_s=1.0)
        
        # Metric cards: Compatible, Would Break, Unknown
        ctrl.move_to(650, 360, duration_s=1.0)
        ctrl.continuous_motion(duration_s=1.0)
        ctrl.move_to(900, 360, duration_s=1.0)
        ctrl.continuous_motion(duration_s=1.0)
        ctrl.move_to(1150, 360, duration_s=1.0)
        ctrl.continuous_motion(duration_s=1.0)
        
        ctrl.smooth_scroll(320, duration_s=1.2)
        
        # Client 192.0.2.23 (TLS 1.0 only, WOULD_BREAK)
        client_23_elem = page.locator('div:has-text("192.0.2.23")').first
        box = client_23_elem.bounding_box()
        if box:
            ctrl.move_to((box['x'] + 150)*0.90, (box['y'] + 25)*0.90, duration_s=0.8)
            ctrl.continuous_motion(duration_s=1.2)
            
        ctrl.smooth_scroll(160, duration_s=1.0)
        ctrl.move_to(700, 580, duration_s=1.0)
        
        # Pad to exactly 55.0s
        elapsed = time.time() - start_time
        if elapsed < 55.0:
            ctrl.continuous_motion(duration_s=(55.0 - elapsed))

        # ---------------------------------------------------------------------
        # 0:55 - 1:10 (Client intelligence & Fix first weights)
        # ---------------------------------------------------------------------
        print(f"[0:55 - 1:10] Section 4: Client intelligence & Fix first (current t={time.time() - start_time:.2f}s)")
        ctrl.set_caption("Offline JA3. Honest, explainable prioritisation.")
        
        ctrl.smooth_scroll(-680, duration_s=0.8)
        ctrl.click_element('nav[aria-label="Main navigation"] button:has-text("Client intelligence")', pre_move_duration=0.6, post_wait=0.4)
        ctrl.inject_helpers()
        
        ctrl.smooth_scroll(200, duration_s=0.8)
        ctrl.move_to(550, 480, duration_s=1.0)
        ctrl.continuous_motion(duration_s=1.0)
        ctrl.move_to(550, 620, duration_s=1.0)
        ctrl.continuous_motion(duration_s=1.0)
        
        ctrl.smooth_scroll(-200, duration_s=0.5)
        ctrl.click_element('nav[aria-label="Main navigation"] button:has-text("Overview")', pre_move_duration=0.6, post_wait=0.4)
        ctrl.inject_helpers()
        
        ctrl.smooth_scroll(380, duration_s=1.0)
        
        weights_elem = page.locator('summary:has-text("Explain ordering and weights")').first
        box = weights_elem.bounding_box()
        if box:
            ctrl.move_to((box['x'] + 80)*0.90, (box['y'] + 10)*0.90, duration_s=0.6)
            weights_elem.click()
            time.sleep(0.3)
            
        ctrl.move_to(650, 520, duration_s=1.0)
        
        # Pad to exactly 70.0s
        elapsed = time.time() - start_time
        if elapsed < 70.0:
            ctrl.continuous_motion(duration_s=(70.0 - elapsed))

        # ---------------------------------------------------------------------
        # 1:10 - 1:25 (Evidence report & integrity export)
        # ---------------------------------------------------------------------
        print(f"[1:10 - 1:25] Section 5: Evidence report (current t={time.time() - start_time:.2f}s)")
        ctrl.set_caption("Tamper-evident reports with SHA-256 digests.")
        
        ctrl.smooth_scroll(-380, duration_s=0.6)
        ctrl.click_element('nav[aria-label="Main navigation"] button:has-text("Evidence report")', pre_move_duration=0.6, post_wait=0.5)
        ctrl.inject_helpers()
        
        ctrl.move_to(600, 240, duration_s=0.8)
        ctrl.continuous_motion(duration_s=0.8)
        
        ctrl.click_element('button:has-text("Export JSON")', pre_move_duration=0.5, post_wait=0.3)
        ctrl.click_element('button:has-text("Export HTML")', pre_move_duration=0.5, post_wait=0.3)
        ctrl.click_element('button:has-text("Export PDF")', pre_move_duration=0.5, post_wait=0.5)
        
        ctrl.smooth_scroll(260, duration_s=1.2)
        ctrl.move_to(800, 480, duration_s=1.2)
        
        # Pad to exactly 85.0s
        elapsed = time.time() - start_time
        if elapsed < 85.0:
            ctrl.continuous_motion(duration_s=(85.0 - elapsed))

        # ---------------------------------------------------------------------
        # 1:25 - 1:30 (End Card)
        # ---------------------------------------------------------------------
        print(f"[1:25 - 1:30] Section 6: End card (current t={time.time() - start_time:.2f}s)")
        ctrl.set_caption("")
        ctrl.show_end_card()
        
        elapsed = time.time() - start_time
        remaining = max(4.5, 90.0 - elapsed)
        ctrl.continuous_motion(duration_s=remaining)

        total_recorded = time.time() - start_time
        print(f"\nRecording completed in {total_recorded:.2f} seconds!")

        page.close()
        context.close()
        browser.close()

def post_process_video():
    print("\n=======================================================")
    print("POST-PROCESSING VIDEO WITH FFMPEG 7.1")
    print("=======================================================")

    rec_dir = os.path.join(BASE_DIR, "recordings")
    webm_files = glob.glob(os.path.join(rec_dir, "*.webm"))
    if not webm_files:
        raise RuntimeError(f"No recorded webm video found in {rec_dir}")
    
    raw_video = webm_files[0]
    print(f"Source raw video: {raw_video}")

    # 1. Run freezedetect and blackdetect verification
    print("\n[1/3] Running freezedetect & blackdetect check...")
    detect_cmd = [
        FFMPEG, "-i", raw_video,
        "-vf", "freezedetect=n=-50dB:d=1.5,blackdetect=d=0.5:pix_th=0.1",
        "-f", "null", "-"
    ]
    detect_res = subprocess.run(detect_cmd, capture_output=True, text=True)
    
    freezes = [line for line in detect_res.stderr.splitlines() if "lavfi.freezedetect" in line or "blackdetect" in line]
    print(f"Freezedetect / blackdetect results ({len(freezes)} events detected):")
    for f in freezes[:10]:
        print("  ", f)

    # 2. Get exact source duration
    probe_cmd = [
        FFMPEG, "-i", raw_video
    ]
    probe_res = subprocess.run(probe_cmd, capture_output=True, text=True)
    import re
    dur_match = re.search(r"Duration:\s*(\d+):(\d+):([\d\.]+)", probe_res.stderr)
    if dur_match:
        hours, mins, secs = dur_match.groups()
        source_dur = float(hours)*3600 + float(mins)*60 + float(secs)
    else:
        source_dur = 90.0
    print(f"Raw video duration: {source_dur:.2f}s")

    # Target duration: exactly 90.0s (within 85-95s rule)
    target_dur = 90.0
    pts_factor = target_dur / source_dur
    print(f"Adjusting setpts factor to {pts_factor:.4f} for perfect {target_dur}s duration")

    # 3. Assemble and encode final MP4
    output_mp4 = os.path.join(BASE_DIR, "SecureMailScope_Demo_Video.mp4")
    audio_track = os.path.join(BASE_DIR, "voiceover", "full_voiceover_90s.mp3")
    
    print(f"\n[2/3] Muxing and encoding final MP4 ({output_mp4})...")
    encode_cmd = [
        FFMPEG, "-y",
        "-i", raw_video,
        "-i", audio_track,
        "-filter_complex",
        f"[0:v]setpts={pts_factor:.6f}*PTS,fps=30,scale=1920:1080:flags=lanczos,format=yuv420p[v]",
        "-map", "[v]",
        "-map", "1:a",
        "-c:v", "libx264",
        "-preset", "medium",
        "-crf", "18",
        "-c:a", "aac",
        "-b:a", "192k",
        "-t", "90",
        "-movflags", "+faststart",
        output_mp4
    ]
    subprocess.run(encode_cmd, check=True)

    # 4. Final verification of output file
    print(f"\n[3/3] Verifying final MP4 video properties...")
    final_probe = subprocess.run([FFMPEG, "-i", output_mp4], capture_output=True, text=True)
    print(final_probe.stderr)

    file_size_mb = os.path.getsize(output_mp4) / (1024 * 1024)
    print(f"\n=======================================================")
    print(f"SUCCESS! Output Video Generated: {output_mp4}")
    print(f"Size: {file_size_mb:.2f} MB | Resolution: 1920x1080 | 30 FPS | Target: 90.0s")
    print(f"=======================================================")

if __name__ == '__main__':
    execute_single_pass_recording()
    post_process_video()


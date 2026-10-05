import asyncio
import os
import edge_tts
import subprocess
import imageio_ffmpeg

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FFMPEG = imageio_ffmpeg.get_ffmpeg_exe()

VOICEOVER_SECTIONS = [
    {
        "id": "part1_intro",
        "rate": "+15%",
        "text": "Email still carries cleartext logins and legacy TLS, and analysts have no fast way to see it. SecureMailScope reads an authorized packet capture completely offline."
    },
    {
        "id": "part2_findings",
        "rate": "+5%",
        "text": "Here, five mail sessions are rebuilt from real packet bytes. Every finding is labelled observed, rule, or assumption, with a concrete fix, such as this Postfix setting."
    },
    {
        "id": "part3_hardening",
        "rate": "+5%",
        "text": "Our hardening lab answers the question admins fear: what breaks if we enforce TLS 1.2? Two clients would break, two are compatible, and one is unknown because the evidence is missing. We never guess."
    },
    {
        "id": "part4_intel",
        "rate": "+5%",
        "text": "Client fingerprints are derived offline, and the fix-first list shows its exact weights, with machine learning only breaking ties."
    },
    {
        "id": "part5_report",
        "rate": "+8%",
        "text": "Finally, a verified report exports as JSON, HTML or PDF with integrity digests. SecureMailScope: offline, passive, and honest about evidence."
    }
]

async def generate_and_assemble():
    vo_dir = os.path.join(BASE_DIR, "voiceover")
    os.makedirs(vo_dir, exist_ok=True)
    voice = "en-US-ChristopherNeural"
    
    for section in VOICEOVER_SECTIONS:
        out_path = os.path.join(vo_dir, f"{section['id']}.mp3")
        communicate = edge_tts.Communicate(section['text'], voice, rate=section['rate'])
        await communicate.save(out_path)
        print(f"Generated {out_path}")

    p1 = os.path.join(vo_dir, "part1_intro.mp3")
    p2 = os.path.join(vo_dir, "part2_findings.mp3")
    p3 = os.path.join(vo_dir, "part3_hardening.mp3")
    p4 = os.path.join(vo_dir, "part4_intel.mp3")
    p5 = os.path.join(vo_dir, "part5_report.mp3")
    full_out = os.path.join(vo_dir, "full_voiceover_90s.mp3")

    cmd = [
        FFMPEG, "-y",
        "-i", p1,
        "-i", p2,
        "-i", p3,
        "-i", p4,
        "-i", p5,
        "-filter_complex",
        "[0:a]adelay=600|600,volume=1.8[a0];"
        "[1:a]adelay=10500|10500,volume=1.8[a1];"
        "[2:a]adelay=30500|30500,volume=1.8[a2];"
        "[3:a]adelay=55500|55500,volume=1.8[a3];"
        "[4:a]adelay=70500|70500,volume=1.8[a4];"
        "[a0][a1][a2][a3][a4]amix=inputs=5:duration=longest[aout]",
        "-map", "[aout]",
        "-t", "90",
        "-ac", "2",
        "-ar", "44100",
        full_out
    ]
    subprocess.run(cmd, check=True)
    print(f"Full voiceover track saved to {full_out}")

if __name__ == '__main__':
    asyncio.run(generate_and_assemble())

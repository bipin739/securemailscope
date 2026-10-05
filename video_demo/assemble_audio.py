import os
import subprocess

FFMPEG = r"D:\Proteus\Tools\Python\ffmpeg.exe"

def assemble_audio():
    # We will use ffmpeg adelay and amix or an audio filter graph to place each audio clip at its precise timestamp
    # part1 at 0.8s (800ms)
    # part2 at 10.8s (10800ms)
    # part3 at 31.0s (31000ms)
    # part4 at 55.8s (55800ms)
    # part5 at 71.0s (71000ms)
    
    cmd = [
        FFMPEG, "-y",
        "-i", "voiceover/part1_intro.mp3",
        "-i", "voiceover/part2_findings.mp3",
        "-i", "voiceover/part3_hardening.mp3",
        "-i", "voiceover/part4_intel.mp3",
        "-i", "voiceover/part5_report.mp3",
        "-filter_complex",
        "[0:a]adelay=800|800[a0];"
        "[1:a]adelay=10800|10800[a1];"
        "[2:a]adelay=31000|31000[a2];"
        "[3:a]adelay=55800|55800[a3];"
        "[4:a]adelay=71000|71000[a4];"
        "[a0][a1][a2][a3][a4]amix=inputs=5:normalize=0[aout]",
        "-map", "[aout]",
        "-t", "90",
        "-ac", "2",
        "-ar", "44100",
        "voiceover/full_voiceover_90s.mp3"
    ]
    
    subprocess.run(cmd, check=True)
    print("Full 90s voiceover track assembled!")

if __name__ == '__main__':
    assemble_audio()

import urllib.request
import json
import os

pcap_path = r"C:\Users\LOQ\Downloads\smtp.pcap"
with open(pcap_path, "rb") as f:
    file_bytes = f.read()

boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
body = (
    f"--{boundary}\r\n"
    f'Content-Disposition: form-data; name="file"; filename="smtp.pcap"\r\n'
    f"Content-Type: application/vnd.tcpdump.pcap\r\n\r\n"
).encode("utf-8") + file_bytes + f"\r\n--{boundary}--\r\n".encode("utf-8")

req = urllib.request.Request("http://127.0.0.1:8000/api/investigations/analyze", data=body)
req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
with urllib.request.urlopen(req) as resp:
    inv = json.loads(resp.read().decode("utf-8"))
    print("Investigation ID:", inv["id"])
    print("Data Source:", inv["data_source"])
    print("Total replays:", len(inv.get("replays", [])))
    if inv.get("replays"):
        r = inv["replays"][0]
        print("Session ID:", r["session_id"])
        print("Client -> Server:", r["summary"]["client_endpoint"], "->", r["summary"]["server_endpoint"])
        print("Event Count:", len(r["events"]))
        print("Critical Moment:", r.get("critical_moment"))
        print("\n--- CHRONOLOGICAL SECURITY EVENTS ---")
        for idx, evt in enumerate(r["events"]):
            print(f"  [{idx+1}] +{evt['relative_time_ms']/1000:.3f}s | {evt['direction']:16} | {evt['event_type']:28} | {evt['security_state']:8} | {evt['title']}")

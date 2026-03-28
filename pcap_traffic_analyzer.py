import os
import subprocess
from datetime import datetime
from concurrent.futures import ProcessPoolExecutor, as_completed
import csv

PCAP_DIR = "C:\\Users\\Scott\\OneDrive\\Desktop\\networklabs\\Network_Traffic"
MAX_WORKERS = os.cpu_count()

TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"
CAPINFOS_PATH = r"C:\Program Files\Wireshark\capinfos.exe"

DEBUG = True
EXPORT_CSV = True


def debug(msg):
    if DEBUG:
        print(f"[DEBUG] {msg}")


def get_capinfos_count(file_path):
    try:
        # Surround file path with quotes for Windows
        cmd = f'"{CAPINFOS_PATH}" -c "{file_path}"'
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            shell=True  # shell=True allows the quotes to work
        )

        if result.returncode != 0:
            debug(f"capinfos failed on {file_path} | stderr: {result.stderr.strip()}")
            return None

        for line in result.stdout.splitlines():
            if "Number of packets" in line:
                return int(line.split(":")[1].strip())

        debug(f"No packet line found in capinfos output: {file_path} | stdout: {result.stdout.strip()}")
        return None

    except Exception as e:
        debug(f"capinfos exception on {file_path}: {e}")
        return None


def process_pcap(file_path):
    try:
        debug(f"Processing: {file_path}")

        cmd = [
            TSHARK_PATH,
            "-r", file_path,
            "-T", "fields",
            "-e", "frame.time_epoch"
        ]

        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        first_time = None
        last_time = None
        packet_count = 0

        for line in proc.stdout:
            try:
                ts = float(line.strip())
                packet_count += 1

                if first_time is None:
                    first_time = ts

                last_time = ts

            except Exception:
                continue

        proc.wait()

        if packet_count == 0:
            debug(f"No packets: {file_path}")
            return None

        capinfos_count = get_capinfos_count(file_path)
        debug(f"capinfos count for {file_path}: {capinfos_count}")
        
        mismatch = False
        if capinfos_count is not None and capinfos_count != packet_count:
            mismatch = True
            debug(f"COUNT MISMATCH: {file_path} | tshark={packet_count}, capinfos={capinfos_count}")

        return {
            "file": file_path,
            "packets": packet_count,
            "capinfos_packets": capinfos_count,
            "mismatch": mismatch,
            "start": datetime.fromtimestamp(first_time),
            "end": datetime.fromtimestamp(last_time)
        }

    except Exception as e:
        debug(f"Error processing {file_path}: {e}")
        return None


def main():
    pcap_files = []

    print("Scanning directory...\n")

    for root, _, files in os.walk(PCAP_DIR):
        for file in files:
            full_path = os.path.join(root, file)

            if os.path.getsize(full_path) == 0:
                continue

            pcap_files.append(full_path)

    print(f"Found {len(pcap_files)} candidate files\n")

    results = []

    with ProcessPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(process_pcap, f): f for f in pcap_files}

        for future in as_completed(futures):
            result = future.result()
            if result:
                results.append(result)

    # Aggregate totals
    total_packets = sum(r["packets"] for r in results)
    earliest_time = min(r["start"] for r in results)
    latest_time = max(r["end"] for r in results)

    duration = latest_time - earliest_time
    days = duration.days
    seconds = duration.seconds

    weeks = days // 7
    months = days // 30
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60

    # Count mismatches
    mismatches = [r for r in results if r["mismatch"]]

    print("\n===== FINAL RESULTS =====")
    print(f"Total Packets: {total_packets}")
    print(f"Start Time: {earliest_time}")
    print(f"End Time:   {latest_time}")
    print("\nTotal Duration:")
    print(f"{months} months, {weeks} weeks, {days} days, {hours} hours, {minutes} minutes")

    print(f"\nFiles with count mismatches: {len(mismatches)}")

    # Optional CSV export
    if EXPORT_CSV:
        csv_file = "pcap_analysis.csv"
        with open(csv_file, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "file", "packets", "capinfos_packets", "mismatch", "start", "end"
            ])
            writer.writeheader()
            writer.writerows(results)

        print(f"\nCSV exported: {csv_file}")


if __name__ == "__main__":
    main()

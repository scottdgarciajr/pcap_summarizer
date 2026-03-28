# PCAP Traffic Analyzer

A Python script to analyze multiple PCAP files, extract packet counts and timestamps, compare results with Wireshark's `capinfos`, and export the analysis to a CSV file.

---

## Features

- Recursively scans a specified directory for PCAP files.
- Uses `tshark` to count packets and capture the first and last timestamps.
- Optionally uses `capinfos` to cross-check packet counts.
- Detects mismatches between `tshark` and `capinfos` packet counts.
- Aggregates total packets, earliest start time, latest end time, and overall duration.
- Supports parallel processing using all available CPU cores.
- Exports results to a CSV file for further analysis.

---

## Requirements

- Python 3.7+
- [Wireshark](https://www.wireshark.org/) installed with:
  - `tshark.exe`
  - `capinfos.exe`
- PCAP files to analyze.

---

## Configuration

Edit the following variables at the top of the script:

```python
PCAP_DIR = "C:\\path\\to\\pcap\\directory"       # Directory containing PCAP files
TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"  # Path to tshark
CAPINFOS_PATH = r"C:\Program Files\Wireshark\capinfos.exe"  # Path to capinfos
DEBUG = True          # Enable/disable debug logging
EXPORT_CSV = True     # Enable/disable CSV export
MAX_WORKERS = os.cpu_count()  # Number of parallel workers

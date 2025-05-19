from pathlib import Path
import argparse
import csv

def scan_files(directory, min_size_kb=0, extension="txt"):
    directory = Path(directory)
    if not directory.exists():
        print("Directory does not exist.")
        return

    files = list(directory.rglob(f"*.{extension}"))

    print(f"\nScanning: {directory.resolve()}")
    print(f"Found {len(files)} .{extension} files (filtered by --min-size {min_size_kb} KB):\n")

    print(f"{'File':<40} {'Size (KB)':>10}")
    print("-" * 52)

    total_size = 0
    file_count = 0

    with open("output.csv", "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["file", "size_kb"])

        for file in files:
            size_kb = file.stat().st_size / 1024
            if size_kb < min_size_kb:
                continue
            total_size += size_kb
            file_count += 1
            relative_path = str(file.relative_to(directory))
            print(f"{relative_path:<40} {size_kb:>10.1f}")
            writer.writerow([relative_path, round(size_kb, 1)])

    print("-" * 52)
    print(f"Included files: {file_count}, Total size: {total_size:.1f} KB")
    print("Results written to output.csv\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Recursively scan directory for files by extension.")
    parser.add_argument("path", help="Path to directory to scan")
    parser.add_argument("--min-size", type=float, default=0, help="Minimum file size in KB to include")
    parser.add_argument("--ext", type=str, default="txt", help="File extension to scan for (default: txt)")
    args = parser.parse_args()

    scan_files(args.path, args.min_size, args.ext)

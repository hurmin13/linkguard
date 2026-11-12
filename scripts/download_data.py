"""Download the original UCI dataset without visiting any dataset URL."""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import tempfile
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_URL = "https://archive.ics.uci.edu/static/public/967/phiusiil%2Bphishing%2Burl%2Bdataset.zip"
DATASET_PAGE = "https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset"
CSV_NAME = "PhiUSIIL_Phishing_URL_Dataset.csv"
MAX_DOWNLOAD_BYTES = 100 * 1024 * 1024
MAX_CSV_BYTES = 150 * 1024 * 1024


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download_dataset(destination: Path, *, force: bool = False) -> Path:
    destination = Path(destination).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    csv_path = destination / CSV_NAME
    metadata_path = destination / "source_metadata.json"
    if csv_path.exists() and not force:
        if metadata_path.exists():
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            if metadata.get("csv_sha256") == sha256_file(csv_path):
                print(f"Verified existing dataset: {csv_path}", flush=True)
                return csv_path
        raise ValueError("Existing dataset has no matching checksum metadata; use --force to download it again.")

    request = urllib.request.Request(SOURCE_URL, headers={"User-Agent": "LinkGuard-academic/1.0"})
    with tempfile.TemporaryDirectory(prefix=".linkguard-data-", dir=destination) as temporary:
        archive = Path(temporary) / "dataset.zip"
        downloaded_bytes = 0
        with urllib.request.urlopen(request, timeout=120) as response, archive.open("wb") as output:
            if urllib.parse.urlparse(response.url).hostname != "archive.ics.uci.edu":
                raise ValueError("Unexpected dataset download destination")
            for chunk in iter(lambda: response.read(1024 * 1024), b""):
                downloaded_bytes += len(chunk)
                if downloaded_bytes > MAX_DOWNLOAD_BYTES:
                    raise ValueError("Dataset download exceeded the size limit")
                output.write(chunk)
        with zipfile.ZipFile(archive) as bundle:
            # Read one exact filename; never extract paths supplied by an archive.
            matches = [info for info in bundle.infolist() if info.filename == CSV_NAME]
            if len(matches) != 1 or matches[0].is_dir() or matches[0].file_size > MAX_CSV_BYTES:
                raise ValueError("Archive did not contain the expected bounded CSV")
            staged = Path(temporary) / CSV_NAME
            with bundle.open(matches[0]) as source, staged.open("wb") as output:
                shutil.copyfileobj(source, output)
            csv_digest = sha256_file(staged)
            staged.replace(csv_path)
        metadata = {
            "dataset": "UCI PhiUSIIL Phishing URL (Website)",
            "source_url": SOURCE_URL,
            "dataset_page": DATASET_PAGE,
            "license": "CC BY 4.0",
            "downloaded_at_utc": datetime.now(timezone.utc).isoformat(),
            "archive_sha256": sha256_file(archive),
            "csv_sha256": csv_digest,
            "csv_filename": CSV_NAME,
            "archive_size_bytes": downloaded_bytes,
            "csv_size_bytes": csv_path.stat().st_size,
        }
        metadata_path.write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Downloaded and checksummed dataset: {csv_path}", flush=True)
    return csv_path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "data" / "raw")
    parser.add_argument("--force", action="store_true", help="Replace an existing local download")
    args = parser.parse_args()
    download_dataset(args.output_dir, force=args.force)


if __name__ == "__main__":
    main()

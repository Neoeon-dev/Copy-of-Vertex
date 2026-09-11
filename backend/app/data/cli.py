"""
Command-Line Interface for the VERTEX Dataset Pipeline.
Usage:
    python -m app.data.cli [all|acquire|extract|preprocess|deduplicate|split|report|verify]
"""
import argparse
from pathlib import Path
import sys
import json

from app.data.pipeline import VertexDataPipeline
from app.data.checksum import verify_manifest_checksums


def main():
    parser = argparse.ArgumentParser(
        description="VERTEX Phase C Dataset Pipeline & Integrity CLI"
    )
    parser.add_argument(
        "action",
        choices=["all", "acquire", "extract", "run", "verify", "status"],
        help="Pipeline action to execute",
    )
    parser.add_argument(
        "--data-dir",
        default=str(Path(__file__).resolve().parent.parent.parent.parent / "data"),
        help="Path to the data directory (default: project_root/data)",
    )

    args = parser.parse_args()
    data_root = Path(args.data_dir).resolve()
    print(f"[*] Target data root: {data_root}")

    pipeline = VertexDataPipeline(data_root)

    if args.action in ("all", "run"):
        pipeline.run()
    elif args.action == "acquire":
        pipeline.step_acquire()
    elif args.action == "extract":
        pipeline.step_extract_archives()
    elif args.action == "verify":
        manifest_p = data_root / "manifests" / "checksums.json"
        if not manifest_p.exists():
            print(f"[!] Checksum manifest not found at {manifest_p}. Run 'all' first.")
            sys.exit(1)
        valid, mismatches = verify_manifest_checksums(manifest_p, base_dir=data_root)
        if valid:
            print("[+] All checksums verified successfully against manifest!")
        else:
            print(f"[-] Checksum verification failed with {len(mismatches)} issues:")
            for m in mismatches:
                print(f"    {m}")
            sys.exit(1)
    elif args.action == "status":
        manifest_p = data_root / "manifests" / "dataset_manifest.json"
        if manifest_p.exists():
            with open(manifest_p, "r") as f:
                data = json.load(f)
            print(f"Manifest version: {data.get('manifest_version')}")
            print(f"Created: {data.get('created_at')}")
            print(f"Datasets: {list(data.get('datasets', {}).keys())}")
        else:
            print("No manifest found.")


if __name__ == "__main__":
    main()

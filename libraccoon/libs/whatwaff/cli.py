import argparse
import asyncio
import json
from whatwaff import WAFDetector

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Async WAF detection tool (WhatWAF style)"
    )
    parser.add_argument(
        "-u", "--url", required=True, help="Target URL (https://example.com)"
    )
    parser.add_argument(
        "--json", action="store_true", help="Output JSON"
    )
    return parser.parse_args()


async def main() -> None:
    args = parse_args()
    detector = WAFDetector(args.url)
    result = await detector.detect()

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"URL: {result['url']}")
        print(f"Status: {result['status_code']}")
        print(f"WAF detected: {result['detected']}")
        if result["wafs"]:
            print("WAFs:")
            for waf in result["wafs"]:
                print(f"  - {waf}")


if __name__ == "__main__":
    asyncio.run(main())

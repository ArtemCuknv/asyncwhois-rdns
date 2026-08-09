"""Run a WHOIS lookup through a SOCKS proxy with configurable DNS resolution.

Examples:
    python examples/proxy-rdns.py example.com socks5://127.0.0.1:9050 --rdns remote
    python examples/proxy-rdns.py example.com socks5://127.0.0.1:9050 --rdns local
    python examples/proxy-rdns.py example.com socks5://127.0.0.1:9050 --rdns remote --async-mode
    python examples/proxy-rdns.py example.com socks5://127.0.0.1:9050 --rdns remote --reusable-client
"""

import argparse
import asyncio

import asyncwhois


def sync_lookup(domain: str, proxy_url: str, rdns: bool) -> None:
    query_string, parsed_dict = asyncwhois.whois(
        domain,
        proxy_url=proxy_url,
        rdns=rdns,
    )
    print(query_string)
    print(parsed_dict)


async def async_lookup(domain: str, proxy_url: str, rdns: bool) -> None:
    query_string, parsed_dict = await asyncwhois.aio_whois(
        domain,
        proxy_url=proxy_url,
        rdns=rdns,
    )
    print(query_string)
    print(parsed_dict)


def reusable_client_lookup(domain: str, proxy_url: str, rdns: bool) -> None:
    client = asyncwhois.DomainClient(
        proxy_url=proxy_url,
        rdns=rdns,
    )
    query_string, parsed_dict = client.whois(domain)
    print(query_string)
    print(parsed_dict)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("domain")
    parser.add_argument("proxy_url", help="For example: socks5://127.0.0.1:9050")
    parser.add_argument(
        "--rdns",
        choices=("remote", "local"),
        default="remote",
        help="Resolve WHOIS server names remotely through the proxy or locally",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--async-mode", action="store_true")
    mode.add_argument("--reusable-client", action="store_true")
    args = parser.parse_args()

    rdns = args.rdns == "remote"
    print(f"proxy_url={args.proxy_url}, rdns={rdns} ({args.rdns} DNS)")

    if args.async_mode:
        asyncio.run(async_lookup(args.domain, args.proxy_url, rdns))
    elif args.reusable_client:
        reusable_client_lookup(args.domain, args.proxy_url, rdns)
    else:
        sync_lookup(args.domain, args.proxy_url, rdns)


if __name__ == "__main__":
    main()

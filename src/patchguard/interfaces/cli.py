import argparse
import sys

from patchguard.detection.prompt import PromptDetactor
from patchguard.detection.registry import DectactorRegistry
from patchguard.detection.sql import SQLDetector
from patchguard.domain.models import RequestPayLoad
from patchguard.domain.policy import get_default_policy

def main()-> None:
    """Main entry point for the CLI."""

    praser=argparse.ArgumentParser(description="PatchGuard CLI -- A tool for detecting and preventing security threats in web applications.")

    subparsers=praser.add_subparsers(dest="command",help="Available commands")
    scan_parser=subparsers.add_parser("scan",help="Scan a raw payload string for potential threats.")
    
    
    scan_parser.add_argument("--payload",type=str,required=True,help="Payload string to inspect")

    subparsers.add_parser("policy",help="Display default security policy configuration.")

    args=praser.parse_args()

    if args.command=="scan":
        registry=DectactorRegistry()
        registry.register(SQLDetector())
        registry.register(PromptDetactor())

        payload=RequestPayLoad(
            meathod="GET",
            path="/cli-scan",
            headers={},
            query_params={"input": args.payload},
            body=args.payload,
            client_ip="127.0.0.1",
        )

        event=registry.evaluate(payload)
        if event:
            print("🚨 [THREAT DETECTED]") 
            print(f" Threat Type: {event.threat_type.value}") 
            print(f" Rule ID: {event.rule_id}") 
            print(f" Snippet: {event.payload_snippet}") 
            sys.exit(1)

        else:
            print("✅ No threats detected.")
            sys.exit(0)

    elif args.command=="policy":

        policy=get_default_policy()

        print("🛡️ PatchGuard Default Security Policy:") 
        print(f" Policy ID: {policy.policy_id}") 
        print(f" Block Mode: {policy.block_mode}") 
        print(f" Max Latency: {policy.max_latency_ms}ms") 
        print(f" Active Detectors: {[t.value for t in policy.enabled_detectors]}")


    else:
        praser.print_help()


if __name__=="__main__":
    main()
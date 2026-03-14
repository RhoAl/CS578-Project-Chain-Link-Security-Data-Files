# Authors:
# Yu-Siang Chou - ONID: 934-366-906
# Richard Mwaiwo Ngeti - ONID - 934-556-320
# Alexander Yang Rhoads - ONID: 932-534-551

# Class: CS 578 Cybersecurity
# Project: Chain Link Security: Trends in Simultaneous HTTPS, ECH, and DNSSEC Use

# Program Description:
# This is a proof of concept program for retrieving domains listed
# in a Tranco list using the dnspython toolkit. Essentially this is 
# to teach us how to use the library, as well as to check if we need to use 
# additional tools to retrieve our target data. It will use a super-small
# 500 domain list, instead of the larger 10,000 one we'll use in the 
# study proper. The list is the top 500 domains from 20 January 2026 to 18 February 2026.

# Source for reading HTTPS records: https://kb.isc.org/docs/svcb-and-https-resource-records-what-are-they

# Potential example code:
# DNSPython GitHub: https://github.com/rthalley/dnspython/tree/main
# GitHub of the prior HTTPS study: https://github.com/yzzhn/imc2024dnshttps
# GitHub of the Tranco data pipline for the same study: https://github.com/yzzhn/dnsstudy/tree/main

# Things we're looking to retrieve:
# -Adoption rates of HTTPS by itself (find resource records)
# -Adoption rates of HTTPS + ECH
# -Adoption rates of HTTPS + DNSSEC
# -Adoption rates of HTTPS + ECH + DNSSEC
# -Usage of parameter SvcPriority (0 = AliasMode, 1 or 2 = ServiceMode)
# -Usage of parameter ALPN
# -Usage of parameter ipv4hint
# -Usage of parameter ipv6hint
# -Usage of HTTPS RR Default vs Dynamic Config



import pandas as pd 
import json
from typing import Literal
import numpy as np
import dns.name
import dns.resolver
import dns.dnssec
import dns.message
import dns.query
import dns.flags
import dns.rdatatype
import os
import datetime
import csv
import requests
from contextlib import ExitStack
import socket
import ssl


TRANCO_TEST_PATH = "tranco_test.csv" # File name for the tranco list
TRANCO_FILEPATH = "tranco_year.csv"  # 10,000 domain list for the range of 01/01/2025 - 01/01/2026

# 10,000 domain monthly tranco lists of the year 2025
TRANCO_JAN = "./Monthly_CSV/01-Jan/tranco_jan.csv"
TRANCO_FEB = "./Monthly_CSV/02-Feb/tranco_feb.csv"
TRANCO_MAR = "./Monthly_CSV/03-Mar/tranco_mar.csv"
TRANCO_APRIL = "./Monthly_CSV/04-April/tranco_april.csv"
TRANCO_MAY = "./Monthly_CSV/05-May/tranco_may.csv"
TRANCO_JUNE = "./Monthly_CSV/06-June/tranco_june.csv"
TRANCO_JULY = "./Monthly_CSV/07-July/tranco_july.csv"
TRANCO_AUG = "./Monthly_CSV/08-Aug/tranco_aug.csv"
TRANCO_SEP = "./Monthly_CSV/09-Sep/tranco_sep.csv"
TRANCO_OCT = "./Monthly_CSV/10-Oct/tranco_oct.csv"
TRANCO_NOV = "./Monthly_CSV/11-Nov/tranco_nov.csv"
TRANCO_DEC = "./Monthly_CSV/12-Dec/tranco_dec.csv"

#Will run queries in three list chunks, just to reduce potential for incomplete data
# Should have set up a contingency for
# Which domain count to use
TEST_DOMAIN_COUNT = 500 #Isn't attatched to anything yet
DOMAIN_COUNT = 10000  #Number of domains in the tranco list
# DOMAIN_COUNT = 500 #Number of domains in the test list
TEST_BOOL = False    # Just determines if we're running a test with the 500 domain list or not
YEAR_BOOL = True   # Determines if we extract the yearly 10,000 domain list
JAN_MAR = False
APRIL_JUNE = False
JULY_SEP = False
OCT_DEC = False

PICK_MONTH_BOOL = False
PICK_MONTH = "" #Just extracting a specific month;

SPLIT_RECORDS_BOOL = True # Bool to decide if we split the HTTPS RR records into seperate files for each type of data extracted (ECH, DNSSEC, etc.)

# EXTERNAL_FILE_MODE = False  # Bool to decide if functions write to external files; for testing (might end up with a ton of files if always on) 
# Seems like external file mode is always on; we probably don't need to make this particularly modular
# We could just leave them as JSON files

#Yearly list is top 10,000 domains of 01/01/2025 to 12/31/2025

#TODO: Figure out a way to deal with domains with identical destinations, or if we even want to do anything about it (Forget it)
#TODO: Analyze results
#TODO: Compare values to existing work (DNSSEC is the big difference in data, which they talk about on page 9 of Dong et al.) 
#Blog discussing it from 2025: https://netlas.io/blog/what_is_dnssec/#:~:text=DNSSEC%20does%20not%20protect%20against,responses%20by%20removing%20DNSSEC%20configuration
#TODO: Pull an additional analysis method out of a hat
#TODO: Actually figure out what what to do during timeouts, if we, uh, have time




# Did a bunch of compliance printing
# That might actually cause some performance issues


# Example code for counting csv rows
# def count_csv_rows(filename):
#     with open(filename, 'r', newline='', encoding='utf-8') as file:
#         reader = csv.reader(file)
#         # Count all rows (including header)
#         row_count = sum(1 for row in reader)
#         return row_count

# # Example usage:
# file_path = 'your_file.csv'
# total_rows = count_csv_rows(file_path)
# print(f"Total number of rows: {total_rows}")

# used to extract the list for specific months
def switch_month(month):
    switcher = {
        "jan": TRANCO_JAN,
        "feb": TRANCO_FEB,
        "mar": TRANCO_MAR,
        "april": TRANCO_APRIL,
        "may": TRANCO_MAY,
        "june": TRANCO_JUNE,
        "july": TRANCO_JULY,
        "aug": TRANCO_AUG,
        "sep": TRANCO_SEP,
        "oct": TRANCO_OCT,
        "nov": TRANCO_NOV,
        "dec": TRANCO_DEC
    }
    return switcher.get(month.lower(), None)

# Extract the output paths of specific months
def switch_month_output(month):
    switcher = {
        "jan": ("output/jan/jan_rr_records.jsonl", "output/jan/jan_summary.jsonl"),
        "feb": ("output/feb/feb_rr_records.jsonl", "output/feb/feb_summary.jsonl"),
        "mar": ("output/mar/mar_rr_records.jsonl", "output/mar/mar_summary.jsonl"),
        "april": ("output/april/april_rr_records.jsonl", "output/april/april_summary.jsonl"),
        "may": ("output/may/may_rr_records.jsonl", "output/may/may_summary.jsonl"),
        "june": ("output/june/june_rr_records.jsonl", "output/june/june_summary.jsonl"),
        "july": ("output/july/july_rr_records.jsonl", "output/july/july_summary.jsonl"),
        "aug": ("output/aug/aug_rr_records.jsonl", "output/aug/aug_summary.jsonl"),
        "sep": ("output/sep/sep_rr_records.jsonl", "output/sep/sep_summary.jsonl"),
        "oct": ("output/oct/oct_rr_records.jsonl", "output/oct/oct_summary.jsonl"),
        "nov": ("output/nov/nov_rr_records.jsonl", "output/nov/nov_summary.jsonl"),
        "dec": ("output/dec/dec_rr_records.jsonl", "output/dec/dec_summary.jsonl")
    }
    return switcher.get(month.lower(), (None, None))

# Grab the domains from the tranco list
def grab_list_domain(filepath):
    # answer_list = [0,0,0,0]    #Will order data like this: [HTTPS RR number, ECH number, DNSSEC number]
    domains = []

    with open(filepath, "r", encoding="utf-8") as file:
        reader = csv.reader(file)

        for i, row in enumerate(reader):
            # rank = row[0] #Rank of domain in terms of popularity
            domain = row[1]
            
            domains.append(domain.strip())

    return domains



# Try to grab the raw HTTPS Resource record
# Hopefully write to some sort of external file too
def raw_https_rr(domains) :
    # For right now let's just trying outputting the data we get from a query
    try:
        HTTPS_List = dns.resolver.resolve(domains, "HTTPS")

        for rdata in HTTPS_List: 
            print(f"RDATA: {rdata}")
            print(f"Priority: {rdata.priority}")
            print(f"Target: {rdata.target}")
            print(f"Params: {rdata.params}")

        # When we have a better idea of what we're returning, let's try to return the actual data
        return True
    except (dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.exception.Timeout):
        return False

def extract_https_rr_records(HTTPS_List):
    records = []
    for rdata in HTTPS_List:
        records.append({
            "rdata_text": rdata.to_text(),
            "priority": int(getattr(rdata, "priority", 0) or 0),
            "target": str(getattr(rdata, "target", "")),
        })
    return records


# Check the domains with HTTPS + ech support
# In order to reduce the number of redundant domain requests, this will be called within https_check
def ech_check(HTTPS_List):
    ech_bool = False   # Count of domains with ech support
    inc = 0 #For loop incrementor
    # ech_count = True

    for rdata in HTTPS_List:
            if 'ech=' in rdata.to_text():
                # ech_count += 1  # this should probably just be ech_bool = 1, since the function's only gonna be used on 1 domain at a time
                ech_bool = True
    
    return ech_bool



# When checking for DNSSEC via the AD flag instead of just RRSIG, it seems you need a dedicated DNSSEC-validating resolver, like Cloudflare
def dnssec_check(domain):
    try:
        resolver = dns.resolver.Resolver()

        # Apperently a DNSSEC-validating resolver to prevent the local ISP stripping info
        resolver.nameservers = ['1.1.1.1', '8.8.8.8'] 

        request = dns.message.make_query(domain, dns.rdatatype.A, want_dnssec=True)
        
        #response = dns.query.udp(request, resolver.nameservers[0], timeout=3)
        response = dns.query.udp(request, resolver.nameservers[0])  # Trying a version without timeout

        # Actually checking for  the AD Flag and the RRSIG record

        # Doing the bit to check for the AD flag
        if response.flags & dns.flags.AD:
            return True

        # RRSIG check
        for rrset in response.answer:
            if rrset.rdtype == dns.rdatatype.RRSIG:
                return True

        return False

    except Exception as e:
        # It's usually good practice to log 'e' during testing so bugs don't hide
        # print(f"DNSSEC Error for {domain}: {e}") 
        return False
    

# Get the parameter data
# SvcPriority (0 = AliasMode, 1 or 2 = ServiceMode)
# ALPN
# ipv4hint
# ipv6hint
# HTTPS RR Default vs Dynamic Config
# Return types should be covered here: https://dnspython.readthedocs.io/en/2.7/rdata-subclasses.html
def param_check(HTTPS_List):
    # Status of parameters SvcPriority, ALPN, ipv4hint, ipv6hint, HTTPS RR Default vs Dynamic Config]

    mode = None #SvcPriority mode
    alpn = False
    ipv4hint = False
    ipv6hint = False
    dynamic_config = False

    # Change how we get SvcPriority mode
    priority_num = 0    # SVCPriority Value; replaces param_list

    #Maybe make this a switch statement
    for rdata in HTTPS_List:
        if rdata.priority:
            priority_num = int(rdata.priority)

        # I think I doing this part wrong, so let's go with the old method
        # if priority_num == 0:
        #     mode = "Alias"
        # elif priority_num > 0 and priority_num <= 2:
        #     mode = "Service"
        # else:
        #     mode = "Invalid"    #Kind of an error catch

        if priority_num == 0:
            mode = "Alias"
        else:
            mode = "Service"


        params = getattr(rdata, "params", None)
        if len(params) > 0:
            dynamic_config = True
            for k in params.items():
                key = str(k).lower()
                if "alpn" in key:
                    alpn = True
                elif "ipv4hint" in key:
                    ipv4hint = True
                elif "ipv6hint" in key:
                    ipv6hint = True

    return {
        "mode": mode,
        "alpn": alpn,
        "ipv4hint": ipv4hint,
        "ipv6hint": ipv6hint,
        "dynamic_config": dynamic_config,
    }


# Check raw TLS connectivity to see if a domain is using HTTPS
def check_tls_connection(domain, port=443, timeout=5.0):
    targets = [domain, f"www.{domain}"]
    
    for target in targets:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE 

        try:
            with socket.create_connection((target, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    # return True, target
                    return True
        except (socket.timeout, ConnectionRefusedError, socket.gaierror, ssl.SSLError, OSError):
            continue 
        # We either try the next target subdomains or fail
            
    # return False, None
    return False


# Helper function for http_check (gets RR, not HTTPS!!!) to try both the apex domain and the www. subdomain, with retries for failures
def get_https_answers(domain, retries=4):
    # Expanded resolver list to prevent rate limiting
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8', '1.1.1.1', '9.9.9.9', '208.67.222.222'] 
    resolver.lifetime = 5.0 # Timeout
    
    targets = [domain, f"www.{domain}"]
    
    for target in targets:
        for attempt in range(retries):
            try:
                # UDP
                HTTPS_List = resolver.resolve(target, "HTTPS")
                if HTTPS_List:
                    return HTTPS_List, target 
                    
            except dns.resolver.NoAnswer:
                break 
            except dns.resolver.NXDOMAIN:
                break 
            except (dns.exception.Timeout, dns.resolver.NoNameservers):
                # Timeout, so retrty
                if attempt < retries - 1:
                    continue
                else:
                    break # Hit max, so quit
                    
    return None, None



# Modifying, so I'm keep the old one here like this as backup
def old_https_check(domains) :
    try:
        HTTPS_List = dns.resolver.resolve(domains, "HTTPS") 
        ech_bool = ech_check(HTTPS_List)
        
        # Passing the domains string seems to fix the undercounting
        dnssec_bool = dnssec_check(domains) 
        
        params = param_check(HTTPS_List)
        records = extract_https_rr_records(HTTPS_List)

        return len(HTTPS_List) > 0, ech_bool, dnssec_bool, params, records

    except(dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.exception.Timeout):
        return False, False, False, {}, []
    

# Modifying, so I'm also keeping the other old one here like this as backup
def old_https_check2(domains) :
    # Might be a resolver issue causing the undercount
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['1.1.1.1', '8.8.8.8']

    # The idea is to to try UDP first, then move to TCP if that fails
    # Some domains may block UDP quries
    for transport in ['UDP', 'TCP']:
        try:
            if transport == 'UDP':
                HTTPS_List = resolver.resolve(domains, "HTTPS")
            else:
                # Try to force a TCP query

                request = dns.message.make_query(domains, dns.rdatatype.HTTPS)
                #response = dns.query.tcp(request, resolver.nameservers[0], timeout=5)
                response = dns.query.tcp(request, resolver.nameservers[0])  # Trying a version without timeout

                # HTTPS_List = response.answer 
                # In the event of a TCP query, the response is a raw DNS message, so we'll need to parse it to get rdata
                # Unpack the RRsets from the raw message into a list of Rdata objects
                HTTPS_List = []
                for rrset in response.answer:
                    if rrset.rdtype == dns.rdatatype.HTTPS:
                        HTTPS_List.extend([rdata for rdata in rrset])

            # If response successful
            if HTTPS_List:
                ech_bool = ech_check(HTTPS_List)
                dnssec_bool = dnssec_check(domains)
                params = param_check(HTTPS_List)
                records = extract_https_rr_records(HTTPS_List)
                return True, ech_bool, dnssec_bool, params, records

        except(dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.exception.Timeout):
            continue 
    
    # When both UDP and TCP fail
    return False, False, False, {}, []


# Let's try one more time
def https_check(domain):
    HTTPS_List, successful_target = get_https_answers(domain)
    HTTPS_usage = check_tls_connection(domain)
    
    if HTTPS_List:
        #check_tls_connection(domain)

        ech_bool = ech_check(HTTPS_List)
        dnssec_bool = dnssec_check(successful_target) 
        
        params = param_check(HTTPS_List)
        records = extract_https_rr_records(HTTPS_List)
        
        return HTTPS_usage, True, ech_bool, dnssec_bool, params, records

    return HTTPS_usage, False, False, False, {}, []



# Share among domains
def share(x): 
    return (x / DOMAIN_COUNT) * 100



# Taking the output from the main output, and putting it in a function
def output_list(records_path, summary_path, list_of_domains):
    # TODO: figure out the parameters
    HTTPS_count = 0   # Domains with HTTPS usage
    HTTPS_RR_Count = 0 # Domains with HTTPS RR
    ech_count = 0   # Domains with HTTPS + ECH
    https_dnssec_count = 0  # Domains with HTTPS RR + DNSSEC
    https_ech_dnssec_count = 0  # Domains with HTTPS RR + ECH + DNSSEC
    aliasmode_count = 0
    servicemode_count = 0
    alpn_count = 0
    ipv4hint_count = 0
    ipv6hint_count = 0
    dynamic_config_count = 0
    count = 0

    # os.makedirs(records_path, exist_ok=True)
    os.makedirs(os.path.dirname(records_path), exist_ok=True)

    with open(records_path, "w", encoding="utf-8") as rec_f:
        for domain in list_of_domains:
            # Checking progress if we have to rerecord data
            count += 1
            print(f"Recording record {count}")

            HTTPS_use, HTTPS_Ans, ech_ans, dnssec_ans, params, records = https_check(domain)

            if HTTPS_use == True:
                HTTPS_count += 1
            if HTTPS_Ans == True :
                HTTPS_RR_Count += 1
                if dnssec_ans == True:
                    https_dnssec_count += 1
            if ech_ans == True:
                ech_count += 1
            if HTTPS_Ans and ech_ans and dnssec_ans:
                https_ech_dnssec_count += 1

            mode = params.get("mode")
            if mode == "Alias":
                aliasmode_count += 1
            elif mode == "Service":
                servicemode_count += 1

            alpn = params.get("alpn") or []
            ipv4hint = params.get("ipv4hint") or []
            ipv6hint = params.get("ipv6hint") or []
            if alpn:
                alpn_count += 1
            if ipv4hint:
                ipv4hint_count += 1
            if ipv6hint:
                ipv6hint_count += 1
            dynamic_config = bool(params.get("dynamic_config", False))
            if dynamic_config:
                dynamic_config_count += 1
            
            row = {
                "domain": domain,
                "https_usage": HTTPS_use,
                "has_https_rr": HTTPS_Ans,
                "rr_count": len(records),
                "ech_present": ech_ans,
                "dnssec_present": dnssec_ans,
                "param_flags": params,
                "records": records,
            }
            rec_f.write(json.dumps(row, ensure_ascii=False) + "\n")

            print(f"Record {count} recorded")   # Finished iteration

        # raw_https_rr(domain)  # Output raw data

    print("Records retrieved")

    summary = {
        "domain_count": DOMAIN_COUNT,

        "counts": {
            "https_usage_count": HTTPS_count,
            "https_RR_count": HTTPS_RR_Count,
            "https_ech_count": ech_count,
            "https_dnssec_count": https_dnssec_count,
            "https_ech_dnssec_count": https_ech_dnssec_count,
            "aliasmode_count": aliasmode_count,
            "servicemode_count": servicemode_count,
            "alpn_count": alpn_count,
            "ipv4hint_count": ipv4hint_count,
            "ipv6hint_count": ipv6hint_count,
            "dynamic_config_count": dynamic_config_count,
        },
        "shares_percent (%)": {
            "https_usage_share": share(HTTPS_count),
            "https_RR_share": share(HTTPS_RR_Count),
            "https_ech_share": share(ech_count),
            "https_dnssec_share": share(https_dnssec_count),
            "https_ech_dnssec_share": share(https_ech_dnssec_count),
            "aliasmode_share": share(aliasmode_count),
            "servicemode_share": share(servicemode_count),
            "alpn_share": share(alpn_count),
            "ipv4hint_share": share(ipv4hint_count),
            "ipv6hint_share": share(ipv6hint_count),
            "dynamic_config_share": share(dynamic_config_count),
        },
    }

    with open(summary_path, "w", encoding="utf-8") as sum_f:
        json.dump(summary, sum_f, indent=2, ensure_ascii=False)

    print(f"Wrote per-domain records to: {records_path}")
    print(f"Wrote summary metrics to:    {summary_path}")


# Split the records into seperate files for each type of data extracted (ECH, DNSSEC, etc.)
def split_records(input_jsonl_path):
    base_dir = os.path.dirname(input_jsonl_path)
    output_dir = os.path.join(base_dir, "split_records")
    os.makedirs(output_dir, exist_ok=True)

    # Define the mapping of criteria to filenames
    criteria_map = {
        "https_usage": "https_usage.jsonl",
        "has_https_rr": "has_https_rr.jsonl",
        "https_ech": "https_ech.jsonl",
        "https_dnssec": "https_dnssec.jsonl",
        "https_ech_dnssec_all": "https_ech_dnssec_all.jsonl",
        "mode_service": "mode_service.jsonl",
        "mode_alias": "mode_alias.jsonl",
        "alpn": "alpn.jsonl",
        "ipv4hint": "ipv4hint.jsonl",
        "ipv6hint": "ipv6hint.jsonl",
        "dynamic_config": "dynamic_config.jsonl"
    }

    print(f"Reading from: {input_jsonl_path}")
    print(f"Writing split files to: {output_dir}")

    with ExitStack() as stack:
        handles = {
            key: stack.enter_context(open(os.path.join(output_dir, fname), "w", encoding="utf-8"))
            for key, fname in criteria_map.items()
        }

        with open(input_jsonl_path, "r", encoding="utf-8") as f_in:
            for line in f_in:
                if not line.strip():
                    continue
                
                data = json.loads(line)
                params = data.get("param_flags", {})
                
                # Logic for splitting
                https_usage = data.get("https_usage", False)
                has_https_rr = data.get("has_https_rr", False)
                has_ech = data.get("ech_present", False)
                has_dnssec = data.get("dnssec_present", False)
                
                if https_usage:
                    handles["https_usage"].write(line)

                if has_https_rr:
                    handles["has_https_rr"].write(line)
                    if has_ech:
                        handles["https_ech"].write(line)
                    if has_dnssec:
                        handles["https_dnssec"].write(line)
                    if has_ech and has_dnssec:
                        handles["https_ech_dnssec_all"].write(line)

                # 2. Modes (Service vs Alias)
                mode = params.get("mode")
                if mode == "Service":
                    handles["mode_service"].write(line)
                elif mode == "Alias":
                    handles["mode_alias"].write(line)

                # 3. Param Flags
                if params.get("alpn"):
                    handles["alpn"].write(line)
                if params.get("ipv4hint"):
                    handles["ipv4hint"].write(line)
                if params.get("ipv6hint"):
                    handles["ipv6hint"].write(line)
                if params.get("dynamic_config"):
                    handles["dynamic_config"].write(line)

    print("Extraction complete.")

# Usage Example:
# split_records_by_criteria("output/https_rr_records.jsonl")


def main() :
    # We could prob make some sort of a switch statement / enum / bool thing to reduce the number of items declared all at once
    # I still intensely feel embaressed by all these declarations
    # Oh well! Time limit! 
    # list_of_domains = grab_list_domain(TRANCO_FILEPATH)
    # list_test = grab_list_domain(TRANCO_TEST_PATH)

    # os.makedirs("output", exist_ok=True)

    #Can't conditionally declare the record paths anymore if I want to make records split work :(
    records_path = f"output/https_rr_records.jsonl"
    jan_path = f"output/jan/jan_rr_records.jsonl"
    feb_path = f"output/feb/feb_rr_records.jsonl"
    mar_path = f"output/mar/mar_rr_records.jsonl"
    april_path = f"output/april/april_rr_records.jsonl"
    may_path = f"output/may/may_rr_records.jsonl"
    june_path = f"output/june/june_rr_records.jsonl"
    july_path = f"output/july/july_rr_records.jsonl"
    aug_path = f"output/aug/aug_rr_records.jsonl"
    sep_path = f"output/sep/sep_rr_records.jsonl"
    oct_path = f"output/oct/oct_rr_records.jsonl"
    nov_path = f"output/nov/nov_rr_records.jsonl"
    dec_path = f"output/dec/dec_rr_records.jsonl"
    test_path = f"output/test/test_rr_records.jsonl"


    #Running a set of bool checks (prob could just make a switch, note for next time)
    if (TEST_BOOL == False):
        if (YEAR_BOOL):
            list_of_domains = grab_list_domain(TRANCO_FILEPATH)

            records_path = f"output/https_rr_records.jsonl"
            summary_path  = f"output/summary.json"

            print("Retrieving Yearly Record...\n")
            output_list(records_path, summary_path, list_of_domains)

        if (JAN_MAR):
            list_jan = grab_list_domain(TRANCO_JAN)
            list_feb = grab_list_domain(TRANCO_FEB)
            list_mar = grab_list_domain(TRANCO_MAR)

            jan_path = f"output/jan/jan_rr_records.jsonl"
            jan_sum_path = f"output/jan/jan_summary.jsonl"
            feb_path = f"output/feb/feb_rr_records.jsonl"
            feb_sum_path = f"output/feb/feb_summary.jsonl"
            mar_path = f"output/mar/mar_rr_records.jsonl"
            mar_sum_path = f"output/mar/mar_summary.jsonl"

            print("Retrieving January Record...\n")
            output_list(jan_path, jan_sum_path, list_jan)

            print("Retrieving Feburary Record...\n")
            output_list(feb_path, feb_sum_path, list_feb)

            print("Retrieving March Record...\n")
            output_list(mar_path, mar_sum_path, list_mar)

        if(APRIL_JUNE):
            list_april = grab_list_domain(TRANCO_APRIL)
            list_may = grab_list_domain(TRANCO_MAY)
            list_june = grab_list_domain(TRANCO_JUNE)

            april_path = f"output/april/april_rr_records.jsonl"
            april_sum_path = f"output/april/april_summary.jsonl"
            may_path = f"output/may/may_rr_records.jsonl"
            may_sum_path = f"output/may/may_summary.jsonl"
            june_path = f"output/june/june_rr_records.jsonl"
            june_sum_path = f"output/june/june_summary.jsonl"

            print("Retrieving April Record...\n")
            output_list(april_path, april_sum_path, list_april)

            print("Retrieving May Record...\n")
            output_list(may_path, may_sum_path, list_may)

            print("Retrieving June Record...\n")
            output_list(june_path, june_sum_path, list_june)

        if(JULY_SEP):
            list_july = grab_list_domain(TRANCO_JULY)
            list_aug = grab_list_domain(TRANCO_AUG)
            list_sep = grab_list_domain(TRANCO_SEP)

            july_path = f"output/july/july_rr_records.jsonl"
            july_sum_path = f"output/july/july_summary.jsonl"
            aug_path = f"output/aug/aug_rr_records.jsonl"
            aug_sum_path = f"output/aug/aug_summary.jsonl"
            sep_path = f"output/sep/sep_rr_records.jsonl"
            sep_sum_path = f"output/sep/sep_summary.jsonl"

            print("Retrieving July Record...\n")
            output_list(july_path, july_sum_path, list_july)

            print("Retrieving August Record...\n")
            output_list(aug_path, aug_sum_path, list_aug)

            print("Retrieving September Record...\n")
            output_list(sep_path, sep_sum_path, list_sep)

        if(OCT_DEC):
            list_oct = grab_list_domain(TRANCO_OCT)
            list_nov = grab_list_domain(TRANCO_NOV)
            list_dec = grab_list_domain(TRANCO_DEC)

            oct_path = f"output/oct/oct_rr_records.jsonl"
            oct_sum_path = f"output/oct/oct_summary.jsonl"
            nov_path = f"output/nov/nov_rr_records.jsonl"
            nov_sum_path = f"output/nov/nov_summary.jsonl"
            dec_path = f"output/dec/dec_rr_records.jsonl"
            dec_sum_path = f"output/dec/dec_summary.jsonl"

            print("Retrieving October Record...\n")
            output_list(oct_path, oct_sum_path, list_oct)

            print("Retrieving November Record...\n")
            output_list(nov_path, nov_sum_path, list_nov)

            print("Retrieving December Record...\n")
            output_list(dec_path, dec_sum_path, list_dec)

        #Problem Children Section:
        if(PICK_MONTH_BOOL):
            list_month = grab_list_domain(switch_month(PICK_MONTH))
            if list_month is None:
                print(f"Invalid month selection: {PICK_MONTH}")
                return 1

            month_paths, month_sum_paths = switch_month_output(PICK_MONTH)
            if month_paths is None or month_sum_paths is None:
                print(f"Invalid month selection: {PICK_MONTH}")
                return 1
    


            print(f"Retrieving {PICK_MONTH} Record...\n")
            output_list(month_paths, month_sum_paths, list_month)

    else:
        list_test = grab_list_domain(TRANCO_TEST_PATH)
        test_path = f"output/test/test_rr_records.jsonl"
        test_sum_path = f"output/test/test_summary.jsonl"

        print("Retrieving Test Record...\n")
        output_list(test_path, test_sum_path, list_test)

    # Record splitting section
    if SPLIT_RECORDS_BOOL:
        split_records(test_path)
        split_records(records_path)
        split_records(jan_path)
        split_records(feb_path)
        split_records(mar_path)
        split_records(april_path)
        split_records(may_path)
        split_records(june_path)
        split_records(july_path)
        split_records(aug_path)
        split_records(sep_path)
        split_records(oct_path)
        split_records(nov_path)
        split_records(dec_path)


    return 0


if __name__ == "__main__":
    main()
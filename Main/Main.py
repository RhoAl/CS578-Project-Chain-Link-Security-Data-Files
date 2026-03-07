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
YEAR_BOOL = True # Determines if we extract the yearly 10,000 domain list
JUST_JAN = False #Just test January's list
JAN_MAR = True
APRIL_JUNE = False
JULY_SEP = False
OCT_DEC = False

# EXTERNAL_FILE_MODE = False  # Bool to decide if functions write to external files; for testing (might end up with a ton of files if always on) 
# Seems like external file mode is always on; we probably don't need to make this particularly modular
# We could just leave them as JSON files

#Yearly list is top 10,000 domains of 01/01/2025 to 12/31/2025

#TODO: Figure out a way to deal with domains with identical destinations, or if we even want to do anything about it (Forget it)
#TODO: Analyze results
#TODO: Compare values to existing work (DNSSEC is the big difference in data, which they talk about on page 9 of Dong et al.) 
#Blog discussing it from 2025: https://netlas.io/blog/what_is_dnssec/#:~:text=DNSSEC%20does%20not%20protect%20against,responses%20by%20removing%20DNSSEC%20configuration
#TODO: Pull an additional analysis method out of a hat
#TODO: Fix the DNSSEC retrieval method
#TODO: Reconfigure the output to retrieve from each csv list specified


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


#TODO: Fix our method for finding this
# When checking for DNSSEC via the AD flag instead of just RRSIG, it seems you need a dedicated DNSSEC-validating resolver, like Cloudflare
# This might take quite awhile. For right now, it's probably better to just check for the presesence of RRSIGs

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

# Check if a domain is using HTTPS protocol
# Returns the number of domains using HTTPS protocol
# def https_check(domains) :
#     try:
#         HTTPS_List = dns.resolver.resolve(domains, "HTTPS") # It's important to note that resolve returns a special memory object; I think you need to alter it to parse it
#         ech_bool = ech_check(HTTPS_List)
#         dnssec_bool = dnssec_check(HTTPS_List)
#         params = param_check(HTTPS_List)
#         records = extract_https_rr_records(HTTPS_List)

#         # print(HTTPS_List) #Test print of the response

#         return len(HTTPS_List) > 0, ech_bool, dnssec_bool, params, records

#     except(dns.resolver.NoAnswer,
#             dns.resolver.NXDOMAIN,
#             dns.resolver.NoNameservers,
#             dns.exception.Timeout):
#         return False, False, False, {}, []



def https_check(domains) :
    try:
        HTTPS_List = dns.resolver.resolve(domains, "HTTPS") 
        ech_bool = ech_check(HTTPS_List)
        
        # FIX: Pass the 'domains' string, not the 'HTTPS_List' answer object
        dnssec_bool = dnssec_check(domains) 
        
        params = param_check(HTTPS_List)
        records = extract_https_rr_records(HTTPS_List)

        return len(HTTPS_List) > 0, ech_bool, dnssec_bool, params, records

    except(dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.exception.Timeout):
        return False, False, False, {}, []



# Share among domains
def share(x): 
    return (x / DOMAIN_COUNT) * 100



# Taking the output from the main output, and putting it in a function
# TODO: actually finish these Functions
# TODO: Put them all in an external file and import them
def output_list(records_path, summary_path, list_of_domains):
    # TODO: figure out the parameters
    HTTPS_Count = 0 # Domains with HTTPS RR
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

            HTTPS_Ans, ech_ans, dnssec_ans, params, records = https_check(domain)

            if HTTPS_Ans == True :
                HTTPS_Count += 1
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
            "https_count": HTTPS_Count,
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
            "https_share": share(HTTPS_Count),
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



def main() :
    # We could prob make some sort of a switch statement / enum / bool thing to reduce the number of items declared all at once
    # I still intensely feel embaressed by all these declarations
    # Oh well! Time limit! 
    # list_of_domains = grab_list_domain(TRANCO_FILEPATH)
    # list_test = grab_list_domain(TRANCO_TEST_PATH)

    # os.makedirs("output", exist_ok=True)

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

    else:
        list_test = grab_list_domain(TRANCO_TEST_PATH)
        test_path = f"output/test/test_rr_records.jsonl"
        test_sum_path = f"output/test/test_summary.jsonl"

        print("Retrieving Test Record...\n")
        output_list(test_path, test_sum_path, list_test)

    #Sorta just testing the monthly retrieval here  
    if (JUST_JAN):
        list_jan = grab_list_domain(TRANCO_JAN)

        jan_path = f"output/jan/jan_rr_records.jsonl"
        jan_sum_path = f"output/jan/jan_summary.jsonl"

        print("Retrieving January Record...\n")
        output_list(jan_path, jan_sum_path, list_jan)

    

    return 0


if __name__ == "__main__":
    main()
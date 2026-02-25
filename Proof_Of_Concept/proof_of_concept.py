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


TRANCO_FILEPATH = "tranco_ZWZGG.csv" # File name for the tranco list
DOMAIN_COUNT = 500  #Number of domains in the tranco list
EXTERNAL_FILE_MODE = False  # Bool to decide if functions write to external files; for testing (might end up with a ton of files if always on) 

# The most performant way of doing this (not making a bunch of extra domain fetches) is to just
# get the json (or any kind of list) with the Domain protocol, then to parse it. That'll take some time to understand 
# the formatting, so in order to learn how to use DNSPython as fast as possible, I'll just be inefficient for now.

# The old study has a systamatized program that understands
# what part of the HTTPS field to get. It might make sense to
# reuse their code, so in the checkpoint meeting we can ask the 
# professor about the ethics of doing so with a citation,

#TODO: Figure out a way to deal with domains with identical destinations, or if we even want to do anything about it
#TODO: Figure out a way to request and parse the domains that have HTTPS + ECH + DNSSEC (should be easy with what we currently have)
#TODO: Finalize the way to write both the study calculations AND the retrieved data itself to external files (specifically the HTTPS protocols we're parsing, so we actually know what we're looking at) 
#TODO: Finalize our methodology for data collection (should we repeat the retrieves over a period of a week)

#TODO: Figure out a way to retrieve the following parameters:
# -Usage of parameter SvcPriority (0 = AliasMode, 1 or 2 = ServiceMode)
# -Usage of parameter ALPN
# -Usage of parameter ipv4hint
# -Usage of parameter ipv6hint
# -Usage of HTTPS RR Default vs Dynamic Config

#TODO: Make the inital calculations with parameters


# Grab the domains from the tranco list
def grab_list_domain() :
    # answer_list = [0,0,0,0]    #Will order data like this: [HTTPS RR number, ECH number, DNSSEC number]
    domains = []

    with open(TRANCO_FILEPATH, "r", encoding="utf-8") as file:
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
# This might take quite awhile. For right now, it's probably better to just check for the presesence of RRSIGs
def dnssec_check(HTTPS_List):
    dnssec_bool = False

    for rrset in HTTPS_List.response.answer:
        if rrset.rdtype == dns.rdatatype.RRSIG:
            dnssec_bool = True

    return dnssec_bool

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

    # -1 means nothing has been returned
    param_list = [-1, "-1", "-1", "-1", "-1"] # Strings in case I can't convey status with just numbers

    #Maybe make this a switch statement
    for rdata in HTTPS_List:
        if rdata.priority:
            param_list[0] = int(rdata.priority)

        if param_list[0] == 0:
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
def https_check(domains) :
    try:
        HTTPS_List = dns.resolver.resolve(domains, "HTTPS") # It's important to note that resolve returns a special memory object; I think you need to alter it to parse it
        ech_bool = ech_check(HTTPS_List)
        dnssec_bool = dnssec_check(HTTPS_List)
        params = param_check(HTTPS_List)

        # print(HTTPS_List) #Test print of the response

        return len(HTTPS_List) > 0, ech_bool, dnssec_bool, params

    except(dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.exception.Timeout):
        return False, False, False, {}

def main() :
    list_of_domains = grab_list_domain()
    HTTPS_Count = 0 # Domains with HTTPS RR
    ech_count = 0   # Domains with HTTPS + ECH
    https_dnssec_count = 0  # Domains with HTTPS RR + DNSSEC
    aliasmode_count = 0
    servicemode_count = 0
    alpn_count = 0
    ipv4hint_count = 0
    ipv6hint_count = 0
    dynamic_config_count = 0

    for domain in list_of_domains:
        HTTPS_Ans, ech_ans, dnssec_ans, params = https_check(domain)

        if HTTPS_Ans == True :
            HTTPS_Count += 1
            if dnssec_ans == True:
                https_dnssec_count += 1
        if ech_ans == True:
            ech_count += 1

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

        # raw_https_rr(domain)  # Output raw data

    # Share among domains
    # In the final version of the program
    # we'll want write this to an external file,
    # like an csv file, while also dating this.
    HTTPS_Share = (HTTPS_Count / DOMAIN_COUNT) * 100    # Percentage point with no rounding
    ech_share = (ech_count / DOMAIN_COUNT) * 100
    https_dnssec_share = (https_dnssec_count / DOMAIN_COUNT) * 100
    aliasmode_share = (aliasmode_count / DOMAIN_COUNT) * 100
    servicemode_share = (servicemode_count / DOMAIN_COUNT) * 100
    alpn_share = (alpn_count / DOMAIN_COUNT) * 100
    ipv4hint_share = (ipv4hint_count / DOMAIN_COUNT) * 100
    ipv6hint_share = (ipv6hint_count / DOMAIN_COUNT) * 100
    dynamic_config_share = (dynamic_config_count / DOMAIN_COUNT) * 100

    print(f"Share of HTTPS RR: {HTTPS_Share}%")
    print(f"Share of domains with HTTPS RR + ECH: {ech_share}%")
    print(f"Share of HTTPS RR + DNSSEC: {https_dnssec_share}%")

    print("\nParameter usage (among all domains):")
    print(f"Share of AliasMode: {aliasmode_share}%")
    print(f"Share of ServiceMode: {servicemode_share}%")
    print(f"Share of ALPN: {alpn_share}%")
    print(f"Share of ipv4hint: {ipv4hint_share}%")
    print(f"Share of ipv6hint: {ipv6hint_share:.1f}%")
    print(f"Share of Dynamic Config: {dynamic_config_share:.1f}%")

    #test prints
    #print(list_of_domains)
    #print(HTTPS_Count) # 51 domains with HTTPS RR
    #print(ech_count)
    #print(https_dnssec_count)

    return 0


if __name__ == "__main__":
    main()
# This is meant to carry all the output functions
# Until then, I'm going to code them in main - Alex

    
# Share among domains
def share(x): 
    return (x / DOMAIN_COUNT) * 100

# Helper function for writing the json files
def write_JSON():
    pass

# Taking the output from the main output, and putting it in a function
# TODO: actually finish these Functions
# TODO: Put them all in an external file and import them
def output_list(records_path, summary_path, list_of_domains):
    # TODO: figure out the parameters
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

# Make all the outputs at once
# Might be a bad idea
def murderers_row():
    pass

# A whole bunch of monthly list output functions
def output_jan_list():
    pass

def output_feb_list():
    pass

def output_mar_list():
    pass

def output_april_list():
    pass

def output_may_list():
    pass

def output_june_list():
    pass

def output_july_list():
    pass

def output_aug_list():
    pass

def output_sep_list():
    pass

def output_oct_list():
    pass

def output_nov_list():
    pass

def output_dec_list():
    pass

import pandas as pd
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
from dateutil.relativedelta import relativedelta
import re
from collections import Counter, defaultdict

# Single FastAPI app instance
app = FastAPI()

@app.get("/")
def healthcheck():
    return {"status": "ok"}

@app.head("/")
def healthcheck_head():
    return Response(status_code=200)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/apps")
def get_apps():
    # 1) Load CSV data
    try:
        usecols = [
            "Organisation",
            "Org ID",
            "Sub Org",
            "Sub Org ID",
            "Org Target Migration Data",
            "Application",
            "Application ID",
            "Cryptography Algorithms Used",
            "Certificates Used",
            "NIST Compliant",
            "PCI DSS Compliant",
            "HIPAA Compliant",
            "Non-Compliant",
            "Changed Algorithms",
            "Changed Certificates",
            "Replaced With (Algorithms)",
            "Replaced With (Certificates)",
            "PQC Vulnerable Algorithms",
            "PQC Vulnerable Certificates",
            "App Category",
        ]

        df = pd.read_csv(
            "data.csv",
            usecols=usecols,
            engine="python",
            on_bad_lines="skip",
            dtype=str,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"CSV read error: {e}")

    # 2) Fill nulls
    df["Cryptography Algorithms Used"] = df["Cryptography Algorithms Used"].fillna("")
    df["Certificates Used"] = df["Certificates Used"].fillna("")

    # 3) Clean compliance fields
    for col in ["NIST Compliant", "PCI DSS Compliant", "HIPAA Compliant", "Non-Compliant"]:
        df[col] = (
            df[col].fillna("")
                  .str.strip().str.upper()
                  .map({"TRUE": True, "FALSE": False})
                  .fillna(False)
        )

    # 4) Replacement counts
    def count_replacements(cell: str) -> int:
        tokens = re.split(r"[;,]", (cell or "").strip())
        return sum(1 for t in tokens if t.strip())

    df["alg_changes"] = df["Changed Algorithms"].fillna("").map(count_replacements)
    df["cert_changes"] = df["Changed Certificates"].fillna("").map(count_replacements)

    # 5) Count used algorithms and certificates
    def count_used_items(cell: str) -> int:
        tokens = re.split(r"[;,]", (cell or "").strip())
        return sum(1 for t in tokens if t.strip())

    df["total_algorithms"] = df["Cryptography Algorithms Used"].map(count_used_items)
    df["total_certificates"] = df["Certificates Used"].map(count_used_items)

    # 6) PQC vulnerabilities
    df["total_pqc_vulnerable_algorithms"] = df["PQC Vulnerable Algorithms"].fillna("").map(count_used_items)
    df["total_pqc_vulnerable_certificates"] = df["PQC Vulnerable Certificates"].fillna("").map(count_used_items)

    # 7) PQC readiness
    def calculate_pqc_ready(row):
        total = row["total_algorithms"] + row["total_certificates"]
        if total == 0:
            return 0.0
        pqc_weak = (row["total_pqc_vulnerable_algorithms"] + row["total_pqc_vulnerable_certificates"]) \
                   - (row["alg_changes"] + row["cert_changes"])
        pqc_weak = max(pqc_weak, 0)
        return round((1 - pqc_weak / total) * 100, 1)

    df["pqc_ready"] = df.apply(calculate_pqc_ready, axis=1)

    # 8) Risk level
    def risk_level(pqc):
        try:
            pqc = float(pqc)
        except:
            return "Unknown"
        if pqc >= 80:
            return "Low"
        elif 60 <= pqc < 80:
            return "Medium"
        elif 40 <= pqc < 60:
            return "High"
        else:
            return "Very High"

    df["risk_level"] = df["pqc_ready"].map(risk_level)

    # 9) Migration status
    df["status"] = df["Org Target Migration Data"].fillna("")

    # 10) Current date
    now = datetime.now()
    df["current_date"] = now.strftime("%d-%m-%Y")

    # 11) Combine unique algorithms + certs
    def combine_unique_items(algs, certs):
        items = re.split(r"[;,]", (algs or "") + ";" + (certs or ""))
        unique = sorted(set([i.strip() for i in items if i.strip()]))
        return unique

    df["algorithms_used"] = df.apply(
        lambda row: combine_unique_items(row["Cryptography Algorithms Used"], row["Certificates Used"]),
        axis=1
    )

    # 12) Vulnerabilities = pqc total - changes
    df["vulnerabilities"] = (
        df["total_pqc_vulnerable_algorithms"]
        + df["total_pqc_vulnerable_certificates"]
        - df["alg_changes"]
        - df["cert_changes"]
    ).clip(lower=0)

    # 13) Time complexity based on migration date
    def parse_quarter_to_date(qstr):
        try:
            parts = qstr.strip().upper().split()
            if len(parts) != 2:
                return None
            quarter, year = parts
            month_day = {
                "Q1": "31-03",
                "Q2": "30-06",
                "Q3": "30-09",
                "Q4": "31-12"
            }.get(quarter)
            if not month_day:
                return None
            full_date = f"{month_day}-{year}"
            return datetime.strptime(full_date, "%d-%m-%Y")
        except:
            return None

    def compute_time_complexity(row):
        tgt = parse_quarter_to_date(row["Org Target Migration Data"])
        if not tgt:
            return "Unknown"
        months = (tgt.year - now.year) * 12 + (tgt.month - now.month)
        if months <= 6:
            return "High"
        elif months <= 12:
            return "Medium"
        else:
            return "Low"

    df["time_complexity"] = df.apply(compute_time_complexity, axis=1)

    # Final response
    try:
        out = df[
            [
                "Organisation",
                "Org ID",
                "Sub Org",
                "Sub Org ID",
                "Org Target Migration Data",
                "Application",
                "Application ID",
                "pqc_ready",
                "risk_level",
                "status",
                "alg_changes",
                "cert_changes",
                "total_algorithms",
                "total_certificates",
                "total_pqc_vulnerable_certificates",
                "total_pqc_vulnerable_algorithms",
                "vulnerabilities",
                "time_complexity",
                "current_date",
                "App Category",
                "algorithms_used"
            ]
        ].rename(columns={"Application": "application"}).to_dict(orient="records")
        return out
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Response formatting error: {e}")
    

def split_and_clean(cell_content):
    """Splits a string by semicolon or comma, cleans whitespace, and removes empty strings."""
    if not isinstance(cell_content, str):
        return []
    # Split by semicolon or comma and clean up each item
    items = re.split(r'[;,]', cell_content)
    return [item.strip() for item in items if item and item.strip()]

@app.get("/api/apps2")
def get_algorithm_usage():
    """
    Analyzes algorithm usage from two CSV files (data.csv and algorithms.csv).

    This endpoint calculates the net usage of each algorithm by subtracting the
    number of times it was changed from its total usage count across all applications.

    It returns a detailed JSON object for each algorithm, including its properties,
    PQC status, usage count, and a list of applications that use it.
    """
    try:
        # Step 1: Load the datasets from CSV files
        df_data = pd.read_csv("data.csv", engine="python", on_bad_lines="skip").fillna('')
        df_algos = pd.read_csv("data2.csv", engine="python", on_bad_lines="skip").fillna('')
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=f"Error: {e}. Make sure 'data.csv' and 'algorithms.csv' are in the same directory.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred while reading the CSV files: {e}")

    # Step 2: Calculate total usage counts for each algorithm/certificate
    total_usage_counts = Counter()
    # This dictionary will map each algorithm to the applications that use it
    algorithm_to_apps_map = defaultdict(list)
    # This dictionary will map each algorithm to its NIST compliance status
    algorithm_nist_status = defaultdict(bool)


    for _, row in df_data.iterrows():
        # Combine algorithms and certificates into a single list for usage counting
        used_items = split_and_clean(row["Cryptography Algorithms Used"]) + split_and_clean(row["Certificates Used"])
        app_name = row["Application"]
        is_nist_compliant = str(row["NIST Compliant"]).upper() == 'TRUE'

        for item in used_items:
            total_usage_counts[item] += 1
            if app_name not in algorithm_to_apps_map[item]:
                algorithm_to_apps_map[item].append(app_name)
            # If any application using this algorithm is NIST compliant, we mark the algorithm as such.
            if is_nist_compliant:
                algorithm_nist_status[item] = True


    # Step 3: Calculate how many times each algorithm/certificate was changed/replaced
    changed_counts = Counter()
    for _, row in df_data.iterrows():
        changed_items = split_and_clean(row["Changed Algorithms"]) + split_and_clean(row["Changed Certificates"])
        for item in changed_items:
            changed_counts[item] += 1

    # Step 4: Combine data and format the final JSON response
    final_results = []
    for _, row in df_algos.iterrows():
        algo_name = row["Algorithm"]
        
        # Calculate net usage: total usage minus changes
        total_used = total_usage_counts.get(algo_name, 0)
        total_changed = changed_counts.get(algo_name, 0)
        net_usage = total_used - total_changed

        # Only include algorithms that are currently in use
        if net_usage > 0:
            result_item = {
                "Algorithm": algo_name,
                "Applications": algorithm_to_apps_map.get(algo_name, []),
                "Type": row["Algorithm Type"],
                "Strength": row["Strength"],
                "NIST Status": algorithm_nist_status.get(algo_name, False),
                "PQC": row["PQC"].strip().lower() == 'yes',
                "Usage": net_usage,
                "Implementation Complexity": row["Implementation Complexity"],
                "Description": row["Description"],
                "Quantum Vulnerability": row["Quantum Vulnerability"],
                "Recommended Replacement": row["Recommended Replacement"],
            }
            final_results.append(result_item)

    if not final_results:
        raise HTTPException(status_code=404, detail="No active algorithm usage found based on the provided data.")

    return final_results

import pandas as pd
from fastapi import FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
from dateutil.relativedelta import relativedelta
import re
from collections import Counter, defaultdict
from typing import Dict, List, Optional
import json

# Single FastAPI app instance
app = FastAPI(title="Healthcare Cryptography API", version="1.0.0")

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

# Load and process CSV data for apps4 endpoints
def load_csv_data():
    """Load both CSV files and create lookup dictionaries"""
    try:
        # Load the algorithm details CSV (data3)
        algorithm_df = pd.read_csv('data3.csv')
        
        # Load the applications CSV (data4)
        applications_df = pd.read_csv('data4.csv')
        
        # Create algorithm lookup dictionary
        algorithm_lookup = {}
        for _, row in algorithm_df.iterrows():
            algorithm_lookup[row['Algorithm_Name']] = {
                'name': row['Algorithm_Name'],
                'section': row['Section'],
                'category': row['Category'],
                'variant': row['Variant'],
                'purpose': row['Purpose'],
                'usage_context': row['Usage_Context'],
                'status_today': row['Status_Today'],
                'pqc_status': row['PQC_Status'],
                'priority': row['Priority'],
                'classical_recommended': row['Classical_Recommended'],
                'quantum_recommended': row['Quantum_Recommended'],
                'nist_reference': row['NIST_Reference'],
                'notes': row['Notes']
            }
        
        return applications_df, algorithm_lookup
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="CSV files not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error loading data: {str(e)}")

# Global variables to store data
try:
    applications_df, algorithm_lookup = load_csv_data()
except:
    # Initialize empty data structures if files don't exist
    applications_df = pd.DataFrame()
    algorithm_lookup = {}

def parse_algorithms(algorithm_string):
    """Parse comma-separated algorithms from CSV cell"""
    if pd.isna(algorithm_string) or algorithm_string.strip() == '':
        return []
    return [algo.strip() for algo in str(algorithm_string).split(',')]

def get_algorithm_details(algorithm_name):
    """Get detailed information about a specific algorithm"""
    if algorithm_name in algorithm_lookup:
        return algorithm_lookup[algorithm_name]
    else:
        return {
            'name': algorithm_name,
            'section': 'Unknown',
            'category': 'Unknown',
            'variant': 'Unknown',
            'purpose': 'Unknown',
            'usage_context': 'Unknown',
            'status_today': 'Unknown',
            'pqc_status': 'Unknown',
            'priority': 'Unknown',
            'classical_recommended': 'Unknown',
            'quantum_recommended': 'Unknown',
            'nist_reference': 'Unknown',
            'notes': 'Algorithm details not found in database'
        }

def split_and_clean(cell_content):
    """Splits a string by semicolon or comma, cleans whitespace, and removes empty strings."""
    if not isinstance(cell_content, str):
        return []
    # Split by semicolon or comma and clean up each item
    items = re.split(r'[;,]', cell_content)
    return [item.strip() for item in items if item and item.strip()]

# ENDPOINT 1: Original apps endpoint
@app.get("/api/apps")
def get_apps():
    """Get applications with PQC readiness analysis"""
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

# ENDPOINT 2: Algorithm usage analysis
@app.get("/api/apps2")
def get_algorithm_usage():
    """
    Analyzes algorithm usage from two CSV files (data.csv and data2.csv).

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
        raise HTTPException(status_code=404, detail=f"Error: {e}. Make sure 'data.csv' and 'data2.csv' are in the same directory.")
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

# ENDPOINT 3: Complete data3 file
@app.get("/api/apps3")
def get_full_data3_data():
    """
    Returns the complete data3 file data as JSON without any calculations or transformations.
    
    This endpoint simply reads the data3.csv file and returns all rows and columns
    as a JSON array of objects, with each object representing a row from the CSV.
    """
    try:
        # Load the data3 file without any column restrictions
        df_data3 = pd.read_csv("data3.csv", engine="python", on_bad_lines="skip")
        
        # Fill NaN values with empty strings for cleaner JSON output
        df_data3 = df_data3.fillna("")
        
        # Convert DataFrame to list of dictionaries (JSON format)
        data3_data = df_data3.to_dict(orient="records")
        
        return {
            "status": "success",
            "total_records": len(data3_data),
            "data": data3_data
        }
        
    except FileNotFoundError:
        raise HTTPException(
            status_code=404, 
            detail="data3 file not found. Make sure 'data3.csv' exists in the same directory."
        )
    except pd.errors.EmptyDataError:
        raise HTTPException(
            status_code=400, 
            detail="data3 file is empty or contains no valid data."
        )
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail=f"An error occurred while reading the data3 file: {str(e)}"
        )

# ENDPOINT 4: All applications with complete details
@app.get("/api/apps4")
def get_all_applications():
    """Get all applications with complete details"""
    try:
        if applications_df.empty:
            raise HTTPException(status_code=404, detail="Applications data not available. Check if data4.csv exists.")
            
        all_applications = []
        
        for _, app_row in applications_df.iterrows():
            application_name = app_row['Application']
            
            # Structure the response with all 5 sections
            sections = {
                'Symmetric Algorithms': [],
                'Asymmetric Algorithms': [],
                'Hash Functions': [],
                'MACs & KDFs': [],
                'Post-Quantum Cryptography': []
            }
            
            # Process each section
            for section in sections.keys():
                if section in app_row and not pd.isna(app_row[section]):
                    algorithms = parse_algorithms(app_row[section])
                    
                    for algo in algorithms:
                        algo_details = get_algorithm_details(algo)
                        sections[section].append(algo_details)
            
            application_data = {
                "application": application_name,
                "cryptographic_profile": sections,
                "summary": {
                    "total_algorithms": sum(len(algos) for algos in sections.values()),
                    "sections_with_algorithms": len([s for s in sections.values() if s]),
                    "sections_breakdown": {section: len(algos) for section, algos in sections.items()}
                }
            }
            
            all_applications.append(application_data)
        
        return {
            "status": "success",
            "count": len(all_applications),
            "applications": all_applications
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving applications: {str(e)}")

# ENDPOINT 5: Specific application details
@app.get("/applications/{application_name}")
def get_application_details(application_name: str):
    """Get detailed cryptographic information for a specific application"""
    try:
        if applications_df.empty:
            raise HTTPException(status_code=404, detail="Applications data not available. Check if data4.csv exists.")
            
        # Find the application in the dataframe
        app_row = applications_df[applications_df['Application'] == application_name]
        
        if app_row.empty:
            raise HTTPException(status_code=404, detail=f"Application '{application_name}' not found")
        
        app_data = app_row.iloc[0]
        
        # Structure the response with all 5 sections
        sections = {
            'Symmetric Algorithms': [],
            'Asymmetric Algorithms': [],
            'Hash Functions': [],
            'MACs & KDFs': [],
            'Post-Quantum Cryptography': []
        }
        
        # Process each section
        for section in sections.keys():
            if section in app_data and not pd.isna(app_data[section]):
                algorithms = parse_algorithms(app_data[section])
                
                for algo in algorithms:
                    algo_details = get_algorithm_details(algo)
                    sections[section].append(algo_details)
        
        return {
            "status": "success",
            "application": application_name,
            "cryptographic_profile": sections,
            "summary": {
                "total_algorithms": sum(len(algos) for algos in sections.values()),
                "sections_with_algorithms": len([s for s in sections.values() if s]),
                "sections_breakdown": {section: len(algos) for section, algos in sections.items()}
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving application details: {str(e)}")

# ENDPOINT 6: Application section details
@app.get("/applications/{application_name}/section/{section_name}")
def get_application_section(application_name: str, section_name: str):
    """Get algorithms for a specific section of an application"""
    try:
        if applications_df.empty:
            raise HTTPException(status_code=404, detail="Applications data not available. Check if data4.csv exists.")
            
        # Validate section name
        valid_sections = ['Symmetric Algorithms', 'Asymmetric Algorithms', 'Hash Functions', 'MACs & KDFs', 'Post-Quantum Cryptography']
        if section_name not in valid_sections:
            raise HTTPException(status_code=400, detail=f"Invalid section. Valid sections: {valid_sections}")
        
        # Find the application
        app_row = applications_df[applications_df['Application'] == application_name]
        if app_row.empty:
            raise HTTPException(status_code=404, detail=f"Application '{application_name}' not found")
        
        app_data = app_row.iloc[0]
        algorithms_data = []
        
        if section_name in app_data and not pd.isna(app_data[section_name]):
            algorithms = parse_algorithms(app_data[section_name])
            
            for algo in algorithms:
                algo_details = get_algorithm_details(algo)
                algorithms_data.append(algo_details)
        
        return {
            "status": "success",
            "application": application_name,
            "section": section_name,
            "algorithms": algorithms_data,
            "count": len(algorithms_data)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving section details: {str(e)}")

# ENDPOINT 7: Algorithm information
@app.get("/algorithms/{algorithm_name}")
def get_algorithm_info(algorithm_name: str):
    """Get detailed information about a specific algorithm"""
    try:
        algo_details = get_algorithm_details(algorithm_name)
        
        if algo_details['section'] == 'Unknown':
            raise HTTPException(status_code=404, detail=f"Algorithm '{algorithm_name}' not found in database")
        
        return {
            "status": "success",
            "algorithm": algo_details
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving algorithm details: {str(e)}")

# ENDPOINT 8: Search algorithms
@app.get("/search/algorithms")
def search_algorithms(
    section: Optional[str] = None,
    status: Optional[str] = None,
    pqc_status: Optional[str] = None,
    classical_recommended: Optional[bool] = None,
    quantum_recommended: Optional[bool] = None
):
    """Search algorithms based on various criteria"""
    try:
        if not algorithm_lookup:
            raise HTTPException(status_code=404, detail="Algorithm lookup data not available. Check if data3.csv exists.")
            
        filtered_algorithms = []
        
        for algo_name, details in algorithm_lookup.items():
            # Apply filters
            if section and details['section'] != section:
                continue
            if status and details['status_today'] != status:
                continue
            if pqc_status and details['pqc_status'] != pqc_status:
                continue
            if classical_recommended is not None:
                if str(details['classical_recommended']).lower() != str(classical_recommended).lower():
                    continue
            if quantum_recommended is not None:
                if str(details['quantum_recommended']).lower() != str(quantum_recommended).lower():
                    continue
            
            filtered_algorithms.append(details)
        
        return {
            "status": "success",
            "count": len(filtered_algorithms),
            "algorithms": filtered_algorithms
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error searching algorithms: {str(e)}")

# ENDPOINT 9: Overview statistics
@app.get("/stats/overview")
def get_overview_stats():
    """Get overall statistics about applications and algorithms"""
    try:
        if applications_df.empty or not algorithm_lookup:
            raise HTTPException(status_code=404, detail="Required data files not available.")
            
        # Application stats
        total_apps = len(applications_df)
        
        # Algorithm stats
        total_algorithms = len(algorithm_lookup)
        sections_count = {}
        status_count = {}
        pqc_status_count = {}
        
        for details in algorithm_lookup.values():
            # Count by section
            section = details['section']
            sections_count[section] = sections_count.get(section, 0) + 1
            
            # Count by status
            status = details['status_today']
            status_count[status] = status_count.get(status, 0) + 1
            
            # Count by PQC status
            pqc_status = details['pqc_status']
            pqc_status_count[pqc_status] = pqc_status_count.get(pqc_status, 0) + 1
        
        return {
            "status": "success",
            "overview": {
                "total_applications": total_apps,
                "total_algorithms": total_algorithms,
                "algorithms_by_section": sections_count,
                "algorithms_by_status": status_count,
                "algorithms_by_pqc_status": pqc_status_count
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating overview stats: {str(e)}")

# ENDPOINT 10: Reload data
@app.post("/admin/reload")
def reload_data():
    """Reload CSV data (useful for development)"""
    try:
        global applications_df, algorithm_lookup
        applications_df, algorithm_lookup = load_csv_data()
        return {"status": "success", "message": "Data reloaded successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reloading data: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

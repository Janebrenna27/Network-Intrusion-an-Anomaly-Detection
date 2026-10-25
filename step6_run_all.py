"""
step6_run_all.py — Master Script for Big Data Network Intrusion Detection Pipeline

This script runs all analysis steps sequentially, tracks execution time,
and provides a summary report at the end. If a step fails, it logs the
error and continues with the remaining steps.

Steps:
    1. Download dataset from Kaggle
    2. Ingest CSV data into MongoDB
    3. Data preprocessing and cleaning
    4. MapReduce analysis operations
    5. Visualization generation
"""

import subprocess
import sys
import time
from datetime import datetime

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# ============================================================================
# Configuration
# ============================================================================

# Define all pipeline steps in execution order
PIPELINE_STEPS = [
    {
        "step": 1,
        "script": "step1_download_dataset.py",
        "description": "Download CIC-IDS-2017 dataset from Kaggle",
    },
    {
        "step": 2,
        "script": "step2_ingest_to_mongodb.py",
        "description": "Ingest CSV data into MongoDB",
    },
    {
        "step": 3,
        "script": "step3_data_preprocessing.py",
        "description": "Data preprocessing and cleaning",
    },
    {
        "step": 4,
        "script": "step4_mapreduce_analysis.py",
        "description": "MapReduce analysis operations",
    },
    {
        "step": 5,
        "script": "step5_visualization.py",
        "description": "Generate visualizations",
    },
]


# ============================================================================
# Helper Functions
# ============================================================================

def format_duration(seconds):
    """Format a duration in seconds into a human-readable string."""
    if seconds < 60:
        return f"{seconds:.2f} seconds"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = seconds % 60
        return f"{minutes}m {secs:.2f}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = seconds % 60
        return f"{hours}h {minutes}m {secs:.2f}s"


def print_separator(char="=", length=70):
    """Print a visual separator line."""
    print(char * length)


def print_header(text):
    """Print a formatted header."""
    print_separator()
    print(f"  {text}")
    print_separator()


def run_step(step_info):
    """
    Run a single pipeline step as a subprocess.

    Args:
        step_info (dict): Dictionary containing step number, script name,
                          and description.

    Returns:
        dict: Result dictionary with status, duration, and error info.
    """
    step_num = step_info["step"]
    script = step_info["script"]
    description = step_info["description"]

    print(f"\n{'─' * 70}")
    print(f"  STEP {step_num}: {description}")
    print(f"  Script: {script}")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'─' * 70}\n")

    result = {
        "step": step_num,
        "script": script,
        "description": description,
        "status": "PENDING",
        "duration": 0,
        "error": None,
    }

    start_time = time.time()

    try:
        # Run the script as a subprocess using the same Python interpreter
        process = subprocess.run(
            [sys.executable, script],
            capture_output=False,  # Show output in real-time
            text=True,
            timeout=7200,  # 2-hour timeout per step
        )

        elapsed = time.time() - start_time
        result["duration"] = elapsed

        if process.returncode == 0:
            result["status"] = "SUCCESS"
            print(f"\n  ✅ Step {step_num} completed successfully "
                  f"in {format_duration(elapsed)}")
        else:
            result["status"] = "FAILED"
            result["error"] = f"Process exited with return code {process.returncode}"
            print(f"\n  ❌ Step {step_num} FAILED with return code "
                  f"{process.returncode} (took {format_duration(elapsed)})")

    except subprocess.TimeoutExpired:
        elapsed = time.time() - start_time
        result["duration"] = elapsed
        result["status"] = "TIMEOUT"
        result["error"] = "Step exceeded the 2-hour timeout limit"
        print(f"\n  ⏰ Step {step_num} TIMED OUT after {format_duration(elapsed)}")

    except FileNotFoundError:
        elapsed = time.time() - start_time
        result["duration"] = elapsed
        result["status"] = "NOT FOUND"
        result["error"] = f"Script '{script}' not found"
        print(f"\n  ⚠️  Step {step_num} SKIPPED — script '{script}' not found")

    except Exception as e:
        elapsed = time.time() - start_time
        result["duration"] = elapsed
        result["status"] = "ERROR"
        result["error"] = str(e)
        print(f"\n  ❌ Step {step_num} encountered an error: {e}")

    return result


def print_summary(results, total_duration):
    """
    Print a formatted summary table of all pipeline step results.

    Args:
        results (list): List of result dictionaries from each step.
        total_duration (float): Total pipeline execution time in seconds.
    """
    print("\n")
    print_header("PIPELINE EXECUTION SUMMARY")
    print(f"  Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Total Duration: {format_duration(total_duration)}")
    print_separator("-")

    # Status icons
    status_icons = {
        "SUCCESS": "✅",
        "FAILED": "❌",
        "TIMEOUT": "⏰",
        "NOT FOUND": "⚠️ ",
        "ERROR": "❌",
        "SKIPPED": "⏭️ ",
    }

    # Print each step result
    print(f"\n  {'Step':<6} {'Status':<14} {'Duration':<18} {'Description'}")
    print(f"  {'─' * 6} {'─' * 14} {'─' * 18} {'─' * 30}")

    for r in results:
        icon = status_icons.get(r["status"], "❓")
        duration_str = format_duration(r["duration"]) if r["duration"] > 0 else "—"
        print(f"  {r['step']:<6} {icon} {r['status']:<10} {duration_str:<18} "
              f"{r['description']}")

    # Print error details if any
    failed_steps = [r for r in results if r["status"] != "SUCCESS"]
    if failed_steps:
        print(f"\n  {'─' * 64}")
        print("  ERRORS:")
        for r in failed_steps:
            if r["error"]:
                print(f"    Step {r['step']}: {r['error']}")

    # Print overall status
    success_count = sum(1 for r in results if r["status"] == "SUCCESS")
    total_count = len(results)

    print(f"\n  {'─' * 64}")
    if success_count == total_count:
        print(f"  🎉 ALL {total_count} STEPS COMPLETED SUCCESSFULLY!")
    else:
        print(f"  ⚠️  {success_count}/{total_count} steps completed successfully")
        print(f"     {total_count - success_count} step(s) had issues")

    print_separator()


# ============================================================================
# Main Execution
# ============================================================================

def main():
    """Run the complete Big Data analysis pipeline."""

    print_header("BIG DATA NETWORK INTRUSION & ANOMALY DETECTION PIPELINE")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Python:  {sys.version.split()[0]}")
    print(f"  Steps:   {len(PIPELINE_STEPS)}")
    print_separator()

    results = []
    pipeline_start = time.time()

    # Run each step sequentially. Later steps depend on earlier database inputs.
    for step_info in PIPELINE_STEPS:
        if results and results[-1]["status"] != "SUCCESS":
            result = {
                "step": step_info["step"],
                "script": step_info["script"],
                "description": step_info["description"],
                "status": "SKIPPED",
                "duration": 0,
                "error": "Skipped because a prerequisite step failed.",
            }
            results.append(result)
            print(f"\n  Step {step_info['step']} skipped - prerequisite step failed")
            continue

        result = run_step(step_info)
        results.append(result)

    total_duration = time.time() - pipeline_start

    # Print the final summary
    print_summary(results, total_duration)

    # Return exit code based on results
    if all(r["status"] == "SUCCESS" for r in results):
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()

## Container Vulnerability Scanner

### Purpose

This script automates vulnerability scanning of container images using [Trivy](https://github.com/aquasecurity/trivy) and [Grype](https://github.com/anchore/grype), enriches the results with NVD (National Vulnerability Database) data, and generates comprehensive reports. It is designed to streamline vulnerability management for containerized environments.

### Workflow

1. **Scan Stage:**  
   - Scans specified container images using Trivy and Grype.
   - Outputs CSV files with vulnerability data for each image.

2. **NVD Enrichment Stage:**  
   - Enriches the scan results by querying the NVD API for additional CVE details (severity, CVSS score, etc.).
   - Produces enriched CSV files.

3. **Report Stage:**  
   - Aggregates all results and generates an Excel report summarizing vulnerabilities and statistics.

### Usage

1. **Install Python Dependencies**

   ```
   pip install -r requirements.txt
   ```

2. **Install External Tools**

   - Ensure both `trivy` and `grype` are installed and available in your system's PATH.

3. **Run the Script**

   ```
   python container_vulnerability_scanner.py --images <image1>,<image2> --output-dir <output_folder>
   ```

   - Example:
     ```
     python container_vulnerability_scanner.py --images nginx:latest,ubuntu:22.04 --output-dir ./output
     ```

   - You can resume at specific stages using `--stage`:
     - `scan` (default): Full workflow.
     - `nvd_enrich`: Only enrich and report.
     - `report`: Only generate the final report.

4. **Review the Output**

   - The output directory will contain CSV files and a comprehensive Excel report (`vulnerability_report.xlsx`).

---

**Note:**  
- You may need to set the `NVD_API_KEY` environment variable for higher NVD API rate limits.
- If you believe any part of the code can be optimized, feel free to do so yourself—unless it’s a critical issue, in which case please report or fix it directly.
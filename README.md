#  Security Log Analyzer

A web-based dashboard for analyzing authentication logs and detecting suspicious activities.

## Features

-  Upload and parse authentication log files
-  Real-time security metrics and statistics
-  Identify suspicious IP addresses with multiple failed attempts
-  Visualize login patterns by time, IP, and user
-  Generate downloadable security reports
-  Interactive charts and dashboards

## Technologies Used

- **Python** - Core programming language
- **Streamlit** - Web application framework
- **Pandas** - Data manipulation and analysis
- **Plotly** - Interactive visualizations

## Installation

1. Clone the repository:
```bash
git clone <your-repo-url>
cd log_analyzer
```
2. Install dependencies:
```bash
pip install -r requirements.txt
```
3. Run the application:
```bash
streamlit run app.py
```
4. Open your browser and navigate to http://localhost:8501
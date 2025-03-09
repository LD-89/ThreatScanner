Threat Scanner
-

Run the script with python interpreter.

Use Command Line Interface to get the results.

!Important - Be sure to set your API keys in the environment file.

Available commands:
- get_sources [limit: optional, default=100]
- print_sources
- save_sources
- scan
- print_reports
- compare
- print_results
- save_results [format: optional, default=csv]
- quit

Regular flow should follow the path:
- get_sources
- scan
- compare
- save_results

File created from save_result contains the analysis of websites scan.
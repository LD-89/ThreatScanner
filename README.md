Threat Scanner
-

Run the script with python interpreter.

Use Command Line Interface to get the results.

**!Important - Be sure to set your API keys in the environment file.**

### Available commands:
- `get_sources [limit: optional, default=100]`
- `print_sources`
- `save_sources`
- `scan`
- `print_reports`
- `compare`
- `print_results`
- `save_results [format: optional, default=csv]`
- `quit`

### Regular flow should follow the path:
- `get_sources`
- `scan`
- `compare`
- `save_results`

File created from save_result contains the analysis of websites scan.

## Storage Options

ThreatScanner supports two storage options:

1. **Local File Storage** (default): Results are saved to local files
2. **AWS S3 Storage**: Results are saved to an AWS S3 bucket

### Using S3 Storage

To use S3 storage, set the following environment variables:

- `USE_S3_STORAGE=True` - Enable S3 storage
- `AWS_ACCESS_KEY_ID` - Your AWS access key
- `AWS_SECRET_ACCESS_KEY` - Your AWS secret key
- `S3_BUCKET_NAME` - The name of your S3 bucket (default: 'threatscanner-data')

You can also specify the storage option when using the `save_results` command:


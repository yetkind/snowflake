# Snowflake
# Alienvault OTX Domain IP Address Lookup

This script uses the OTX API to search for IP addresses associated with a domain using the `passive_dns` endpoint. It then exports the IP addresses to YARA, SpamAssassin, CSV, and JSON formats.
(The quality of these exports can be subjective /s .)

## Prerequisites

- Python 3.x
- `requests` library (`pip install requests`)

## Usage

1. Clone the repository or download the script file.

2. Install the required library:
    ```sh
    pip install requests
    ```

3. Run the script:
    ```sh
    python snowflake.py
    ```

4. Follow the prompts to enter the domain and your OTX API key.

## Output

The script will generate four output files in the same directory:

- `output.yara`
- `output.spamassassin`
- `output.csv`
- `output.json`

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

**Author**: Yetkin Degirmenci (2024)

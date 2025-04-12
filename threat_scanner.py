import os
from datetime import datetime
from typing import Tuple
from dotenv import load_dotenv
import requests
import asyncio
import aiohttp
import time
import vt
from urllib.request import urlopen
from urllib.parse import urlparse

from storage import FileStorage, S3Storage

load_dotenv()

# urls
OPEN_PHISH_FEED_URL = os.getenv("OPEN_PHISH_FEED_URL")
BLOCK_LIST_PROJECT_URL = os.getenv("BLOCK_LIST_PROJECT_URL")
GOOGLE_SAFE_BROWSING_API_URL = os.getenv("GOOGLE_SAFE_BROWSING_API_URL")

# credentials
VIRUS_TOTAL_API_KEY = os.getenv("VIRUS_TOTAL_API_KEY")
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")

# configs
VIRUS_TOTAL_MALICIOUS_THRESHOLD = 3
VIRUS_TOTAL_RATE_LIMIT_TIME = 15


class ThreatScanner:
    storage = None
    phishing_websites: dict
    final_report: list

    def __init__(self):
        if os.environ.get('USE_S3_STORAGE', 'False').lower() == 'true':
            bucket_name = os.environ.get('S3_BUCKET_NAME', 'threatscanner-data')
            self.storage = S3Storage(bucket_name)
        else:
            self.storage = FileStorage()
        self.phishing_websites = {}
        self.final_report = []

    def _validate_url(self, url: str)-> bool:
        if urlparse(url.strip()):
            return True
        return False

    def _get_timestamp(self)-> str:
        return datetime.now().strftime("%Y%m%d_%H%M")

    def _get_list_from_url(self, url:str)-> list[str]:
        """
        Fetches list of urls from specified feed url.
        :param url:
        :return: list of strings
        """
        print(f"Fetching sources from {url}...", end="\t")
        try:
            page = urlopen(url)
            page_bytes = page.read()
            page_content = page_bytes.decode("utf-8")
            urls_list = page_content.split("\n")
        except Exception as e:
            print(f"Error: Could not extract data from {url}")
            raise e
        print(f"Done.")
        return list(filter(self._validate_url, urls_list))

    def _set_phishing_websites(self, limit: int):
        """
        Fetches the list of phishing websites from sources and merges them into a dict.
        """
        print(f"Gathering sources...")
        open_phish_urls = self._get_list_from_url(OPEN_PHISH_FEED_URL)
        block_list_urls = self._get_list_from_url(BLOCK_LIST_PROJECT_URL)
        full_urls_list = open_phish_urls + block_list_urls
        self.phishing_websites = {url: {"url": url} for url in full_urls_list[:limit]}
        print(f"Sources gathered: {len(self.phishing_websites)}")

    def _get_vt_report_for_website(self, url: str)-> dict|None:
        """
        Encodes the website url and requests the url scan report.
        See more: https://virustotal.github.io/vt-py/quickstart.html#get-information-about-an-url
        :param url: str
        :return: dict or None
        """
        print(f"Checking report for {url}... ", end="\t")
        url_id = vt.url_id(url)
        url_report = self.client.get_object("/urls/{}", url_id)

        if not url_report:
            print(f"Error: Could not get report for {url}.")
            return None
        print("Done")
        return url_report.to_dict()

    def _get_malicious_result(self, phishing_website: dict)-> bool:
        """
        Checks if malicious vendors reported by VirusTotal exceeds given threshold.
        :param phishing_website:
        :return: bool
        """
        if phishing_website["virus_total_report"]:
            malicious_reports_count = (
                phishing_website["virus_total_report"]["attributes"].get("last_analysis_stats", {}).get("malicious", 0)
            )
            if malicious_reports_count >= VIRUS_TOTAL_MALICIOUS_THRESHOLD:
                return True
        return False

    def _scan_virus_total(self):
        """
        Check the list of phishing websites against a VirusTotal scan reports.
        """
        print("VirusTotal scan started.")
        self.client = vt.Client(VIRUS_TOTAL_API_KEY)
        for url, website in self.phishing_websites.items():
            self.phishing_websites[url]["virus_total_report"] = (self._get_vt_report_for_website(url))
            self.phishing_websites[url]["virus_total_malicious_result"] = self._get_malicious_result(website)
            # Limiting the number of requests based on public API limits
            time.sleep(VIRUS_TOTAL_RATE_LIMIT_TIME)
        self.client.close()
        print("VirusTotal scan completed.")

    def _get_google_reports_for_websites(self) -> dict | None:
        """
        Requests the reports for websites from Google Safe Browsing API.
        See more: https://developers.google.com/safe-browsing/reference/rest/v4/threatMatches/find
        :return: dict or None
        """
        def _create_payload() -> dict:
            google_threat_scanner_app_id = os.getenv("GOOGLE_THREAT_SCANNER_APP_ID")
            return {
                'client': {
                    # Register your threat scanner app
                    'clientId': google_threat_scanner_app_id,
                    'clientVersion': "1.0"
                },
                'threatInfo': {
                    'threatTypes': ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    'platformTypes': ["ANY_PLATFORM"],
                    'threatEntryTypes': ["URL"],
                    'threatEntries': [{'url': url} for url in self.phishing_websites]
                }
            }

        print(f"Fetching report for all websites... ", end="\t")
        api_url = f"{GOOGLE_SAFE_BROWSING_API_URL}threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
        headers = {'Content-Type': 'application/json'}
        payload = _create_payload()
        response = requests.post(api_url, headers=headers, json=payload)
        if response.status_code != 200:
            print(
                f"Error: Could not get reports from Google Safe Browsing API. Status code: {response.status_code} .")
            return None
        print("Done")
        return response.json()

    def _assign_reports_to_websites(self, reports):
        """
        Assigns GSB threat reports to related websites.
        If there is no threat match, the website is considered safe.
        :param reports:
        :return:
        """
        matches = reports.get('matches', [])
        for match in matches:
            url = match["threat"]["url"]
            if url in self.phishing_websites:
                self.phishing_websites[url]["google_safe_browsing_report"] = match["threat"]
                self.phishing_websites[url]["google_safe_browsing_result"] = True

        #If the url is not in the matches consider it not malicious
        for url in self.phishing_websites:
            if "google_safe_browsing_report" not in self.phishing_websites[url]:
                self.phishing_websites[url]["google_safe_browsing_report"] = {}
                self.phishing_websites[url]["google_safe_browsing_result"] = False

    def _scan_google_safe_browsing(self):
        """
        Check the dict of phishing websites against a Google Safe Browsing scan reports.
        """
        print("GoogleSafeBrowsing scan started.")
        reports = self._get_google_reports_for_websites()
        self._assign_reports_to_websites(reports)
        print("GoogleSafeBrowsing scan completed.")

    async def _is_website_alive(self, session, url: str)-> Tuple[str, bool]:
        """
        Checks the status of a website.
        :param session:
        :param url: str
        :return: Tuple[str, bool]
        """
        message = f"Status of {url}: "
        try:
            async with session.head(url, timeout=5, allow_redirects=False) as response:
                if 200 <= response.status < 400:
                    print(message+"Alive.")
                    return url, True
            print(message+"Dead.")
            return url, False
        except Exception as e:
            print(message+"Dead.")
            return url, False

    async def _check_websites_status(self):
        print(f"Checking status of websites...")
        async with aiohttp.ClientSession() as session:
            tasks = []
            for url in self.phishing_websites:
                tasks.append(self._is_website_alive(session, url))
            results = await asyncio.gather(*tasks)
            return results

    def _assign_website_status(self, results):
        for url, alive in results:
            self.phishing_websites[url]["live"] = alive

    def _count_results(self)-> Tuple[int, int, int, int]:
        """
        Counts the results for further analysis.
        :return: Tuple[int, int, int, int]
        """
        total_count = 0
        alive_count = 0
        virus_total_count = 0
        google_safe_browsing_count = 0

        for url, data in self.phishing_websites.items():
            total_count += 1
            if data['live']:
                alive_count += 1
            if data["virus_total_malicious_result"]:
                virus_total_count += 1
            if data["google_safe_browsing_result"]:
                google_safe_browsing_count += 1
        return total_count, alive_count, virus_total_count, google_safe_browsing_count

    def _analyze_results(self):
        """
        Analysis the results and sets a human-readable report.
        :return:
        """
        print(f"Analyzing results...")
        total_count, alive_count, virus_total_count, google_safe_browsing_count = self._count_results()
        dead_count = total_count - alive_count
        alive_percentage = (alive_count / total_count) * 100
        dead_percentage = (dead_count / total_count) * 100

        final_report = [
            f"There were a total of {total_count} websites scanned.",
            f"{alive_count} websites were alive.",
            f"{alive_percentage:.2f}% of websites were alive.",
            f"{dead_count} websites were dead.",
            f"{dead_percentage:.2f}% of websites were dead.",
            f"VirusTotal marked {virus_total_count} websites as malicious.",
            f"GoogleSafeBrowsing marked {google_safe_browsing_count} websites as malicious."
        ]

        if virus_total_count > google_safe_browsing_count:
            final_report.append("VirusTotal was more effective in detecting phishing.")
        elif google_safe_browsing_count > virus_total_count:
            final_report.append("GoogleSafeBrowsing was more effective in detecting phishing.")
        else:
            final_report.append("VirusTotal and GoogleSafeBrowsing were equal in detecting phishing.")
            
        self.final_report = final_report
        print(f"Analysis completed. Final report is ready for viewing or saving.")


    def get_sources(self, limit: int):
        """Method used by CLI to fetch sources"""
        self._set_phishing_websites(limit)

    def print_sources(self):
        """Method used by CLI to print sources to terminal"""
        if not self.phishing_websites:
            print("No phishing websites found.")
        for url in self.phishing_websites:
            print(url)

    def save_sources(self, data_format: str):
        """Method used by CLI to save sources to a csv file"""
        if not self.phishing_websites:
            print("No phishing websites found.")
        else:
            self.storage.save(self.phishing_websites, 'sources', data_format)

    def scan_websites(self):
        """Method used by CLI to scan websites"""
        if not self.phishing_websites:
            print("No phishing websites found.")
        else:
            self._scan_virus_total()
            self._scan_google_safe_browsing()

            status_results = asyncio.run(self._check_websites_status())
            self._assign_website_status(status_results)

    def print_reports(self):
        """Method used by CLI to print scan reports to terminal"""
        if not self.phishing_websites:
            print("No phishing websites found.")
        else:
            for url, data in self.phishing_websites.items():
                print(data)

    def compare_results(self):
        """Method used by CLI to compare results and prepare analysis report"""
        if not self.phishing_websites:
            print("No phishing websites found.")
        else:
            try:
                self._analyze_results()
            except KeyError as e:
                print("Reports not found.")

    def print_results(self):
        """Method used by CLI to print final report to terminal"""
        if not self.phishing_websites:
            print("No phishing websites found.")
        elif not self.final_report:
            print("Final report not ready.")
        else:
            print("Final report:")
            for line in self.final_report:
                print(line)
            print("---")

    def save_results(self, data_format: str):
        """Method used by CLI to save final report to a file"""
        if not self.phishing_websites:
            print("No phishing websites found.")
        elif not self.final_report:
            print("Final report not ready.")
        else:
            self.storage.save(self.final_report, 'final_report', data_format)
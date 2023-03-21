import base64
import hashlib
import time

import requests


def _hash_file(filepath):
    """
    Compute the SHA-256 hash of a file.

    Args:
        filepath (str): The path to the file to hash.

    Returns:
        str: The SHA-256 hash of the file.
    """
    with open(filepath, "rb") as f:
        hasher = hashlib.sha256()
        while chunk := f.read(1024 * 1024):
            hasher.update(chunk)
    return hasher.hexdigest()


class VirusTotalClient:
    def __init__(self, api_key):
        # Initialize the VirusTotalClient instance with the API key, base URL, and headers
        self.api_key = api_key
        self.url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": self.api_key}

    def _submit_file_for_analysis(self, filepath):
        """
        Submit a file for analysis.

        Args:
            filepath (str): The path to the file to submit for analysis.

        Returns:
            dict: A dictionary containing the analysis results for the submitted file.
        """
        params = {"filename": filepath}
        files = {"file": open(filepath, "rb")}
        response = requests.post(f"{self.url}/files", headers=self.headers, params=params, files=files)
        if response.status_code == 200:
            resource = response.json()["data"]["id"]
            # Check analysis status every 10 seconds until it is finished
            while True:
                response = requests.get(f"{self.url}/analyses/{resource}", headers=self.headers)
                if response.status_code == 200:
                    analysis_results = response.json()["data"]["attributes"]
                    if analysis_results["status"] == "completed":
                        return analysis_results
                    else:
                        time.sleep(10)
                else:
                    print(f"Error retrieving analysis results: {response.text}")
                    break
        else:
            print(f"Error submitting file for analysis: {response.text}")

    def get_file_report(self, filepath):
        """
        Get the analysis report for a file given its SHA-256 hash.

        Args:
            filepath (str): The SHA-256 hash of the file to get the analysis report for.

        Returns:
            dict: A dictionary containing the analysis report for the file.
        """
        self._submit_file_for_analysis(filepath)
        hashed_file = _hash_file(filepath)
        response = requests.get(f"{self.url}/files/{hashed_file}", headers=self.headers)
        if response.status_code == 200:
            return response.json()["data"]["attributes"]
        else:
            print(f"Error getting file report: {response.text}")

    def get_url_report(self, url):
        """
        Submit a URL for analysis.

        Args:
            url (str): The URL to submit for analysis.

        Returns:
            dict: A dictionary containing the analysis results for the submitted URL.
        """
        params = {"url": url}
        response = requests.post(f"{self.url}/urls", headers=self.headers, params=params)
        if response.status_code == 200:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            while True:
                response = requests.get(f"{self.url}/urls/{url_id}", headers=self.headers)
                if response.status_code == 200:
                    analysis_results = response.json()
                    if analysis_results["data"]["attributes"]["status"] == "completed":
                        print(analysis_results)
                        return analysis_results
                    else:
                        time.sleep(10)
                else:
                    print(f"Error retrieving analysis results: {response.text}")
                    break
        else:
            print(f"Error submitting URL for analysis: {response.text}")


    def get_domain_report(self, domain):
        """
        Get the domain report for a given domain.

        Args:
            domain (str): The domain to get the report for.

        Returns:
            dict: A dictionary containing the domain report.
        """
        response = requests.get(f"{self.url}/domains/{domain}", headers=self.headers)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error getting domain report: {response.text}")

    def get_ip_address_report(self, ip_address):
        """
        Get a report on an IP address.

        Args:
            ip_address (str): The IP address to get the report for.

        Returns:
            dict: A dictionary containing the report for the IP address.
        """
        response = requests.get(f"{self.url}/ip_addresses/{ip_address}", headers=self.headers)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error getting IP address report: {response.text}")

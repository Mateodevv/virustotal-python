import requests


class VirusTotalClient:
    def __init__(self, api_key):
        # Initialize the VirusTotalClient instance with the API key, base URL, and headers
        self.api_key = api_key
        self.url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": self.api_key}

    def get_analysis_results(self, hash):
        """
        Get the analysis results for a file given its SHA-256 hash.

        Args:
            hash (str): The SHA-256 hash of the file to get the analysis results for.

        Returns:
            dict: A dictionary containing the analysis results for the file.
        """
        response = requests.get(f"{self.url}/files/{hash}/analysis", headers=self.headers)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error getting analysis results: {response.text}")

    def submit_file_for_analysis(self, filepath):
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
            return response.json()
        else:
            print(f"Error submitting file for analysis: {response.text}")

    def get_file_report(self, hash):
        """
        Get a report on a file given its SHA-256 hash.

        Args:
            hash (str): The SHA-256 hash of the file to get the report for.

        Returns:
            dict: A dictionary containing the report for the file.
        """
        response = requests.get(f"{self.url}/files/{hash}", headers=self.headers)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error getting file report: {response.text}")

    def get_url_report(self, url):
        """
        Get a report on a URL.

        Args:
            url (str): The URL to get the report for.

        Returns:
            dict: A dictionary containing the report for the URL.
        """
        params = {"resource": url}
        response = requests.get(f"{self.url}/urls", headers=self.headers, params=params)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error getting URL report: {response.text}")

    def submit_url_for_analysis(self, url):
        """
        Submit a URL for analysis.

        Args:
            url (str): The URL to submit for analysis.

        Returns:
            dict: A dictionary containing the analysis results for the submitted URL.
        """
        params = {"url": url}
        response = requests.post(f"{self.url}/urls", headers=self.headers, json=params)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error submitting URL for analysis: {response.text}")

    def get_domain_report(self, domain):
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

    def get_intelligence_search(self, query, limit=None):
        """
        Search VirusTotal Intelligence for information about a file, URL, domain, or IP address.

        Args:
            query (str): The query string to search for.
            limit (int, optional): The maximum number of results to return. Defaults to None.

        Returns:
            dict: A dictionary containing the search results.
        """
        params = {"query": query}
        if limit is not None:
            params["limit"] = limit
        response = requests.get(f"{self.url}/intelligence/search", headers=self.headers, params=params)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error searching VirusTotal Intelligence: {response.text}")

    def get_intelligence_file_metadata(self, hash):
        """
        Get metadata for a file from VirusTotal Intelligence.

        Args:
            hash (str): The SHA-256 hash of the file to get metadata for.

        Returns:
            dict: A dictionary containing the metadata for the file.
        """
        response = requests.get(f"{self.url}/intelligence/search/{hash}/files", headers=self.headers)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error getting file metadata: {response.text}")

    def get_intelligence_url_metadata(self, url):
        """
        Get metadata for a URL from VirusTotal Intelligence.

        Args:
            url (str): The URL to get metadata for.

        Returns:
            dict: A dictionary containing the metadata for the URL.
        """
        response = requests.get(f"{self.url}/intelligence/search/{url}/urls", headers=self.headers)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error getting URL metadata: {response.text}")

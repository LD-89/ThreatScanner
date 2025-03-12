from abc import ABC, abstractmethod

import boto3
import os
import csv
import json
from datetime import datetime


class Storage(ABC):
    def _get_timestamp(self)-> str:
        return datetime.now().strftime("%Y%m%d_%H%M")

    @abstractmethod
    def save(self, data, file_name, file_type):
        pass

    @abstractmethod
    def load(self):
        pass


class FileStorage(Storage):
    def save(self, data, data_type: str = "threat_scanner_data" , file_type: str = "csv"):
        """Save data to file"""
        timestamp = self._get_timestamp()
        file_name = f"{timestamp}_{data_type}.{file_type}"
        print(f"Writing {data_type} to {file_name} ...", end="\t")
        if file_type not in ["csv", "md", "txt", "json"]:
            print(f"Error: Unsupported file type {file_type}.")
            return
        with open(file_name, 'w', newline='') as file:
            if file_type == "csv":
                writer = csv.writer(file)
                for row in data:
                    writer.writerow([row])
            elif file_type == 'json':
                json.dump(data, file, indent=4)
            else:
                for line in data:
                    file.write(f"{line}\n")

        print(f"{data_type} saved to {file_name}")


    def load(self):
        """Load data from file"""
        print("Not implemented yet.")
        pass


class S3Storage(Storage):
    def __init__(self, bucket_name):
        self.s3_client = boto3.client(
            's3',
            aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY')
        )
        self.bucket_name = bucket_name

    def save(self, data, data_type: str = "threat_scanner_data" , file_type: str = "csv"):
        """Save data to S3 bucket"""
        print("Not implemented yet.")
        pass


    def load(self):
        """Load data from S3 bucket"""
        print("Not implemented yet.")
        pass
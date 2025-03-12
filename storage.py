from abc import ABC, abstractmethod

from botocore.exceptions import ClientError
import boto3
import os
import csv
import json
from datetime import datetime


class Storage(ABC):
    def _get_timestamp(self)-> str:
        return datetime.now().strftime("%Y%m%d_%H%M")

    @abstractmethod
    def save(self, data, data_type, data_format):
        pass

    @abstractmethod
    def load(self):
        pass


class FileStorage(Storage):
    def save(self, data, data_type: str = "threat_scanner_data" , data_format: str = "csv"):
        """Save data to file"""
        timestamp = self._get_timestamp()
        file_name = f"{timestamp}_{data_type}.{data_format}"
        print(f"Writing {data_type} to {file_name} ...", end="\t")
        if data_format not in ["csv", "md", "txt", "json"]:
            print(f"Error: Unsupported file type {data_format}.")
            return
        with open(file_name, 'w', newline='') as file:
            if data_format == "csv":
                writer = csv.writer(file)
                for row in data:
                    writer.writerow([row])
            elif data_format == 'json':
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

    def save(self, data, data_type: str = "threat_scanner_data" , data_format: str = "json"):
        """Save data to S3 bucket"""
        timestamp = self._get_timestamp()
        key = f"{timestamp}_{data_type}.{data_format}"
        print(f"Saving {data_type} to S3 Bucket: {self.bucket_name} under key {key} ...", end="\t")
        try:
            if data_format == 'json':
                content = json.dumps(data)
                content_type = 'application/json'
            elif data_format == 'csv':
                content = self._convert_to_csv(data)
                content_type = 'text/csv'
                print(f"Not implemented saving csv to S3, yet.")
                return
            else:
                print(f"Error: Unsupported data format {data_format}.")
                return

            self.s3_client.put_object(
                Bucket=self.bucket_name,
                Key=key,
                Body=content,
                ContentType=content_type
            )
            return True
        except ClientError as e:
            print(f"Error saving to S3: {e}")
            return False

    def load(self):
        """Load data from S3 bucket"""
        print("Not implemented yet.")
        pass

    def _convert_to_csv(self, data):
        # TODO implement csv conversion
        return data.to_csv().encode('utf-8')
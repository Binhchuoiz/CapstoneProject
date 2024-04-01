import os
import django

os.environ['DJANGO_SETTINGS_MODULE'] ='CVEAlert.settings'
django.setup()

import json
from django.db import transaction
from django.utils import timezone
from firstapp.models import CVE, Descriptions, Versions, Solutions, Metric, CvssV20, CvssV30, CvssV31, References, Affected, Products, Vendors, Products_Versions


def add_data_to_database(data, folder_name):
    cve_id = data['cveMetadata']['cveId']
    if CVE.objects.filter(cve_id=cve_id).exists():
        print(f"CVE with ID {cve_id} already exists in the database.")
        return

    cve = CVE.objects.create(
        cve_id=cve_id,
        year=folder_name,
        data_version=data.get('dataVersion', ''),  # Handle missing key with default value
        data_type=data.get('dataType', ''),  # Handle missing key with default value
        date_reserved=data['cveMetadata'].get('dateReserved', None),  # Handle missing key with None
        date_publish=data['cveMetadata'].get('datePublished', None),  # Handle missing key with None
        date_update=data['cveMetadata'].get('dateUpdated', None),  # Handle missing key with None
        assigner_Org_Id=data['cveMetadata'].get('assignerOrgId', ''),  # Handle missing key with default value
        provider_Metadata=data['containers']['cna'].get('providerMetadata', {}).get('orgId', '')  # Handle nested missing key with default value
    )

    try:
        description_en = data['containers']['cna']['descriptions'][0]['value']
        Descriptions.objects.create(value=description_en, con=cve)
    except (KeyError, IndexError):
        pass  # Handle missing key or index error by skipping the creation

    try:
        solution_en = data['containers']['cna']['solutions'][0]['value']
        Solutions.objects.create(value=solution_en, con=cve)
    except (KeyError, IndexError):
        pass  # Handle missing key or index error by skipping the creation

    for affected in data['containers']['cna'].get('affected', []):
        product_name = affected.get('product')
        if product_name != 'n/a':
            product, _ = Products.objects.get_or_create(name=product_name)

            for version_data in affected.get('versions', []):
                version, _ = Versions.objects.get_or_create(version=version_data.get('version', ''), status=version_data.get('status', ''))

            vendor_name = affected.get('vendor')
            if vendor_name:
                vendor, _ = Vendors.objects.get_or_create(name=vendor_name)
            else:
                vendor = None

            Affected.objects.create(con=cve, product=product, vendor=vendor)

    for metric in data['containers']['cna'].get('metrics', []):  # Handle missing key with empty list
        if 'cvssV2_0' in metric:
            cvssV2_0_data = metric['cvssV2_0']
            CvssV20.objects.create(
                version=cvssV2_0_data.get('version', ''),
                vector_string=cvssV2_0_data.get('vectorString', ''),
                base_score=cvssV2_0_data.get('baseScore', ''),
                con=cve
            )

        if 'cvssV3_0' in metric:
            cvssV3_0_data = metric['cvssV3_0']
            CvssV30.objects.create(
                version=cvssV3_0_data.get('version', ''),
                vector_string=cvssV3_0_data.get('vectorString', ''),
                base_score=cvssV3_0_data.get('baseScore', ''),
                base_severity=cvssV3_0_data.get('baseSeverity', ''),
                con=cve
            )

        if 'cvssV3_1' in metric:
            cvssV3_1_data = metric['cvssV3_1']
            CvssV31.objects.create(
                version=cvssV3_1_data.get('version', ''),
                vector_string=cvssV3_1_data.get('vectorString', ''),
                base_score=cvssV3_1_data.get('baseScore', ''),
                base_severity=cvssV3_1_data.get('baseSeverity', ''),
                con=cve
            )

    for reference_data in data['containers']['cna'].get('references', []):  # Handle missing key with empty list
        References.objects.create(con=cve, url=reference_data['url'])

def process_cve_folders(cves_folder_path):
    if not os.path.isdir(cves_folder_path) or not os.listdir(cves_folder_path):
        print("No subfolders found in the 'cves' directory.")
        return
    for folder_name in os.listdir(cves_folder_path):
        if os.path.isdir(os.path.join(cves_folder_path, folder_name)):
            sub_folder_path = os.path.join(cves_folder_path, folder_name)
            read_json_files(sub_folder_path, folder_name)

def read_json_files(folder_path, folder_name):
    for root, _, files in os.walk(folder_path):
        for filename in files:
            if filename.endswith(".json"):
                json_filepath = os.path.join(root, filename)
                try:
                    with open(json_filepath, 'r') as file:
                        data = json.load(file)
                    add_data_to_database(data, folder_name)
                    print(f"Record inserted from: {json_filepath}")
                except UnicodeDecodeError:
                    print("Error decoding JSON in:", json_filepath)
                    continue

# Specify the path to the directory containing JSON files
cves_folder_path = r"D:\Đồ án\cvelistV5\cves"
cves_folder_path = os.path.normpath(cves_folder_path)

try:
    process_cve_folders(cves_folder_path)
except OSError as e:
    print("Error accessing directory:", e)

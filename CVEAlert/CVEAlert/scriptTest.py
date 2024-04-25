import os
import django
import json5

os.environ['DJANGO_SETTINGS_MODULE'] = 'CVEAlert.settings'
django.setup()

from firstapp.models import CVE, Descriptions, Products, Versions, Affected, References, ProblemTypes, Metric

def add_data_to_database(data):
    cve_id = data['cveMetadata']['cveId']
    if CVE.objects.filter(cve_id=cve_id).exists():
        print(f"CVE with ID {cve_id} already exists in the database.")
        return
    
    cve = CVE.objects.create(
        cve_id=cve_id,
        data_version=data.get('dataVersion', ''),  
        data_type=data.get('dataType', ''),  
        date_reserved=data['cveMetadata'].get('dateReserved', None),  
        date_publish=data['cveMetadata'].get('datePublished', None),  
        date_update=data['cveMetadata'].get('dateUpdated', None),  
        assigner_Org_Id=data['cveMetadata'].get('assignerOrgId', ''),  
        assignerShortName=data['cveMetadata'].get('assignerShortName', '')  
    )

    try:
        description_en = data['containers']['cna']['descriptions'][0]['value']
        Descriptions.objects.create(value=description_en, con=cve, lang='en')
    except (KeyError, IndexError):
        pass  # Handle missing key or index error by skipping the creation

    try:
        reference_urls = [reference['url'] for reference in data['containers']['cna']['references']]
        for url in reference_urls:
            References.objects.create(con=cve, url=url)
    except (KeyError, IndexError):
        pass  # Handle missing key or index error by skipping the creation

    try:
        affected_data = data['containers']['cna']['affected'][0]
        product_name = affected_data['product']
        if product_name == 'n/a':
            print(f"Skipping file for CVE {cve_id} because product is 'n/a'")
            return
        product, _ = Products.objects.get_or_create(name=product_name)

        for version_data in affected_data['versions']:
            version = version_data['version']
            version_status = version_data['status']
            version_obj, _ = Versions.objects.get_or_create(version=version, status=version_status)
            Affected.objects.create(con=cve, product=product, version=version_obj)
    except (KeyError, IndexError):
        pass  # Handle missing key or index error by skipping the creation

    try:
        problem_type_desc = data['containers']['cna']['problemTypes'][0]['descriptions'][0]['description']
        ProblemTypes.objects.create(con=cve, description=problem_type_desc, lang='en')
    except (KeyError, IndexError):
        pass  # Handle missing key or index error by skipping the creation

    try:
        metric_data = data['containers']['cna']['metrics'][0]['cvssV3_1']
        Metrics.objects.create(
            con=cve,
            version=metric_data['version'],
            vector_string=metric_data['vectorString'],
            base_score=metric_data['baseScore'],
            base_severity=metric_data['baseSeverity']
        )
    except (KeyError, IndexError):
        pass  # Handle missing key or index error by skipping the creation

def process_json_files(folder_path):
    for filename in os.listdir(folder_path):
        if filename.endswith(".json5"):
            file_path = os.path.join(folder_path, filename)
            try:
                with open(file_path, 'r') as file:
                    data = json5.load(file)
                    add_data_to_database(data)
                    print(f"Record inserted from: {file_path}")
            except Exception as e:
                print(f"Error processing file {file_path}: {e}")

# Specify the path to the directory containing JSON5 files
cves_folder_path = r"D:\path\to\json5_files"

try:
    cves_folder_path = os.path.normpath(cves_folder_path)
    process_json_files(cves_folder_path)
except OSError as e:
    print("Error accessing directory:", e)

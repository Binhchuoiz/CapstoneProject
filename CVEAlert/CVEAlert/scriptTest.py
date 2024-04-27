import os
import django
import json

os.environ['DJANGO_SETTINGS_MODULE'] = 'CVEAlert.settings'
django.setup()

from firstapp.models import CVE, Descriptions, Versions, Solutions, Metric, CvssV20, CvssV30, CvssV31, References, Affected, Products, Vendors, Products_Versions, Exploits, ProblemTypes, Workaround


def add_data_to_database(data, folder_name, json_filepath):
    cve_id = data['cveMetadata']['cveId']
    if CVE.objects.filter(cve_id=cve_id).exists():
        print(f"CVE with ID {cve_id} already exists in the database.")
        return

    try:
        affected = data['containers']['cna']['affected']
    except KeyError:
        return

    cve = CVE.objects.create(
        cve_id=cve_id,
        year=folder_name,
        data_version=data.get('dataVersion', ''),
        data_type=data.get('dataType', ''),
        date_reserved=data['cveMetadata'].get('dateReserved', None),
        date_publish=data['cveMetadata'].get('datePublished', None),
        date_update=data['cveMetadata'].get('dateUpdated', None),
        assigner_org_id=data['cveMetadata'].get('assignerOrgId', ''),
        assigner_short_name=data['cveMetadata'].get('assignerShortName', None),
        title=data['containers']['cna'].get('title', None)
    )

    for product_data in affected:
        product_name = product_data.get('product')
        if product_name == 'n/a':
            continue
        
        product, _ = Products.objects.get_or_create(name=product_name)

        versions_data = product_data.get('versions', [])
        for version_data in versions_data:
            version = version_data.get('version')
            version_status = version_data.get('status')
            version_obj, _ = Versions.objects.get_or_create(version=version, status=version_status)
            Products_Versions.objects.create(con=cve, product=product, version=version_obj)

        vendor_name = product_data.get('vendor')
        vendor, _ = Vendors.objects.get_or_create(name=vendor_name)
        Affected.objects.create(con=cve, product=product, vendor=vendor)

    # Continue with other data insertion logic...

    try:
        description_en = data['containers']['cna']['descriptions'][0]['value']
        Descriptions.objects.create(value=description_en, con=cve)
    except (KeyError, IndexError):
        Descriptions.objects.create(value=None, con=cve)

    try:
        solution_en = data['containers']['cna']['solutions'][0]['value']
        Solutions.objects.create(value=solution_en, con=cve)
    except (KeyError, IndexError):
        Solutions.objects.create(value=None, con=cve)

    try:
        exploit_en = data['containers']['cna']['exploits'][0]['value']
        Exploits.objects.create(value=exploit_en, con=cve)
    except (KeyError, IndexError):
        Exploits.objects.create(value=None, con=cve)

    try:
        workaround_en = data['containers']['cna']['workarounds'][0]['value']
        Workaround.objects.create(value=workaround_en, con=cve)
    except (KeyError, IndexError):
        Workaround.objects.create(value=None, con=cve)

    # Handle 'problemTypes' key
    try:
        problem_types = data['containers']['cna'].get('problemTypes', [])
        for p in problem_types:
            try:
                for d in p['descriptions']:
                    cwe_id = d.get('cweId')
                    description = d.get('description')
                    ProblemTypes.objects.create(cwe_id=cwe_id, description=description, con=cve)
            except (KeyError, IndexError):
                ProblemTypes.objects.create(cwe_id=None, description=None, con=cve)
                continue
    except KeyError:
        print("No 'problemTypes' found in the JSON data.")
        pass

    # Handle metrics
    try:
        metrics = data['containers']['cna']['metrics']
        has_valid_metric = False
        for metric in metrics:
            cvssV2_0_data = metric.get('cvssV2_0', {})
            cvssV2_0_version = cvssV2_0_data.get('version')
            cvssV2_0_base_score = cvssV2_0_data.get('baseScore')
            cvssV2_0_vector = cvssV2_0_data.get('vectorString')

            cvssV3_0_data = metric.get('cvssV3_0', {})
            cvssV3_0_version = cvssV3_0_data.get('version')
            cvssV3_0_base_score = cvssV3_0_data.get('baseScore')
            cvssV3_0_vector = cvssV3_0_data.get('vectorString')
            cvssV3_0_base_severity = cvssV3_0_data.get('baseSeverity')

            cvssV3_1_data = metric.get('cvssV3_1', {})
            cvssV3_1_version = cvssV3_1_data.get('version')
            cvssV3_1_base_score = cvssV3_1_data.get('baseScore')
            cvssV3_1_vector = cvssV3_1_data.get('vectorString')
            cvssV3_1_base_severity = cvssV3_1_data.get('baseSeverity')
            attackComplexity = cvssV3_1_data.get('attackComplexity')
            attackVector = cvssV3_1_data.get('attackVector')
            availabilityImpact = cvssV3_1_data.get('availabilityImpact')
            confidentialityImpact = cvssV3_1_data.get('confidentialityImpact')
            integrityImpact = cvssV3_1_data.get('integrityImpact')
            privilegesRequired = cvssV3_1_data.get('privilegesRequired')
            scope = cvssV3_1_data.get('scope')
            userInteraction = cvssV3_1_data.get('userInteraction')

            # Check if any CVSS version has values
            if cvssV2_0_version or cvssV3_0_version or cvssV3_1_version:
                has_valid_metric = True
                cvssV20_obj, _ = CvssV20.objects.get_or_create(
                    version=cvssV2_0_version,
                    vector_string=cvssV2_0_vector,
                    base_score=cvssV2_0_base_score,
                )

                cvssV30_obj, _ = CvssV30.objects.get_or_create(
                    version=cvssV3_0_version,
                    vector_string=cvssV3_0_vector,
                    base_score=cvssV3_0_base_score,
                    base_severity=cvssV3_0_base_severity,
                )

                cvssV31_obj, _ = CvssV31.objects.get_or_create(
                    attackComplexity=attackComplexity,
                    attackVector=attackVector,
                    availabilityImpact=availabilityImpact,
                    confidentialityImpact=confidentialityImpact,
                    integrityImpact=integrityImpact,
                    privilegesRequired=privilegesRequired,
                    scope=scope,
                    userInteraction=userInteraction,
                    version=cvssV3_1_version,
                    vector_string=cvssV3_1_vector,
                    base_score=cvssV3_1_base_score,
                    base_severity=cvssV3_1_base_severity,
                )

                Metric.objects.create(con=cve, cvssv20=cvssV20_obj, cvssv30=cvssV30_obj, cvssv31=cvssV31_obj)

        if not has_valid_metric:
            print(f"No valid metric found for CVE {cve_id}. Skipping metric insertion.")

    except KeyError:
        pass

    # Handle references
    try:
        references = data['containers']['cna']['references']
        for reference_data in references:
            reference_url = reference_data.get('url')
            References.objects.create(con=cve, url=reference_url)
    except KeyError:
        print("No 'references' found in the JSON data.")
        pass
    
    print(f"CVE {cve_id} is successfully added.")


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
                    add_data_to_database(data, folder_name, json_filepath)
                    
                except UnicodeDecodeError:
                    print("Error decoding JSON in:", json_filepath)
                    continue


# Specify the path to the directory containing JSON files
cves_folder_path = r"D:\Đồ án\cves"

cves_folder_path = os.path.normpath(cves_folder_path)

try:
    process_cve_folders(cves_folder_path)
except OSError as e:
    print("Error accessing directory:", e)

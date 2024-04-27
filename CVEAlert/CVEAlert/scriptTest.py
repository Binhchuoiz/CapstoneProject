import os
import django

os.environ['DJANGO_SETTINGS_MODULE'] ='CVEAlert.settings'
django.setup()

import json
from firstapp.models import CVE, Descriptions, Versions, Solutions, Metric, CvssV20, CvssV30, CvssV31, References, Affected, Products, Vendors, Products_Versions, Exploits, ProblemTypes, Workaround


def add_data_to_database(data, folder_name):
    cve_id = data['cveMetadata']['cveId']
    if CVE.objects.filter(cve_id=cve_id).exists():
        print(f"CVE with ID {cve_id} already exists in the database.")
        return
    
    try:
        affected = data['containers']['cna']['affected']
    except KeyError:
        return
    try:
        product = data['containers']['cna']['affected'][0]['product']
    except KeyError:
        return
    if product == 'n/a':
        print(f"CVE isnt eligible")
        return
    else:
        cve = CVE.objects.create(
            cve_id=cve_id,
            year=folder_name,
            data_version=data.get('dataVersion', ''),  # Handle missing key with default value
            data_type=data.get('dataType', ''),  # Handle missing key with default value
            date_reserved=data['cveMetadata'].get('dateReserved', None),  # Handle missing key with None
            date_publish=data['cveMetadata'].get('datePublished', None),  # Handle missing key with None
            date_update=data['cveMetadata'].get('dateUpdated', None),  # Handle missing key with None
            assigner_org_id=data['cveMetadata'].get('assignerOrgId', ''),  # Handle missing key with default value
            assigner_short_name=data['cveMetadata'].get('assignerShortName', None),
            title=data['containers']['cna'].get('title', None)
        )

        try:
            description_en = data['containers']['cna']['descriptions'][0]['value']
            Descriptions.objects.create(value=description_en, con=cve)
        except (KeyError, IndexError):
            Descriptions.objects.create(value=None, con=cve)
            pass  # Handle missing key or index error by skipping the creation

        try:
            solution_en = data['containers']['cna']['solutions'][0]['value']
            Solutions.objects.create(value=solution_en, con=cve)
        except (KeyError, IndexError):
            Solutions.objects.create(value=None, con=cve)
            pass  # Handle missing key or index error by skipping the creation

        try:
            exploit_en = data['containers']['cna']['exploits'][0]['value']
            Exploits.objects.create(value=exploit_en, con=cve)
        except (KeyError, IndexError):
            Exploits.objects.create(value=None, con=cve)
            pass

        try:
            workaround_en = data['containers']['cna']['workarounds'][0]['value']
            Workaround.objects.create(value=workaround_en, con=cve)
        except (KeyError, IndexError):
            Workaround.objects.create(value=None, con=cve)
            pass

        i=0
        # problemTypes = data['containers']['cna']['problemTypes']
        for p in data['containers']['cna']['problemTypes']:
            try:
                for d in p['descriptions']:
                    cwe_id = d.get('cweId')
                    description = d.get('description')
                    ProblemTypes.objects.create(cwe_id=cwe_id, description=description, con=cve)
                i+=1
            except (KeyError, IndexError):
                ProblemTypes.objects.create(cwe_id=None, description=None, con=cve)
                pass

        i=0
        for product in affected:
            try:
                product = data['containers']['cna']['affected'][i]['product']
            except KeyError:
                return
            if product == 'n/a':
                return
            else:
                product, _ = Products.objects.get_or_create(name=product)
                j=0
                for versions in data['containers']['cna']['affected'][i]['versions']:
                    try:
                        version = versions['version']
                    except (KeyError, IndexError):
                        version = None
                        version_status = None
                        version_obj, _ = Versions.objects.get_or_create(version=version, status=version_status)
                        Products_Versions.objects.create(con=cve, version=version_obj, product=product)
                        break
                    try:
                        version_status = versions[j]['status']
                    except (KeyError, IndexError):
                        version_status = None
                    version_obj, _ = Versions.objects.get_or_create(version=version, status=version_status)
                    Products_Versions.objects.create(con=cve, product=product, version=version_obj)
                    j+=1
                try:
                    vendor = data['containers']['cna']['affected'][i]['vendor']
                except KeyError:
                    vendor = None
                vendor, _ = Vendors.objects.get_or_create(name=vendor)
                Affected.objects.create(con=cve, product=product, vendor=vendor)
            i+=1
        try:
            metrics = data['containers']['cna']['metrics']
            for metric in metrics:
                if 'cvssV2_0' in metric:
                    cvssV2_0_version = metric['cvssV2_0']['version']
                    cvssV2_0_base_score = metric['cvssV2_0']['baseScore']
                    cvssV2_0_vector = metric['cvssV2_0']['vectorString']
                else: 
                    cvssV2_0_version = None 
                    cvssV2_0_base_score = None
                    cvssV2_0_vector = None
                 
                if 'cvssV3_0' in metric:
                    cvssV3_0_version = metric['cvssV3_0']['version']
                    cvssV3_0_base_score = metric['cvssV3_0']['baseScore']
                    cvssV3_0_vector = metric['cvssV3_0']['vectorString']
                    cvssV3_0_base_severity = metric['cvssV3_0']['baseSeverity']
                else: 
                    cvssV3_0_version = None 
                    cvssV3_0_base_score = None
                    cvssV3_0_vector = None
                    cvssV3_0_base_severity = None
                
                if 'cvssV3_1' in metric:
                    attackComplexity = metric['cvssV3_1'].get('attackComplexity')
                    attackVector = metric['cvssV3_1'].get('attackVector')
                    availabilityImpact = metric['cvssV3_1'].get('availabilityImpact')
                    confidentialityImpact = metric['cvssV3_1'].get('confidentialityImpact')
                    integrityImpact = metric['cvssV3_1'].get('integrityImpact')
                    privilegesRequired = metric['cvssV3_1'].get('privilegesRequired')
                    scope = metric['cvssV3_1'].get('scope')
                    userInteraction = metric['cvssV3_1'].get('userInteraction')
                    cvssV3_1_version = metric['cvssV3_1'].get('version')
                    cvssV3_1_base_score = metric['cvssV3_1'].get('baseScore')
                    cvssV3_1_vector = metric['cvssV3_1'].get('vectorString')
                    cvssV3_1_base_severity = metric['cvssV3_1'].get('baseSeverity')
                else: 
                    attackComplexity = None
                    attackVector = None
                    availabilityImpact = None
                    confidentialityImpact = None
                    integrityImpact = None
                    privilegesRequired = None
                    scope = None
                    userInteraction = None
                    cvssV3_1_version = None 
                    cvssV3_1_base_score = None
                    cvssV3_1_vector = None
                    cvssV3_1_base_severity = None
                
        except KeyError:
            cvssV2_0_version = None 
            cvssV2_0_base_score = None
            cvssV2_0_vector = None
            cvssV3_0_version = None 
            cvssV3_0_base_score = None
            cvssV3_0_vector = None
            cvssV3_0_base_severity = None
            attackComplexity = None
            attackVector = None
            availabilityImpact = None
            confidentialityImpact = None
            integrityImpact = None
            privilegesRequired = None
            scope = None
            userInteraction = None
            cvssV3_1_version = None 
            cvssV3_1_base_score = None
            cvssV3_1_vector = None
            cvssV3_1_base_severity = None

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
            attackComplexity = attackComplexity,
            attackVector = attackVector,
            availabilityImpact = availabilityImpact,
            confidentialityImpact = confidentialityImpact,
            integrityImpact = integrityImpact,
            privilegesRequired = privilegesRequired,
            scope = scope,
            userInteraction = userInteraction,
            version=cvssV3_1_version,
            vector_string=cvssV3_1_vector,
            base_score=cvssV3_1_base_score,
            base_severity=cvssV3_1_base_severity,
        )
        
        Metric.objects.create(con=cve, cvssv20=cvssV20_obj, cvssv30=cvssV30_obj, cvssv31=cvssV31_obj)

        i = 0
        references = data['containers']['cna']['references']
        for reference in references:  
            reference = data['containers']['cna']['references'][i].get('url')
            References.objects.create(con=cve, url=reference)
            i+=1

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

# 


cves_folder_path = os.path.normpath(cves_folder_path)

try:
    process_cve_folders(cves_folder_path)
except OSError as e:
    print("Error accessing directory:", e)

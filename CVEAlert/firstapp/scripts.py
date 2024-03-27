import json
import mysql.connector
import os
from CVEAlert.signals import cve_Updated



# Kết nối đến cơ sở dữ liệu MySQL
mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  password="",
  database="test1"
)

mycursor = mydb.cursor()

mycursor.execute("SELECT IFNULL(MAX(id), 0) FROM firstapp_cve")
cve_id = mycursor.fetchone()[0] + 1
con_id = cve_id
cvssV2_0_id = cve_id
cvssV3_0_id = cve_id
cvssV3_1_id = cve_id
mycursor.execute("SELECT IFNULL(MAX(id), 0) FROM firstapp_products")
product_id = mycursor.fetchone()[0] +1
mycursor.execute("SELECT IFNULL(MAX(id), 0) FROM firstapp_vendors")
vendor_id = mycursor.fetchone()[0] +1
mycursor.execute("SELECT IFNULL(MAX(id), 0) FROM firstapp_versions")
version_id = mycursor.fetchone()[0] +1
# mycursor.execute("SELECT IFNULL(MAX(id), 0) FROM firstapp_descriptions")
# des_id = mycursor.fetchone()[0] +1
# mycursor.execute("SELECT IFNULL(MAX(id), 0) FROM firstapp_solutions")
# sol_id = mycursor.fetchone()[0] +1
# mycursor.execute("SELECT IFNULL(MAX(id), 0) FROM firstapp_references")
# reference_id = mycursor.fetchone()[0] +1



# product_id = 457
# vendor_id = 457
# version_id = 537
# cvssV2_0_id = 19818
# cvssV3_0_id = 19818
# cvssV3_1_id = 19818
# reference_id = 1599


# Trích xuất các trường dữ liệu từ JSON
def add_data_to_mysql(data, folder_name):
  global product_id
  global version_id
  global vendor_id
  global cve_id
  global con_id
  global cvssV2_0_id
  global cvssV3_0_id
  global cvssV3_1_id
#   global reference_id

  cveId = data['cveMetadata']['cveId']
  # Kiểm tra xem cveId đã tồn tại trong cơ sở dữ liệu chưa
  mycursor.execute("SELECT cve_id FROM firstapp_cve WHERE cve_id = %s", (cveId,))
  existing_cve = mycursor.fetchone()

  # Nếu cveId đã tồn tại, trả về ngay lập tức
  if existing_cve:
    print(f"cveId {cveId} already exists in the database.")
    return

  # Kiểm tra giá trị của trường 'product'
  try:
    affected = data['containers']['cna']['affected']
  except KeyError: return
  try:
    product = data['containers']['cna']['affected'][0]['product']
  except KeyError: return
  if product == 'n/a':
    return
  else:
    data_type = data['dataType']
    data_version = data['dataVersion']

    try:
      provider_Metadata = data['containers']['cna']['providerMetadata']['orgId']
    except KeyError:
      provider_Metadata = None
    assigner_Org_Id = data['cveMetadata'].get('assignerOrgId')
    date_reserved = data['cveMetadata'].get('dateReserved')
    date_publish = data['cveMetadata'].get('datePublished')
    date_update = data['cveMetadata'].get('dateUpdated')

    # try:
    #   description_en = data['containers']['cna']['descriptions'][0]['value']
    # except KeyError:
    #   description_en = None

    # try:
    #   solution_en = data['containers']['cna']['solutions'][0]['value']
    # except KeyError:
    #   solution_en = None
   
    mycursor.execute("INSERT INTO firstapp_cve (data_type, data_version, cve_id, year, provider_Metadata, assigner_Org_Id, date_reserved, date_publish, date_update) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                    (data_type, data_version, cveId, folder_name, provider_Metadata, assigner_Org_Id, date_reserved, date_publish, date_update))
    mydb.commit()
    cve_Updated.send(sender=None)

    try:
      description_en = data['containers']['cna']['descriptions'][0]['value']
      mycursor.execute("INSERT INTO firstapp_descriptions (value, con_id) VALUES (%s, %s)", (description_en, con_id))
    except KeyError:
      description_en = None
      mycursor.execute("INSERT INTO firstapp_descriptions (value, con_id) VALUES (%s, %s)", (description_en, con_id))

    try:
      solution_en = data['containers']['cna']['solutions'][0]['value']
      mycursor.execute("INSERT INTO firstapp_solutions (value, con_id) VALUES (%s, %s)", (solution_en, con_id))
    except KeyError:
      solution_en = None
      mycursor.execute("INSERT INTO firstapp_solutions (value, con_id) VALUES (%s, %s)", (solution_en, con_id))
    
    i = 0
    for product in affected:
      try:
        product = data['containers']['cna']['affected'][i]['product']
      except KeyError:
        return
      if product == 'n/a':
        return
      else:
        mycursor.execute("INSERT INTO firstapp_products (name) VALUES (%s)", (product,))
        mydb.commit()
        j = 0
        for version in affected:
          try:
            version = data['containers']['cna']['affected'][i]['versions'][j]['version']
          except (KeyError, IndexError):
            version = None
            version_status = None
            mycursor.execute("INSERT INTO firstapp_versions (version, status) VALUES (%s, %s)", (version, version_status))
            mydb.commit()
            mycursor.execute("INSERT INTO firstapp_products_versions (product_id, version_id) VALUES (%s, %s)", (product_id, version_id))
            mydb.commit()
            # version_id = version_id + 1
            break
          try:
            version_status = data['containers']['cna']['affected'][i]['versions'][j]['status']
          except (KeyError, IndexError):
            version_status = None
          mycursor.execute("INSERT INTO firstapp_versions (version, status) VALUES (%s, %s)", (version, version_status))
          mydb.commit()
          mycursor.execute("INSERT INTO firstapp_products_versions (product_id, version_id) VALUES (%s, %s)", (product_id, version_id))
          mydb.commit()
          version_id = version_id + 1
          j+=1
        try:
          vendor = data['containers']['cna']['affected'][i]['vendor']
        except KeyError:
          vendor = None
        mycursor.execute("INSERT INTO firstapp_vendors (name) VALUES (%s)", (vendor,))
        mydb.commit()
        mycursor.execute("INSERT INTO firstapp_affected (con_id, product_id, vendor_id) VALUES (%s, %s, %s)", (con_id, product_id, vendor_id))
        mydb.commit()
      product_id = product_id + 1
      vendor_id = vendor_id + 1
      i+=1

    
    
    try:
      for metric in data['containers']['cna']['metrics']:
        if 'cvssV2_0' in metric:
          cvssV2_0_version = metric['cvssV2_0']['version']
          cvssV2_0_base_score = metric['cvssV2_0']['baseScore']
          cvssV2_0_vector = metric['cvssV2_0']['vectorString']
        else: 
          cvssV2_0_version = None 
          cvssV2_0_base_score = None
          cvssV2_0_vector = None
    except KeyError:
      cvssV2_0_version = None 
      cvssV2_0_base_score = None
      cvssV2_0_vector = None
    mycursor.execute("INSERT INTO firstapp_cvssv20 (version, base_score, vector_string) VALUES (%s, %s, %s)",
                      (cvssV2_0_version, cvssV2_0_base_score, cvssV2_0_vector))
    mydb.commit()

    try:
      for metric in data['containers']['cna']['metrics']:
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
    except KeyError:
      cvssV3_0_version = None 
      cvssV3_0_base_score = None
      cvssV3_0_vector = None
      cvssV3_0_base_severity = None
    mycursor.execute("INSERT INTO firstapp_cvssv30 (version, base_score, vector_string, base_severity) VALUES (%s, %s, %s, %s)",
                      (cvssV3_0_version, cvssV3_0_base_score, cvssV3_0_vector, cvssV3_0_base_severity))
    mydb.commit()

    try:
      for metric in data['containers']['cna']['metrics']:
        if 'cvssV3_1' in metric:
          cvssV3_1_version = metric['cvssV3_1']['version']
          cvssV3_1_base_score = metric['cvssV3_1']['baseScore']
          cvssV3_1_vector = metric['cvssV3_1']['vectorString']
          cvssV3_1_base_severity = metric['cvssV3_1']['baseSeverity']
        else: 
          cvssV3_1_version = None 
          cvssV3_1_base_score = None
          cvssV3_1_vector = None
          cvssV3_1_base_severity = None
    except KeyError:
      cvssV3_1_version = None 
      cvssV3_1_base_score = None
      cvssV3_1_vector = None
      cvssV3_1_base_severity = None
    mycursor.execute("INSERT INTO firstapp_cvssv31 (version, base_score, vector_string, base_severity) VALUES (%s, %s, %s, %s)",
                    (cvssV3_1_version, cvssV3_1_base_score, cvssV3_1_vector, cvssV3_1_base_severity))
    mydb.commit()
    mycursor.execute("INSERT INTO firstapp_metric (con_id, cvssv20_id, cvssv30_id, cvssv31_id) VALUES (%s, %s, %s, %s)", 
                    (con_id, cvssV2_0_id, cvssV3_0_id, cvssV3_1_id))
    mydb.commit()

    i = 0
    references = data['containers']['cna']['references']
    for reference in references:  
      reference = data['containers']['cna']['references'][i].get('url')
      mycursor.execute("INSERT INTO firstapp_references (con_id, url) VALUES (%s, %s)", (con_id, reference))
      mydb.commit()
      i+=1
    #   reference_id = reference_id + 1

    cve_id = cve_id + 1
    con_id = con_id + 1
    cvssV2_0_id = cvssV2_0_id + 1
    cvssV3_0_id = cvssV3_0_id + 1
    cvssV3_1_id = cvssV3_1_id + 1

# Đường dẫn đến thư mục chứa thư mục các tệp JSON
cves_folder_path = r"D:\Đồ án\cvelistV5\cves"
cves_folder_path = os.path.normpath(cves_folder_path)

def process_cve_folders(cves_folder_path):
    # Kiểm tra xem thư mục cves có thư mục con không
    if not os.path.isdir(cves_folder_path) or not os.listdir(cves_folder_path):
        print("No subfolders found in the 'cves' directory.")
        return
    for folder_name in os.listdir(cves_folder_path):
        # Kiểm tra xem folder_name có phải là một thư mục không
        if os.path.isdir(os.path.join(cves_folder_path, folder_name)):
        # Tạo đường dẫn đầy đủ đến thư mục con
            sub_folder_path = os.path.join(cves_folder_path, folder_name)
            read_json_files(sub_folder_path, folder_name)

def read_json_files(folder_path, folder_name):
    a = 1
    for root, dirs, files in os.walk(folder_path):
        for filename in files:
            if filename.endswith(".json"):
                json_filepath = os.path.join(root, filename)
                # Đọc dữ liệu từ tệp JSON
                try:
                    with open(json_filepath, 'r') as file:
                        data = json.load(file)
                    # Sử dụng hàm để thêm dữ liệu từ tệp JSON vào cơ sở dữ liệu MySQL
                    add_data_to_mysql(data, folder_name )
                    print(a, "Record inserted from:", json_filepath)
                    a += 1
                    
                except UnicodeDecodeError:
                    print("Error decoding JSON in:", json_filepath)
                    continue

try:
    process_cve_folders(cves_folder_path)
except OSError as e:
    print("Error accessing directory:", e)
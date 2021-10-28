import os
import requests
import json
import time
import sca
from sca.project import Project
from config.conf import urls
import matplotlib.pyplot as plt
import numpy as np
from config.conf import path_for_scan_reports, path_for_scan_full_csv_stats
import csv
from datetime import datetime
#project index number for lumo - please initiate it with an index which is NOT already created!
num = '211'

total_projects_scanned = len(urls)
#vulnerabilities counters
total_vulnerabilities_percent = 0
total_outdated_packages_percent = 0
total_vulnerable_packages_percent = 0
num_of_projects_with_risk_score = 0
average_risk_score = 0
total_packages = 0
high_vulnerability_count = 0
high_vulnerability_count_percent = 0
medium_vulnerability_count = 0
medium_vulnerability_count_percent = 0
low_vulnerability_count = 0
low_vulnerability_count_percent = 0
risk_score = 0
total_outdated_packages = 0
num_of_vulnerable_packages = 0
total_vulnerabilities = 0
#license counters
total_packages_with_legal_risk = 0
license_high_risk_count = 0
license_medium_risk_count = 0
total_packages_with_legal_risk_percent = 0
license_high_risk_count_percent = 0
license_medium_risk_count_percent = 0
#running on each Github project
for url in urls:
    client = sca.Client(username='lumo', password=os.getenv('SCA_PASSWORD'))
    project = client.create_project(name='poorly_maintained_' + num)
    print("============= NEW PROJECT STARTING =============")
    print("The project name is " + 'poorly_maintained_' + num)
    print("The project id is " + project.id)
    print("this run number: "+num)
    #increasing the index by 1 for the name of the project in the next run
    num = int(num)+1
    print("next run number: " + str(num))
    num = str(num)
    #scanning the given Github url
    scan_proj = project.scan_public_github_repo(url)
    print("The repo that being checked is " + url)
    print("The scan id is " + scan_proj.id)

    project = client.get_project(id=project.id)
    scans = project.scans()

    time.sleep(3)
    #running on all scans and selecting the current scan id (which is "attached" to the project id)
    for scan in scans:
        if scan.id == scan_proj.id:
            scan_x = client.get_scan(id=scan.id)
            #getting the status of the current scan
            print(scan_x.status())
            status_data = scan_x.status()['name']
            print(status_data)
            time.sleep(10)
            #as long as the status is scanning, we will check every 30 seconds for the status again
            while status_data == 'Scanning':
                time.sleep(30)
                status_data = scan_x.status()['name']
                print("30 seconds passed, the status is " + status_data)
            #use this in case you would like to present the vulnerabilities full report
            #if scan_x.vulnerabilities():
             #   print(scan_x.vulnerabilities())
            #else: print("No vulnerabilities found!")
            # use this in case you would like to present the licenses full report
            #if scan_x.licenses():
             #   print(scan_x.licenses())
            #else: print("No licenses risks found!")
            if status_data == 'Done':
                api_url = str("/risk-management/risk-reports?projectId="+project.id+"&size=1")
                print("-----------------------------------------------------------------------")
                print("The API call is: " +api_url)

                response = client.authenticated_request(api_url,'GET',None, None, None, True)
                #printing the scan report as a JSON
                print(response)
                #Saving the report (the name of the report is the current scan id of that scan)
                url_file = path_for_scan_reports + '/%s.txt'%(scan_proj.id)
                print(url_file)
                with open(url_file, 'w') as outfile:
                    json.dump(response, outfile)
                print("-----------------------------------------------------------------------")
                #counters
                if response:
                    total_packages += response[0]['totalPackages']
                    high_vulnerability_count += response[0]['highVulnerabilityCount']
                    medium_vulnerability_count += response[0]['mediumVulnerabilityCount']
                    low_vulnerability_count += response[0]['lowVulnerabilityCount']
                    #in case the risk score=0, do not add it
                    if response[0]['riskScore'] != 0:
                        risk_score += response[0]['riskScore']
                        num_of_projects_with_risk_score += 1
                    total_outdated_packages += response[0]['totalOutdatedPackages']
                    num_of_vulnerable_packages += response[0]['vulnerablePackages']
                    total_packages_with_legal_risk += response[0]['totalPackagesWithLegalRisk']
                    license_high_risk_count += response[0]['licensesLegalRisk']['high']
                    license_medium_risk_count += response[0]['licensesLegalRisk']['medium']


total_vulnerabilities += high_vulnerability_count + medium_vulnerability_count + low_vulnerability_count
average_risk_score = risk_score / num_of_projects_with_risk_score

print("Total projects that have been scanned: ")
print(total_projects_scanned)
print("Total packages: ")
print(total_packages)
print("high_vulnerability_count: ")
print(high_vulnerability_count)
print("medium_vulnerability_count: ")
print(medium_vulnerability_count)
print("low_vulnerability_count: ")
print(low_vulnerability_count)
print("total_vulnerabilities: ")
print(total_vulnerabilities)
print("total_outdated_packages: ")
print(total_outdated_packages)
print("num_of_vulnerable_packages: ")
print(num_of_vulnerable_packages)
print("total_packages_with_legal_risk: ")
print(total_packages_with_legal_risk)
print("license_high_risk_count: ")
print(license_high_risk_count)
print("license_medium_risk_count: ")
print(license_medium_risk_count)

print("============= VULNERABILITIES STATS =============")
print("total_vulnerabilities_percent")
total_vulnerabilities_percent = (total_vulnerabilities / total_packages) * 100
print(total_vulnerabilities_percent)
print("total_high_vulnerabilities_percent")
high_vulnerability_count_percent = (high_vulnerability_count / total_vulnerabilities) * 100
print(high_vulnerability_count_percent)
print("total_medium_vulnerabilities_percent")
medium_vulnerability_count_percent = (medium_vulnerability_count / total_vulnerabilities) * 100
print(medium_vulnerability_count_percent)
print("total_low_vulnerabilities_percent")
low_vulnerability_count_percent = (low_vulnerability_count / total_vulnerabilities) * 100
print(low_vulnerability_count_percent)
print("total_outdated_packages_percent")
total_outdated_packages_percent = (total_outdated_packages / total_packages) * 100
print(total_outdated_packages_percent)
print("total_vulnerable_packages_percent")
total_vulnerable_packages_percent = (num_of_vulnerable_packages / total_packages) * 100
print(total_vulnerable_packages_percent)
print("average risk score is: ")
print(average_risk_score)


my_labels = ["High", "Medium", "Low"]
sizes = [high_vulnerability_count_percent, medium_vulnerability_count_percent, low_vulnerability_count_percent]

plt.pie(sizes, labels = my_labels)
plt.show()

print("============= LICENSE STATS =============")
print("total_packages_with_legal_risk_percent: ")
total_packages_with_legal_risk_percent = (total_packages_with_legal_risk / total_packages) * 100
print(total_packages_with_legal_risk_percent)
print("license_high_risk_count_percent: ")
license_high_risk_count_percent = (license_high_risk_count / total_packages_with_legal_risk) * 100
print(license_high_risk_count_percent)
print("license_medium_risk_count_percent: ")
license_medium_risk_count_percent = (license_medium_risk_count / total_packages_with_legal_risk) * 100
print(license_medium_risk_count_percent)

my_labels = ["High_risk_license", "Medium_risk_license"]
sizes = [license_high_risk_count_percent, license_medium_risk_count_percent]

plt.pie(sizes, labels = my_labels)
plt.show()

now = datetime.now()
date_time = now.strftime("%m/%d/%Y, %H:%M:%S")
date_time = date_time.replace("/","_").replace(",","_").replace(":","_").replace(" ","_")
path_for_csv = path_for_scan_full_csv_stats + str(date_time) + '.csv'
print(path_for_csv)
with open(path_for_csv, mode='w') as csv_file:
    fieldnames = ['total_projects_scanned', 'total_packages', 'high_vulnerability_count', 'medium_vulnerability_count', 'low_vulnerability_count',
                  'total_vulnerabilities', 'total_outdated_packages', 'num_of_vulnerable_packages', 'total_packages_with_legal_risk', 'license_high_risk_count',
                  'license_medium_risk_count', 'total_vulnerabilities_percent', 'total_high_vulnerabilities_percent', 'total_medium_vulnerabilities_percent', 'total_low_vulnerabilities_percent',
                  'total_outdated_packages_percent', 'total_vulnerable_packages_percent', 'average risk score is', 'total_packages_with_legal_risk_percent', 'license_high_risk_count_percent', 'license_medium_risk_count_percent']
    writer = csv.DictWriter(csv_file, fieldnames=fieldnames)

    writer.writeheader()
    writer.writerow({'total_projects_scanned': total_projects_scanned, 'total_packages': total_packages, 'high_vulnerability_count': high_vulnerability_count,
    'medium_vulnerability_count': medium_vulnerability_count,'low_vulnerability_count': low_vulnerability_count,'total_vulnerabilities': total_vulnerabilities,
    'total_outdated_packages': total_outdated_packages, 'num_of_vulnerable_packages': num_of_vulnerable_packages,
    'total_packages_with_legal_risk': total_packages_with_legal_risk, 'license_high_risk_count': license_high_risk_count,
    'license_medium_risk_count': license_medium_risk_count, 'total_vulnerabilities_percent': total_vulnerabilities_percent, 'total_high_vulnerabilities_percent': high_vulnerability_count_percent,
    'total_medium_vulnerabilities_percent': medium_vulnerability_count_percent, 'total_low_vulnerabilities_percent': low_vulnerability_count_percent, 'total_outdated_packages_percent': total_outdated_packages_percent, 'total_vulnerable_packages_percent': total_vulnerable_packages_percent,
    'average risk score is': average_risk_score, 'total_packages_with_legal_risk_percent': total_packages_with_legal_risk_percent, 'license_high_risk_count_percent': license_high_risk_count_percent, 'license_medium_risk_count_percent': license_medium_risk_count_percent })

print("============= END =============")
exit()

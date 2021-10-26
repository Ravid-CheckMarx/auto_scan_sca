import os
import requests
import json
import time
import sca
from sca.project import Project

from config.conf import urls

num = '74'
# client = sca.Client(username='lumo', password=os.getenv('SCA_PASSWORD'))
total_packages = 0
high_vulnerability_count = 0
medium_vulnerability_count = 0
low_vulnerability_count = 0
risk_score = 0
total_outdated_packages = 0
num_of_vulnerable_packages = 0
total_vulnerabilities = 0

total_packages_with_legal_risk = 0
license_high_risk_count = 0
license_medium_risk_count = 0

for url in urls:
    client = sca.Client(username='lumo', password='UseTheStairs1AtaTime!')
    project = client.create_project(name='poorly_maintained_' + num)
    print("============= NEW PROJECT STARTING =============")
    print("The project name is " + 'poorly_maintained_' + num)
    print("The project id is " + project.id)
    print("this run number: "+num)
    num = int(num)+1
    print("next run number: " + str(num))
    num = str(num)

    scan_proj = project.scan_public_github_repo(url)
    print("The repo that being checked is " + url)
    print("The scan id is " + scan_proj.id)

    project = client.get_project(id=project.id)
    scans = project.scans()

    time.sleep(3)

    for scan in scans:
        if scan.id == scan_proj.id:
            scan_x = client.get_scan(id=scan.id)
            print(scan_x.status())
            status_data = scan_x.status()['name']
            print(status_data)
            time.sleep(10)
            while status_data == 'Scanning':
                time.sleep(30)
                status_data = scan_x.status()['name']
                print("30 seconds passed, the status is " + status_data)

            #if scan_x.vulnerabilities():
             #   print(scan_x.vulnerabilities())
            #else: print("No vulnerabilities found!")
            #if scan_x.licenses():
             #   print(scan_x.licenses())
            #else: print("No licenses risks found!")
            api_url = str("/risk-management/risk-reports?projectId="+project.id+"&size=1")
            print("-----------------------------------------------------------------------")
            print("The API call is: " +api_url)

            response = client.authenticated_request(api_url,'GET',None, None, None, True)
            print(response)
            url_file='C:/Users/ravidm/OneDrive - Checkmarx/Desktop/Work/Projects/SCA Top10/Poorly maintained packages - data/%s.txt'%(scan_proj.id)

            with open(url_file, 'w') as outfile:
                json.dump(response, outfile)
            print("-----------------------------------------------------------------------")

            #num_of_packages = response[0]['TotalPackages']
            #if num_of_packages:
             #   total_packages += num_of_packages
            total_packages += response[0]['totalPackages']
            high_vulnerability_count += response[0]['highVulnerabilityCount']
            medium_vulnerability_count += response[0]['mediumVulnerabilityCount']
            low_vulnerability_count += response[0]['lowVulnerabilityCount']
            risk_score += response[0]['riskScore']
            total_outdated_packages += response[0]['totalOutdatedPackages']
            num_of_vulnerable_packages += response[0]['vulnerablePackages']
            total_packages_with_legal_risk += response[0]['totalPackagesWithLegalRisk']
            license_high_risk_count += response[0]['licensesLegalRisk']['high']
            license_medium_risk_count += response[0]['licensesLegalRisk']['medium']

total_vulnerabilities += high_vulnerability_count + medium_vulnerability_count + low_vulnerability_count
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
print("============= END =============")
exit()

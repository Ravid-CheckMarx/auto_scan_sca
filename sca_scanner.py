import os
import requests
import json
import time
import sca
from sca.project import Project
from config.conf import urls
import matplotlib.pyplot as plt
import numpy as np
from config.conf import path_for_scan_reports, path_for_scan_full_csv_stats, path_for_scan_full_csv_stats_license
import csv
from datetime import datetime
#project index number for lumo - please initiate it with an index which is NOT already created!
num = '1050'

total_projects_scanned = len(urls)
#vulnerabilities counters
copyright_risk_score_1 = 0
copyright_risk_score_2 = 0
copyright_risk_score_3 = 0
copyright_risk_score_4 = 0
copyright_risk_score_5 = 0
copyright_risk_score_6 = 0
copyright_risk_score_7 = 0
referenceType_OTHER = 0
maven_counter = 0
npm_counter = 0
nuget_counter = 0
pip_counter = 0
maven_counter_high_risk = 0
npm_counter_high_risk  = 0
nuget_counter_high_risk  = 0
pip_counter_high_risk  = 0
referenceType_POM = 0
referenceType_JAR = 0
referenceType_NPM = 0
license_name_Eclipse1 = 0
license_name_Eclipse2 = 0
license_name_Eclipse_Dist1 = 0
license_name_Apache2 = 0
license_name_Apache1 = 0
license_name_MIT = 0
license_name_AGPL = 0
license_name_LGPL = 0
license_name_GPL2 = 0
license_name_GPL3 = 0
license_name_GPL_Class_Path = 0
license_name_CDDL = 0
license_name_EPL1 = 0
license_name_EPL2 = 0
license_name_Public_Domain = 0
license_name_BSD2 = 0
license_name_BSD3 = 0
license_name_MPL2 = 0
copyLeft_no = 0
copyLeft_full = 0
copyLeft_partial = 0
copyLeft_empty = 0
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
license_low_risk_count = 0
total_packages_with_legal_risk_percent = 0
license_high_risk_count_percent = 0
license_medium_risk_count_percent = 0
license_low_risk_count_percent = 0
#running on each Github project
for url in urls:
    counter_scanning = 0
    client = sca.Client(username='lumo', password=os.getenv('SCA_PASSWORD'))
    project = client.create_project(name='well_maintained_packages_license_report ' + num)
    print("============= NEW PROJECT STARTING =============")
    print("The project name is " + 'well_maintained_packages_license_report ' + num)
    print("The project id is " + project.id)
    print("this run number: "+num)
    #increasing the index by 1 for the name of the project in the next run
    num = int(num)+1
    print("next run number: " + str(num))
    num = str(num)
    #scanning the given Github url
    scan_proj = project.scan_public_github_repo(url)
    #scan_proj2 = project.scan_folder(folder_path)
    print("The repo that being checked is " + url)
    print("The scan id is " + scan_proj.id)

    project = client.get_project(id=project.id)
    scans = project.scans()

    time.sleep(3)
    #running on all scans and selecting the current scan id (which is "attached" to the project id)

    scan_x = client.get_scan(id=scans[0].id)
    #getting the status of the current scan
    print(scan_x.status())
    status_data = scan_x.status()['name']
    print(status_data)
    time.sleep(10)
    #as long as the status is scanning, we will check every 30 seconds for the status again
    while counter_scanning < 10 and (status_data == 'Scanning'):
        time.sleep(30)
        status_data = scan_x.status()['name']
        print("30 seconds passed, the status is " + status_data)
        counter_scanning += 1
        if status_data == 'Done':
            counter_scanning = 0
            api_url = str("/risk-management/risk-reports?projectId=" + project.id + "&size=1")
            print("-----------------------------------------------------------------------")
            print("The API call is: " + api_url)

            response = client.authenticated_request(api_url, 'GET', None, None, None, True)
            # printing the scan report as a JSON
            print(response)
            license_scan = scan_x.licenses()
            if scan_x.licenses():
                print(license_scan)
            else:
                print("No licenses risks found!")
            # Saving the report (the name of the report is the current scan id of that scan)
            url_file = path_for_scan_reports + '/%s.txt' % (scan_proj.id)
            print(url_file)
            with open(url_file, 'w') as outfile:
                json.dump(response, outfile)
            if scan_x.licenses():
                with open(url_file, 'w') as outfile:
                    json.dump(license_scan, outfile)

            print("-----------------------------------------------------------------------")
            # counters
            if response:
                total_packages += response[0]['totalPackages']
                high_vulnerability_count += response[0]['highVulnerabilityCount']
                medium_vulnerability_count += response[0]['mediumVulnerabilityCount']
                low_vulnerability_count += response[0]['lowVulnerabilityCount']
                # in case the risk score=0, do not add it
                if response[0]['riskScore'] != 0:
                    risk_score += response[0]['riskScore']
                    num_of_projects_with_risk_score += 1
                total_outdated_packages += response[0]['totalOutdatedPackages']
                num_of_vulnerable_packages += response[0]['vulnerablePackages']
                total_packages_with_legal_risk += response[0]['totalPackagesWithLegalRisk']
                license_high_risk_count += response[0]['licensesLegalRisk']['high']
                license_medium_risk_count += response[0]['licensesLegalRisk']['medium']
                license_low_risk_count += response[0]['licensesLegalRisk']['low']
            if license_scan:
                first_type_id = license_scan[0]['id']
                if response[0]['licensesLegalRisk']['high'] >0 or response[0]['licensesLegalRisk']['medium'] >0:
                    num_of_high_risk_packages = response[0]['licensesLegalRisk']['high'] + response[0]['licensesLegalRisk']['medium']
                    if "Pip" in first_type_id:
                            pip_counter_high_risk += num_of_high_risk_packages
                    elif "Npm" in first_type_id:
                            npm_counter_high_risk += num_of_high_risk_packages
                    elif "Maven" in first_type_id:
                            maven_counter_high_risk += num_of_high_risk_packages
                    elif "Nuget" in first_type_id:
                            nuget_counter_high_risk += num_of_high_risk_packages
                for i in range(len(license_scan)):
                    copyright_risk_score = license_scan[i]['copyrightRiskScore']
                    if license_scan[i]['copyrightRiskScore'] ==1:
                        copyright_risk_score_1 +=1
                    elif license_scan[i]['copyrightRiskScore'] ==2:
                        copyright_risk_score_2 +=1
                    elif license_scan[i]['copyrightRiskScore'] ==3:
                        copyright_risk_score_3 +=1
                    elif license_scan[i]['copyrightRiskScore'] ==4:
                        copyright_risk_score_4 +=1
                    elif license_scan[i]['copyrightRiskScore'] ==5:
                        copyright_risk_score_5 +=1
                    elif license_scan[i]['copyrightRiskScore'] ==6:
                        copyright_risk_score_6 +=1
                    elif license_scan[i]['copyrightRiskScore'] ==7:
                        copyright_risk_score_7 +=1
                    type_id = license_scan[i]['id']
                    if "Npm" in type_id:
                        npm_counter +=1
                    elif "Maven" in type_id:
                        maven_counter +=1
                    elif "Pip" in type_id:
                        pip_counter +=1
                    elif "Nuget" in type_id:
                        nuget_counter +=1
                    reference_type = license_scan[i]['referenceType']
                    if reference_type == "PomFile":
                        referenceType_POM +=1
                    elif reference_type == "Other":
                        referenceType_OTHER += 1
                    elif reference_type == "LicenseFileInJar":
                        referenceType_JAR += 1
                    elif reference_type == "Npm":
                        referenceType_NPM += 1
                    license_name = license_scan[i]['name']
                    if license_name == "Apache 2.0":
                        license_name_Apache2 +=1
                    elif license_name == "Apache 1.1":
                        license_name_Apache1 +=1
                    elif license_name == "MIT":
                        license_name_MIT +=1
                    elif license_name == "BSD 3":
                        license_name_BSD3 +=1
                    elif license_name == "BSD 2":
                        license_name_BSD2 +=1
                    elif license_name == "Eclipse Distribution 1.0":
                        license_name_Eclipse_Dist1 +=1
                    elif license_name == "Gpl ClasspathException 2.0":
                        license_name_GPL_Class_Path +=1
                    elif license_name == "Eclipse 1.0":
                        license_name_Eclipse1+=1
                    elif license_name == "Eclipse 2.0":
                        license_name_Eclipse2+=1
                    elif license_name == "GPL 2.0":
                        license_name_GPL2 += 1
                    elif license_name == "GPL 3.0":
                        license_name_GPL3 += 1
                    elif license_name == "Public Domain":
                        license_name_Public_Domain += 1
                    copyLeft = license_scan[i]['copyLeft']
                    if copyLeft == "NoCopyleft":
                        copyLeft_no +=1
                    elif copyLeft == "Full":
                        copyLeft_full +=1
                    elif copyLeft == "Partial":
                        copyLeft_partial +=1
                    elif copyLeft == "Empty":
                        copyLeft_empty +=1


        if status_data not in ('Scaning','Done'):
            print(status_data)

            # while status_data == 'Scanning':
            #     if counter_scanning < 8:
            #         print("counter scanning is: ")
            #         print(counter_scanning)
            #     if counter_scanning < 8:
            #         time.sleep(30)
            #         status_data = scan_x.status()['name']
            #         print("30 seconds passed, the status is " + status_data)
            #         if status_data == 'Scanning':
            #             counter_scanning += 1


            #use this in case you would like to present the vulnerabilities full report
            #if scan_x.vulnerabilities():
             #   print(scan_x.vulnerabilities())
            #else: print("No vulnerabilities found!")
            # use this in case you would like to present the licenses full report

            # if counter_scanning == 8:
            #     counter_scanning = 0
            # if status_data == 'Done':
            #     counter_scanning = 0
                # api_url = str("/risk-management/risk-reports?projectId="+project.id+"&size=1")
                # print("-----------------------------------------------------------------------")
                # print("The API call is: " +api_url)
                #
                # response = client.authenticated_request(api_url,'GET',None, None, None, True)
                # #printing the scan report as a JSON
                # print(response)
                # #Saving the report (the name of the report is the current scan id of that scan)
                # url_file = path_for_scan_reports + '/%s.txt'%(scan_proj.id)
                # print(url_file)
                # with open(url_file, 'w') as outfile:
                #     json.dump(response, outfile)
                # print("-----------------------------------------------------------------------")
                # #counters
                # if response:
                #     total_packages += response[0]['totalPackages']
                #     high_vulnerability_count += response[0]['highVulnerabilityCount']
                #     medium_vulnerability_count += response[0]['mediumVulnerabilityCount']
                #     low_vulnerability_count += response[0]['lowVulnerabilityCount']
                #     #in case the risk score=0, do not add it
                #     if response[0]['riskScore'] != 0:
                #         risk_score += response[0]['riskScore']
                #         num_of_projects_with_risk_score += 1
                #     total_outdated_packages += response[0]['totalOutdatedPackages']
                #     num_of_vulnerable_packages += response[0]['vulnerablePackages']
                #     total_packages_with_legal_risk += response[0]['totalPackagesWithLegalRisk']
                #     license_high_risk_count += response[0]['licensesLegalRisk']['high']
                #     license_medium_risk_count += response[0]['licensesLegalRisk']['medium']


total_vulnerabilities += high_vulnerability_count + medium_vulnerability_count + low_vulnerability_count
if num_of_projects_with_risk_score !=0:
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
print("license_low_risk_count: ")
print(license_low_risk_count)

print("============= VULNERABILITIES STATS =============")
print("total_vulnerabilities_percent")
total_vulnerabilities_percent = (total_vulnerabilities / total_packages) * 100
print(total_vulnerabilities_percent)
print("total_high_vulnerabilities_percent")
if total_vulnerabilities !=0:
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
if total_packages_with_legal_risk != 0:
    license_high_risk_count_percent = (license_high_risk_count / total_packages_with_legal_risk) * 100
    print(license_high_risk_count_percent)
    print("license_medium_risk_count_percent: ")
    license_medium_risk_count_percent = (license_medium_risk_count / total_packages_with_legal_risk) * 100
    print(license_medium_risk_count_percent)
    license_low_risk_count_percent = (license_low_risk_count / (total_packages - total_packages_with_legal_risk)) * 100
    print(license_low_risk_count_percent)

my_labels = ["High_risk_license", "Medium_risk_license"]
sizes = [license_high_risk_count_percent, license_medium_risk_count_percent]

plt.pie(sizes, labels = my_labels)
plt.show()

now = datetime.now()
date_time = now.strftime("%m/%d/%Y, %H:%M:%S")
date_time = date_time.replace("/","_").replace(",","_").replace(":","_").replace(" ","_")
path_for_csv = path_for_scan_full_csv_stats + str(date_time) + '.csv'
path_for_csv_license = path_for_scan_full_csv_stats_license + str(date_time) + '.csv'
print(path_for_csv)
print(path_for_csv_license)
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




with open(path_for_csv_license, mode='w') as csv_file:
    fieldnames = ['npm_counter_high_risk','maven_counter_high_risk','nuget_counter_high_risk','pip_counter_high_risk','npm_counter','maven_counter','nuget_counter','pip_counter', 'total_projects_scanned', 'total_packages', 'total_packages_with_legal_risk', 'license_high_risk_count',
                  'license_medium_risk_count','license_low_risk_count', 'license_low_risk_count_percent', 'total_packages_with_legal_risk_percent', 'license_high_risk_count_percent', 'license_medium_risk_count_percent', 'referenceType_POM', 'referenceType_JAR', 'license_name_Apache2', 'license_name_Apache1',
                  'license_name_Eclipse1','license_name_Eclipse2', 'license_name_Eclipse_Dist1', 'license_name_MIT', 'license_name_AGPL', 'license_name_LGPL', 'license_name_GPL2',
                    'license_name_GPL3', 'license_name_GPL_Class_Path', 'license_name_CDDL', 'license_name_EPL1', 'license_name_EPL2', 'license_name_Public_Domain', 'license_name_BSD2',
                  'license_name_BSD3', 'license_name_MPL2', 'copyLeft_no', 'copyLeft_full', 'copyLeft_partial', 'copyLeft_empty','copyright_risk_score_1','copyright_risk_score_2', 'copyright_risk_score_3','copyright_risk_score_4', 'copyright_risk_score_5','copyright_risk_score_6','copyright_risk_score_7']
    writer = csv.DictWriter(csv_file, fieldnames=fieldnames)

    writer.writeheader()
    writer.writerow({'npm_counter_high_risk':npm_counter_high_risk,'maven_counter_high_risk':maven_counter_high_risk,'nuget_counter_high_risk':nuget_counter_high_risk,'pip_counter_high_risk':pip_counter_high_risk,'npm_counter': npm_counter, 'maven_counter': maven_counter, 'nuget_counter': nuget_counter, 'pip_counter': pip_counter, 'total_projects_scanned': total_projects_scanned, 'total_packages': total_packages, 'total_packages_with_legal_risk': total_packages_with_legal_risk,
                     'license_high_risk_count': license_high_risk_count, 'license_medium_risk_count': license_medium_risk_count, 'license_low_risk_count': license_low_risk_count, 'license_low_risk_count_percent': license_low_risk_count_percent, 'total_packages_with_legal_risk_percent': total_packages_with_legal_risk_percent, 'license_high_risk_count_percent': license_high_risk_count_percent, 'license_medium_risk_count_percent': license_medium_risk_count_percent,
                     'referenceType_POM': referenceType_POM, 'referenceType_JAR': referenceType_JAR, 'license_name_Apache2': license_name_Apache2, 'license_name_Apache1': license_name_Apache1,'license_name_Eclipse1': license_name_Eclipse1,'license_name_Eclipse2': license_name_Eclipse2,
                     'license_name_Eclipse_Dist1': license_name_Eclipse_Dist1, 'license_name_MIT': license_name_MIT, 'license_name_AGPL': license_name_AGPL, 'license_name_LGPL': license_name_LGPL,
                    'license_name_GPL2': license_name_GPL2,
                    'license_name_GPL3': license_name_GPL3, 'license_name_GPL_Class_Path': license_name_GPL_Class_Path, 'license_name_CDDL': license_name_CDDL, 'license_name_EPL1': license_name_EPL1,
                    'license_name_EPL2': license_name_EPL2, 'license_name_Public_Domain': license_name_Public_Domain, 'license_name_BSD2': license_name_BSD2,
                    'license_name_BSD3': license_name_BSD3, 'license_name_MPL2': license_name_MPL2, 'copyLeft_no': copyLeft_no, 'copyLeft_full': copyLeft_full, 'copyLeft_partial': copyLeft_partial,
                    'copyLeft_empty': copyLeft_empty,'copyright_risk_score_1':copyright_risk_score_1,'copyright_risk_score_2':copyright_risk_score_2, 'copyright_risk_score_3':copyright_risk_score_3,'copyright_risk_score_4':copyright_risk_score_4, 'copyright_risk_score_5':copyright_risk_score_5,'copyright_risk_score_6':copyright_risk_score_6,'copyright_risk_score_7':copyright_risk_score_7})

print("============= END =============")
exit()

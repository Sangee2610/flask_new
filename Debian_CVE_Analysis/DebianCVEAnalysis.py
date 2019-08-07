#!/usr/bin/env python3
"""
Debian CVE Analysis Tool

Examples:
# 2017-3731 - openssl
# 2017-1000111 - CVE in 1 patches
# 2016-6786 - CVE in 2 patches
# 2014-0791 - JPMC
# 2014-0790 - JPMC Reserved CVE
"""

import requests
from bs4 import BeautifulSoup
import re
import os
from os import rename
from subprocess import call
from pydpkg import Dpkg
import paramiko
from .config import config_local as config
import getpass

__author__ = "Emil Alekperov, Hans Michel, Nathan Chan, Alex Zamyatin"
__version__ = "0.1.0"

# server = input("\nPlease enter host IP: ")
# username = input("\nPlease enter username: ")
# password = getpass.getpass(prompt="Please enter password: ")
#

# ssh.set_missing_host_key_policy(paramiko.WarningPolicy())
# ssh.connect(server, username=username, password=password)
#passed CVE variable (edited)

printOutput = []
path = config["CVE_DB_path"]

def main(cve, server, username, password):
    printOutput.clear()
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(server, username=username, password=password)
    except:
        return "Invalid Username and Password"
    cveID = getCVEnumber(cve)
    if cveID is None:
        return "Please Enter correct cveid format"
    print("cveID", cveID)
    resultSearch = searchCVE(cveID)
    print("this is resultSearch :", resultSearch)
    if resultSearch == False:
        packageName = getSourcePackageName(cveID)
        print("getSourcePackageName: ", packageName)
        if packageName is not None:
            binaries = getBinaries(packageName)
            print(" Binaries : ", binaries)
            vulnPackages = checkbinaryinpackages(binaries, ssh)
            print("vulnPackages : ", vulnPackages)
            if vulnPackages:
                vulnFixedVer = getVulnFixedVersion(cveID, ssh)
                if vulnFixedVer == 0:
                    printOutput.append('\nNo vulnerable packages found installed. CONGRATULATIONS the product is NOT vulnerable!')
                    resultCompare = 0
                elif vulnFixedVer not in (-1, 0):
                    resultCompare = compareVersions(vulnPackages, vulnFixedVer)
                elif vulnFixedVer == -1:  # there is not fix. Calculate CVSS score and attack vector
                    resultCompare = -1
                if resultCompare == -1:  # meaning the package version in the product is LOWER than the Fixed Version
                    cvss, msg = getCVSS(cveID)
                    if cvss is None:
                        return msg
                    else:
                        attackVector = getAttackVector(cveID)
                        assessScore(cvss, attackVector, cveID)
            else:
                ssh.close()
                printOutput.append('\nNo vulnerable packages found installed. CONGRATULATIONS the product is NOT vulnerable!')
                #return printOutput

    else:
        ssh.close()
        printOutput.append("\n***************************************************"+
                           "\nThe script found your security patch and has ended."+
                           "\nSee ya in the next vulnerability!"+
                           "\n***************************************************")
    return printOutput


def getREL(cveID):
    '''Searching cveID in cveDB dictionary'''
    cveDB = loadCVEdb()
    if cveID in cveDB:
        return cveDB[cveID]
    else:
        return False


def checkRELFormat(rel):

    if rel[0:4] == "REL-" and rel[4:].isdigit():
        return "goodREL"
    else:
        return "Please Check REL-XXX format"


def insertCVEnumber(cve,rel):
    cve = cve.replace('CVE-', '')
    cveID = getCVEnumber(cve)
    if cveID is None:
        return "Please check the CVE format"
    cveDbPath = os.path.join(path,'CVE_DB.txt')
    cveDict = loadCVEdb()
    if (cveID in cveDict) and (rel in cveDict[cveID]):
        return "Existing credentials"
    else:
        with open(cveDbPath, 'a') as f:
            f.write("\n" +cveID + "\t" + rel )
        return cveID + " with " + rel + " is succefully added"


def getCVEnumber(cveRawInput):
    '''Getting CVE ID from user'''
    cveInput = cveRawInput.split("-")
    print(cveRawInput,"cveInput",cveInput)
    if len(cveInput) == 2:
        try:
            int(cveInput[0])
            int(cveInput[1])
            cveID = 'CVE-' + cveInput[0] + '-' + cveInput[1]
        except (ValueError, IndexError, TypeError):
            printOutput.append("\nIncorrect format. Expected input is digits (CVE-XXXX-XXXX). Please try again.\n")
            return None
    else:
        printOutput.append("\nIncorrect format. Expected input is digits (CVE-XXXX-XXXX). Please try again.\n")
        return None
        #continue
    return cveID


def loadCVEdb():
    '''Loading CVE DB from TXT file to dict'''
    cveDbPath = os.path.join(path,'CVE_DB.txt' ) # CVE_DB text file is in current working directory
    with open(cveDbPath) as f:
        file = f.read().splitlines()
    cveDBdic = file2dict(file)
    #print("cveDict : ",cveDBdic)
    return cveDBdic


def file2dict(file):
    newDict = {}
    for line in file:
        newLine = line.split('\t')
        if newLine[0] in newDict:
            newDict[newLine[0]].append(newLine[1])
        else:
            newDict[newLine[0]] = [newLine[1]]
    return newDict


def searchCVE(cveID):
    '''Searching cveID in cveDB dictionary'''
    cveDB = loadCVEdb()
    if cveID in cveDB:
        printOutput.append("\n{} is part of patch(es) {}".format(cveID, set(cveDB[cveID])))
    else:
        printOutput.append("\n{} is not part of any patch".format(cveID))
        return False


def getSoup(url):
    headers = {'user-agent': 'my-app/0.0.1'}
    try:
        r = requests.get(url, headers=headers)
    except ConnectionError:  # need to test this
        printOutput.append('No Internet connection!!')
        quit(0)
    content = r.text
    soup = BeautifulSoup(content, 'html.parser')
    # print("soup output:", soup)
    # print("content :", content)
    return soup


def getSourcePackageName(cveID):
    url = 'https://security-tracker.debian.org/tracker/' + cveID
    soup = getSoup(url)
    print("url :", url)
    packageNameTag = soup.find('a', href=re.compile('/tracker/source-package/'))
    print('packageNameTag :,',packageNameTag)
    if packageNameTag is None:
        strMsg = ("\nSource Package was not found for one of the following reasons:\n"
                  "1. {0} is reserved.\n"
                  "2. {0} is not a Debian vulnerability.\n"
                  "3. You may have a typo.")
        printOutput.append(strMsg.format(cveID))
    else:
        packageName = packageNameTag.text.strip()
        printOutput.append('\nSource Package name is: {}'.format(packageName)+
              'for more information: {}'.format(url))
        return packageName


def getBinaries(packageName):
    '''Get binaries and creates a list'''
    url = 'https://tracker.debian.org/pkg/' + packageName
    soup = getSoup(url)
    binariesTag = soup.find_all('a', href=re.compile('packages.debian.org/unstable/'))
    #print("binariesTag :", binariesTag)
    rawBinaryName = []
    for binary in binariesTag:
        rawBinaryName.append(binary.text.strip())
    '''Removes version from binary and duplicates'''
    print("RawBinaryName : ", rawBinaryName)
    binaries = []
    for newRawBinary in rawBinaryName:
        newBinary = re.sub('\d+\.\d+', '', newRawBinary)
        binaries.append(newBinary.split('-')[0])
        binaries = list(set(binaries))  # removes duplicates
    printOutput.append('\nThe binary files based on the source package:')
    for binary in binaries:
        printOutput[len(printOutput)-1] += "\n" + binary
    printOutput[len(printOutput) - 1] += "\n"
    return binaries


def dpkg2file(ssh):
    '''FOR LINUX ONLY. Writes the output of dpkg-qeury to a file'''
    file = open(os.path.join(path,'dpkg.txt'), 'w')
    try:
        # call(['dpkg-query', '-W', '-f=${Package}\t${Version}\n'], stdout=file)  # executes Linux command
        cmd_to_execute = "dpkg-query -W"
        stdin, stdout, stderr = ssh.exec_command(cmd_to_execute)
        file.write(stdout.read().decode("utf-8"))
        file.close()
    except FileNotFoundError:
        printOutput.append('\nError: Please run this script on a Linux machine. Continue with local file.\n')


def osReleaseName(ssh):
    '''FOR LINUX ONLY. Gets Linux version name'''
    fileV = open(os.path.join(path,'versionName.txt'), 'w')
    try:
        # call(['grep', '-iw', 'version', '/etc/os-release'], stdout=fileV)
        cmd_to_execute = "grep -iw version /etc/os-release"
        stdin, stdout, stderr = ssh.exec_command(cmd_to_execute)
        fileV.write(stdout.read().decode("utf-8"))
        fileV.close()
    except FileNotFoundError:
         printOutput.append('\nError: Please run this script on a Linux machine. Continue with local file.\n')
    with open(os.path.join(path,'versionName.txt')) as f:
        line = f.readline()
    splitLine = line.split()
    osRelName = splitLine[1][1:-2]
    return osRelName


def dpkg_clean_amd64():

    dpkgFile = os.path.join(path,'dpkg.txt')  # dpkg text file is in current working directory
    tmpdpkgFile = os.path.join(path,'tmpdpkg.txt')
    with open(tmpdpkgFile, 'w') as new_file:
        with open(dpkgFile) as old_file:
            for line in old_file:
                new_file.write(line.replace(":amd64", ""))
    rename(os.path.join(path,'dpkg.txt'), os.path.join(path,'origdpkg.txt'))
    rename(os.path.join(path,'tmpdpkg.txt'), os.path.join(path,'dpkg.txt'))


def loadDpkg(ssh):
    '''Loading dpkg from TXT file'''
    dpkg2file(ssh)
    dpkg_clean_amd64()
    dpkgFile = os.path.join(path,'dpkg.txt' ) # dpkg text file is in current working directory
    with open(dpkgFile) as f:
        file = f.read().splitlines()
    dpkgdict = dpk2dict(file)
    # print("dpkgdict : ", dpkgdict)
    return dpkgdict


def dpk2dict(file):
    newDict = {}
    for line in file:
        newLine = line.split('\t')
        newDict[newLine[0]] = newLine[1]
    return newDict


def checkbinaryinpackages(binaries, ssh):
    print('\nChecking if your system contains vulnerable packages...')
    packages = loadDpkg(ssh)
    vulnPack = {}
    #binaries = ['klish'] # this is to force the program
    for package in binaries:
        if package in packages:
            vulnPack[package] = packages[package]
            printOutput.append('\nFound potential vulnerable packages in your system')
            printOutput.append('\nThe vulnerable package is "{}" version "{}"'.format(package, packages[package]))
    return vulnPack



def getVulnFixedVersion(cveID, ssh):
    url = 'https://security-tracker.debian.org/tracker/' + cveID
    soup = getSoup(url)
    osRelName = osReleaseName(ssh)
    print("osRelName : ", osRelName)
    tables = soup.find_all('table')
    print("tables :", tables)
    soup = tables[2]
    try:
        vulnFixedVer = soup.find("td", text=osRelName).find_next_sibling("td").text
        if vulnFixedVer == "(not affected)":
            printOutput.append('\nThe package "Fixed Version" is "(not affected)"'
                  'For more information: {}'.format(url))
            vulnFixedVer = 0
        else:
            printOutput.append('\nThe first version of the package that contains the fix is "{}"'.format(vulnFixedVer)+
                  'For more information: {}'.format(url))
    except AttributeError:
        printOutput.append('\nFix does NOT exist for {}!!'.format(osRelName)+
              'For more information: {}'.format(url))
        vulnFixedVer = -1
    return vulnFixedVer


def compareVersions(vulnPackages, vulnFixedVersion):
    fixedVer = vulnFixedVersion
    for ver in vulnPackages:
        #print("ver : ", ver)
        currVer = vulnPackages[ver]


    #print("currVer : ",  currVer)
    #print("fixedVer : ", fixedVer)
    compareResult = Dpkg.compare_versions(currVer, fixedVer)
    if compareResult == 0:
        printOutput.append('\nThe package version in the product is the same as the Fixed Version ==> CONGRATULATIONS the product is NOT vulnerable.')
    elif compareResult == 1:
        printOutput.append('\nThe package version in the product is higher than the Fixed Version ==> CONGRATULATIONS the product is NOT vulnerable.')
    elif compareResult == -1:
        printOutput.append('\nThe package version in the product is LOWER than the Fixed Version ==> The product is VULNERABLE!')
        return compareResult


def getCVSS(cveID):
    url = 'https://nvd.nist.gov/vuln/detail/' + cveID
    soup = getSoup(url)
    try:
        scoreTag = soup.find('span', attrs={'data-testid': 'vuln-cvssv3-base-score'})
        score = scoreTag.text.strip()
        printOutput.append('\nCVSS score is {}'.format(score)+
              'For more information: {}'.format(url))
        return float(score), None
    except AttributeError:
        message = 'CVSS does NOT exist for {}!!'.format(cveID)+'For more information: {}'.format(url)
        print(message)
        return None, message



def getAttackVector(cveID):
    url = 'https://nvd.nist.gov/vuln/detail/' + cveID
    soup = getSoup(url)
    attackVectorTag = soup.find('span', attrs={'data-testid': 'vuln-cvssv3-av'})
    attackVector = attackVectorTag.text.strip()
    printOutput.append('\nAttack Vector is {}'.format(attackVector)+
          'For more information: {}'.format(url))
    return attackVector


def assessScore(score, attackVector, cveID):
    if score < 7:
        printOutput.append('\nThe {} will be addressed in next Security Cumulative Patch.'.format(cveID))
    elif score >= 7 and attackVector == 'Local':
        printOutput.append('\nThe {} will be addressed in next Security Cumulative Patch.'.format(cveID))
    else:
        printOutput.append('\nCVSS score is {} and Attack Vector is {}. Please create a PM support request in JIRA for {}.'.format(
            score, attackVector, cveID))


if __name__ == "__main__":
    """ This is executed when run from the command line """
    main()

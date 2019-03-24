# Python 3.6.7
# https://github.com/S-S0
# Usage : python3 VT_IOC_HashCheck.py HashList.txt

import requests, time, sys

APIs = [
    "------------- Enter Here Your VirusTotal API Key -------------",
    "------------- Enter Here Your VirusTotal API Key -------------",
    "------------- Enter Here Your VirusTotal API Key -------------"
    ]
vtUrl = "https://www.virustotal.com/vtapi/v2/file/report"
VTResult = []

SecPerMin = 60
ReqPerMin = 4
sleepInterval = SecPerMin/(ReqPerMin * len(APIs))
apiLength = len(APIs)

def removeDuplicates(filePath):
    hashList = []
    with open(filePath, 'r') as f:
        for hashes in f:
            hashes = hashes.lstrip().rstrip()
            hashList.append(hashes)
    return list(set(hashList))

def processingResp(resp, hashValue):
    if resp.status_code is 200:
        # JSON response parsing
        # "response_code" is 1 and "positives" > 0 -> Malware
        # "response_code" is 1 and "positives" = 0 -> Clean
        # "response_code" is 0                     -> No Matches
        resp = resp.json()
        if resp['response_code'] is 0: 
            VTResult.append([hashValue, 'No_Matches'])
        elif resp['response_code'] is 1 and resp['positives'] > 0:
            VTResult.append([hashValue, 'Malware'])
        elif resp['response_code'] is 1 and resp['positives'] is 0:
            VTResult.append([hashValue, 'Clean'])
        else:
            VTResult.append([hashValue, 'ERROR!'])
    elif resp.status_code is 400:
        VTResult.append([hashValue, 'HTTP Response 400 (BAD args)'])
    else:
        VTResult.append([hashValue, "HTTP Response %s" % resp.status_code])

def printResult():
    for i in VTResult:
        print(i[0], i[1])

def searchRequest(APIKey, Hash):
    params = {'apikey': APIKey, 'resource': Hash}
    try:
        response = requests.get(vtUrl, params=params)
        if response.status_code is 204:
            while True:
                time.sleep(sleepInterval)
                response = requests.get(vtUrl, params=params)
                if response.status_code is not 204:
                    break
        processingResp(response, Hash)
    except:
        print("Requests Error")
    
def main(hashListFile):
    hashList = removeDuplicates(hashListFile)
    apiIndex = 0
    for hashValue in hashList:
        apiIndex = (apiIndex + 1) % apiLength
        searchRequest(APIs[apiIndex], hashValue)
        time.sleep(sleepInterval)
    printResult()

if __name__ == "__main__":
    main(sys.argv[1])

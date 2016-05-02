import hashlib
import traceback
from bottle import request, route, static_file, run, BaseRequest
from pymongo import MongoClient
from ConfigParser import SafeConfigParser
import os
import platform
import sys
import unirest
import virustotal
import json
import logging
from bson import json_util

@route('/success', method='GET')
def get_success():
    logging.info('Sanity test')
    return "Success!!"

@route('/uploadApk', method='POST')
def do_upload():

        #Config reading
    # if platform.system().lower() == "windows":
    #     db_config_file = os.path.join(os.path.dirname(sys.executable), 'androbugs-db.cfg')
    # else:
    #     db_config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'androbugs-db.cfg')
    #
    # if not os.path.isfile(db_config_file):
    #     print("[ERROR] AndroBugs Framework DB config file not found: " + db_config_file)
    #     traceback.print_exc()
    #
    # configParser = SafeConfigParser()
    # configParser.read(db_config_file)

    # save_path=configParser.get('General_Config', 'FilePath')
    logging.info("Starting upload method")
    logging.info(request.__sizeof__())
    directory = os.getcwd() +"/Download/"
    if not os.path.exists(directory):
        os.makedirs(directory)

    save_path = directory
    #logging.info(request._get_body_string())
    #upload = request.body.get('upload')

    upload = request.files.get('upload')
    preference = request.forms.get('preference')

    logging.info("File received for upload is"+upload.filename)
    #logging.info("Through data"+data.filename)
    name, ext = os.path.splitext(upload.filename)
    if ext not in ('.apk'):
        return "File extension not allowed."

    if not os.path.exists(save_path):
        os.makedirs(save_path)

    file_path = "{path}/{file}".format(path=save_path, file=upload.filename)
    if(os.path.isfile(file_path)):
        os.remove(file_path)
    upload.save(file_path)
    logging.info("File successfully saved to '{0}'.".format(save_path))
    logging.info("Get report of: "+upload.filename)
    return callAnalyseApk(upload.filename,preference)

@route('/downloadApk', method='POST')
def callDownloadApk():
    '''
    url triming
    url = request._get_body_string().split('=')
    requestBody= url[1]
    :return:
    '''

    #Setting timeout as unirest calls get timed out because analysis takes time
    unirest.timeout(600000)
    #requestBody = request._get_body_string()
    preference = request.forms.get('preference')
    requestBody=request.forms.get('packageName')

    # #Config reading
    # if platform.system().lower() == "windows":
    #     db_config_file = os.path.join(os.path.dirname(sys.executable), 'androbugs-db.cfg')
    # else:
    #     db_config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'androbugs-db.cfg')
    #
    # if not os.path.isfile(db_config_file):
    #     print("[ERROR] AndroBugs Framework DB config file not found: " + db_config_file)
    #     traceback.print_exc()
    #
    # configParser = SafeConfigParser()
    # configParser.read(db_config_file)

    # downloadPath=configParser.get('General_Config', 'DownloadSciptPath')
    directory = os.getcwd() +"/Download/"
    if not os.path.exists(directory):
        os.makedirs(directory)
    downloadPath = os.getcwd() + "/googleplay-api/"

    #Calling the download apk method
    cmd = 'python '+downloadPath+'download.py ' + requestBody
    logging.info("cmd is: "+cmd)
    os.system(cmd)
    #responseBase = unirest.post("http://localhost:8080/analyseApk", headers={ "Accept": "application/json" },
                                       #body={requestBody})
    return callAnalyseApk(requestBody+".apk",preference)

@route('/analyseApk', method='POST')
def callAnalyseApk(requestBody,preference):

    logging.info("Started scanning.......")

    if platform.system().lower() == "windows":
        db_config_file = os.path.join(os.path.dirname(sys.executable), 'androbugs-db.cfg')
    else:
        db_config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'androbugs-db.cfg')

    if not os.path.isfile(db_config_file):
        logging.info("[ERROR] AndroBugs Framework DB config file not found: " + db_config_file)
        traceback.print_exc()

    configParser = SafeConfigParser()
    configParser.read(db_config_file)

    # filePath=configParser.get('General_Config', 'FilePath')
    filePath = os.getcwd() +"/Download/"
    logging.info("File path is: "+filePath)
    MongoDB_Hostname = configParser.get('DB_Config', 'MongoDB_Hostname')
    MongoDB_Database = configParser.get('DB_Config', 'MongoDB_Database')
    Collection_Analyze_Success_Results = configParser.get('DB_Collections', 'Collection_Analyze_Success_Results')

    client = MongoClient(MongoDB_Hostname)
    db = client[MongoDB_Database]
    collection_AppInfo = db[Collection_Analyze_Success_Results]
    logging.info("Trying"+filePath+requestBody)
    with open(filePath+requestBody) as f:
        data = f.read()
        file_sha256 = hashlib.sha256(data).hexdigest()
    cursor = collection_AppInfo.find({"file_sha256": file_sha256})

    if cursor.count() == 0:
        cmd = 'python androbugs.py -s -f ' + filePath+ requestBody
        logging.info('Executing: '+cmd)
        os.system(cmd)
    else:
        logging.info( "Record already exist")

    return buildResult(file_sha256,db,filePath+requestBody,preference)
    #return "Success"



def buildResult(apkFingerprint,db,apkPath,preference):
    #permission list from user
    userPreferences = preference
    userPreferenceArr = ["android.permission.INTERNET"];

    # API KEY for virus total
    #1adad59c01c25eaf3b3f2435c09c3ae253c9b81f2f156682c1fe81790223c584

    #Mongo db connection
    #client = MongoClient("mongodb://secureVaultAdmin:root@ds013971.mlab.com:13971/secure-vault-db?authMechanism=SCRAM-SHA-1")
    #db = client["secure-vault-db"]
    coll = db["AnalyzeSuccessResults"];

    #APK to be scanned
    #apkFingerprint = '2fd01b373e6ea2e151fdc44be369999c4483e5248cd733f617313f0eba7cbaf2'

    #Get scan results from Virus total public API
    statinfo = os.stat(apkPath)
    statinfo = statinfo.st_size
    is_file_virus_scan_enable = statinfo < 25165824
    logging.info("File enabled for virus scan",is_file_virus_scan_enable )

    if is_file_virus_scan_enable:
        v = virustotal.VirusTotal('1adad59c01c25eaf3b3f2435c09c3ae253c9b81f2f156682c1fe81790223c584');
        #virusTotalReportJSON = v.scan(apkFingerprint)
        #virusTotalReportJSON = v.scan("/home/voldy/Desktop/transit.apk")
        logging.info("Getting virus total information of apk from apk path"+apkPath)
        print apkPath
        virusTotalReportJSON = v.scan(apkPath)

        scanCompareResults = virusTotalReportJSON._report['scans']

        #update the virus total scan results in database
        updateResult = db.AnalyzeSuccessResults.update_one(
           {"file_sha256": apkFingerprint},
          {"$set": {"scanCompareResults": scanCompareResults}}
        )

    #fetch scan result from mongoDB
    logging.info("Fetch results from mongoDB with fingerprint"+apkFingerprint)
    analyzeSuccessResultsCollection = db.AnalyzeSuccessResults.find({'file_sha256': apkFingerprint});

    logging.info( "Count of result retrieved from mongodb is: ",analyzeSuccessResultsCollection.count())
    json_docs = [json.dumps(doc, default=json_util.default) for doc in analyzeSuccessResultsCollection]

    #logging.info( "Json docs count: "+json_docs.count())
    tempJson = json_docs[0]
    jsonObject = json.loads(tempJson)

    #add scanCompare results to main result object
    #jsonObject['scanCompareResults'] = scanCompareResults
    #jsonObject = addPreferenceResults(jsonObject,userPreferences)
    jsonObject = addPreferenceResults(jsonObject,userPreferences)
    threatQ = calculateThreatQ(jsonObject,userPreferenceArr)
    jsonObject['threatQ'] = threatQ

    return jsonObject

def addPreferenceResults(jsonObject,userPreferences) :

    logging.info(" ************ Started Adding user preferences to result ************************")

    # Constant Preferences

    CALENDER = "CALENDAR"
    CAMERA = "CAMERA"
    SENSORS = "SENSORS"
    CONTACTS = "CONTACTS"
    LOCATION = "LOCATION"
    MICROPHONE = "MICROPHONE"
    PHONE = "PHONE"
    SMS = "SMS"
    STORAGE = "STORAGE"

    # populating Permission Group Set

    # Calender
    calenderSet = set()
    calenderSet.add("android.permission.READ_CALENDAR")
    calenderSet.add("android.permission.WRITE_CALENDAR")

    # Camera
    cameraSet = set(["android.permission.CAMERA"])

    # SENSORS
    sensorSet = set()
    sensorSet.add("android.permission.BODY_SENSORS")
    sensorSet.add("android.permission.USE_FINGERPRINT")

    # CONTACTS
    contactSet = set()
    contactSet.add("android.permission.READ_CONTACTS")
    contactSet.add("android.permission.WRITE_CONTACTS")
    contactSet.add("android.permission.GET_ACCOUNTS")

    # LOCATION
    locationSet = set()
    locationSet.add("android.permission.ACCESS_FINE_LOCATION")
    locationSet.add("android.permission.ACCESS_FINE_LOCATION")
    locationSet.add("android.permission.ACCESS_COARSE_LOCATION")
    locationSet.add("android.permission.ACCESS_LOCATION_EXTRA_COMMANDS")
    locationSet.add("android.permission.INSTALL_LOCATION_PROVIDER")
    locationSet.add("android.permission.ACCESS_MOCK_LOCATION")
    locationSet.add("android.permission.CONTROL_LOCATION_UPDATES")

    # MICROPHONE
    microphoneSet = set(["android.permission.RECORD_AUDIO"])

    # PHONE
    phoneSet = set()
    phoneSet.add("android.permission.READ_PHONE_STATE")
    phoneSet.add("android.permission.CALL_PHONE")
    phoneSet.add("android.permission.ACCESS_IMS_CALL_SERVICE")
    phoneSet.add("android.permission.READ_CALL_LOG")
    phoneSet.add("android.permission.WRITE_CALL_LOG")
    phoneSet.add("com.android.voicemail.permission.ADD_VOICEMAIL")
    phoneSet.add("android.permission.USE_SIP")
    phoneSet.add("android.permission.PROCESS_OUTGOING_CALLS")
    phoneSet.add("android.permission.MODIFY_PHONE_STATE")
    phoneSet.add("android.permission.READ_PRECISE_PHONE_STATE")
    phoneSet.add("android.permission.READ_PRIVILEGED_PHONE_STATE")
    phoneSet.add("android.permission.REGISTER_SIM_SUBSCRIPTION")
    phoneSet.add("android.permission.REGISTER_CALL_PROVIDER")
    phoneSet.add("android.permission.REGISTER_CONNECTION_MANAGER")
    phoneSet.add("android.permission.BIND_INCALL_SERVICE")
    phoneSet.add("android.permission.BIND_CONNECTION_SERVICE")
    phoneSet.add("android.permission.BIND_TELECOM_CONNECTION_SERVICE")
    phoneSet.add("android.permission.CONTROL_INCALL_EXPERIENCE")
    phoneSet.add("android.permission.RECEIVE_STK_COMMANDS")

    # SMS
    smsSet = set()
    smsSet.add("android.permission.SEND_SMS")
    smsSet.add("android.permission.RECEIVE_SMS")
    smsSet.add("android.permission.READ_SMS")
    smsSet.add("android.permission.RECEIVE_WAP_PUSH")
    smsSet.add("android.permission.RECEIVE_MMS")
    smsSet.add("android.permission.READ_CELL_BROADCASTS")
    smsSet.add("android.permission.WRITE_SMS")
    smsSet.add("android.permission.CARRIER_FILTER_SMS")
    smsSet.add("android.permission.BROADCAST_SMS")

    # STORAGE
    storageSet = set()
    storageSet.add("android.permission.READ_EXTERNAL_STORAGE")
    storageSet.add("android.permission.WRITE_EXTERNAL_STORAGE")
    storageSet.add("android.permission.WRITE_MEDIA_STORAGE")
    storageSet.add("android.permission.ACCESS_KEYGUARD_SECURE_STORAGE")
    storageSet.add("android.permission.MOUNT_UNMOUNT_FILESYSTEMS")
    storageSet.add("android.permission.MOUNT_FORMAT_FILESYSTEMS")

    # populating Permissions to Preference Map

    categoryPermissionsMap = {
                                CALENDER: calenderSet,
                                CAMERA: cameraSet,
                                SENSORS: sensorSet,
                                CONTACTS: contactSet,
                                LOCATION: locationSet,
                                MICROPHONE: microphoneSet,
                                PHONE: phoneSet,
                                SMS: smsSet,
                                STORAGE: storageSet
                            }

    # fetch application permissions array from json
    applicationPermissionArr = jsonObject['permission']
    logging.info("Permission Used" , applicationPermissionArr)
    applicationPermissionSet = set(applicationPermissionArr)

    # build preference array from comma separated user Prefeerence
    preferences = userPreferences.split(",")
    logging.info("User preferences received : " , preferences)

    # flag to determine if preferences are violated
    isPreferenceViolated = False

    # list for preferences violated
    violatedPreferenceList = []

    # list for preferences adhered
    adheredPreferenceList = []

    for preference in preferences:
        preferencePermissions = categoryPermissionsMap[preference]
        preferencePermissionViolatedSet = set(preferencePermissions).intersection(applicationPermissionSet)
        if (len(preferencePermissionViolatedSet) > 0):
            violatedPreferenceList.append(preference)
            isPreferenceViolated = True
        else:
            adheredPreferenceList.append(preference)


    # adding violated preference to json
    jsonObject['violatedPreferenceList'] = violatedPreferenceList
    logging.info("Violated Preferences added to result : " , violatedPreferenceList)

    # adding adhered preferences to json
    jsonObject['adheredPreferenceList'] = adheredPreferenceList
    logging.info("Adhered preferences added to result : " , adheredPreferenceList)

    # adding whether preferences are violated
    jsonObject['isPreferenceViolated']  = isPreferenceViolated
    logging.info("isPreferenceViolated added to result as : " , isPreferenceViolated)

    #jsonWithPreferenceInformation = json.dumps(jsonObject)

    logging.info(" ************ User Preferences added to result json ******************************")

    return  jsonObject

def calculateThreatQ(jsonObject,userPreferenceArr):

    #fetch critical vectors array
    criticalVectorArray  = jsonObject['critical_vectors']
    warningVectorArray = jsonObject['warning_vectors']

    #fetch application permissions array from json
    applicationPermissionArr = jsonObject['permission']
    applicationPermissionSet = set(applicationPermissionArr)

    #give priority to userPreferences, check against application permissions
    isPreferenceViolated = jsonObject['isPreferenceViolated']


    #intersectionSet = set(applicationPermissionArr).intersection(userPreferenceArr)
    if(isPreferenceViolated):
        result = "RED"
    else:
        #check for critical and warnings
        if(len(criticalVectorArray) >=3 ):
            result = "RED"
        else:
            if(warningVectorArray.len >= 3):
                result = "AMBER"
            else:
                result ="GREEN"

    return result

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, filename="logfile", filemode="a+",
                        format="%(asctime)-15s %(levelname)-8s %(message)s")
    logging.info("hello")
    BaseRequest.MEMFILE_MAX =  41943040
    run(host='0.0.0.0', port=8081)

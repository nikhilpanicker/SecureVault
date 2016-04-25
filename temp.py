import json

__author__ = 'nikhil'

def readFile(fileName):
    url = fileName.split('=')
    print url[1]

def parseInfo(item):
    data = json.loads(item)
    data["base"]="Hello"
    print data["base"]
    #return data['clientChannel']

def jsonClss(item):
    #print item['base']
    parseInfo(item)
    #print item['base']

data = { 'base': 'Tortilla/Bowl' }
data = json.dumps(data)
jsonClss(data)
data = json.loads(data)
print data['base']
#readFile("https://play.google.com/store/apps/details?id=com.redphx.deviceid")
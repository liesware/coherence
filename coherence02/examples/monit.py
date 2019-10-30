import requests
import json
import os,binascii

from sending import sending

data_js='{"version":1,"algorithm":"MONIT","operation":"status"}'
sending(data_js)

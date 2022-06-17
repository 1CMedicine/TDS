# -*- coding: utf-8 -*-
import os
import os.path
import sys
import uuid
import tempfile, shutil
import sqlite3
from io import StringIO
import json
from collections import OrderedDict
import time
import datetime
import base64
import requests

local_path = os.path.split(__file__)[0]
if local_path not in sys.path:
    sys.path.insert(0, local_path)

import prefs

CONFIG_NAMES = []
for name in prefs.CONFIGS:
    CONFIG_NAMES.append(name)

def read(environ):
    length = int(environ.get('CONTENT_LENGTH', 0))
    stream = environ['wsgi.input']
    body = tempfile.NamedTemporaryFile(mode='w+b')
    while length > 0:
        part = stream.read(min(length, 1024*200)) # 200KB buffer size
        if not part: break
        body.write(part)
        length -= len(part)
    body.seek(0)
    environ['wsgi.input'] = body
    return body


def application(environ, start_response):
    # /CVS/Hello/{ТикетИТС}
    url = environ['PATH_INFO'].split('/')
    if len(url) == 4 and url[1] == 'CVS' and url[2] == 'Hello':
        output = StringIO()

        # проверить тикет
        response = None
        login = ""
        if prefs.CHECK_ITS_USER:
            r = requests.post("https://login.1c.ru/rest/public/ticket/check", json={'ticket':url[3],'serviceNick':'informed'})
            if r.status_code == 403:
                start_response('401 Unauthorized', [('Content-Type', 'text/plain; charset=utf-8')])
                return ['Не указана действующая подписка на ИТС'.encode('UTF-8')]
            if r.status_code != 200:
                raise Exception("Error in login.1c.ru: " + str(r.status_code) + " " + r.reason+ " ticket " + url[3])
            response = r.json()
            login = response["login"]

        # создаем сессию
        t = round(time.time())  + 959    # время жизни сессии - 16 мин
        sid = str(uuid.uuid4())
        conn = sqlite3.connect(prefs.DATA_PATH+"/templates.db")
        cur = conn.cursor()
        cur.execute("insert into session values (?,?,?,?)", (sid, str(t), url[3], login))
        cur.close()
        conn.commit()
        conn.close()

        ret = sid.encode('UTF-8')
        start_response('200 OK', [
            ('Content-Type', 'application/json; charset=utf-8'),
            ('Content-Length', str(len(ret)))
        ])
        return [ret]

    # /CVS/MDT/{УидСессии}/{ИмяМетода}
    if len(url) == 5 and url[1] == 'CVS' and url[2] == 'MDT':

        # проверяем сессию
        conn = sqlite3.connect(prefs.DATA_PATH+"/templates.db")
        conn.execute("PRAGMA foreign_keys=OFF;")
        t = round(time.time())
        cur = conn.cursor()
        cur.execute("delete from session where tillDate<?", (str(t),))
        cur.close()
        conn.commit()

        cur = conn.cursor()
        cur.execute("select rowid from session where uuid=?", (url[3],))
        session = cur.fetchone()
        cur.close()

        if session is None: 
            conn.close()
            start_response('401 Unauthorized', [('Content-Type', 'text/plain; charset=utf-8')])
            return [("Нет активной сессии").encode('UTF-8')]

        found = False
        output = StringIO(initial_value='')
        if url[4] == 'GetList':
            found = True
            length = int(environ.get('CONTENT_LENGTH', '0'))
            params = environ['wsgi.input'].read(length).decode('utf-8')
            params_json = json.loads(params)
            configName = params_json['#value'][0]['Value']['#value']
            configVersion = params_json['#value'][1]['Value']['#value']

            cur = conn.cursor()
            cur.execute("select * from template where configName=? and configVersion=?", (configName, configVersion))

            print('{"#value": [', sep='', file=output)
            start = True
            for r in cur.fetchall():
                if start:
                    start = False
                else:
                    print(',', sep='', file=output)

                print('''{
"#type": "jv8:Structure",
"#value": [
{
"name": {
"#type": "jxs:string",
"#value": "УИДШМД"
},
"Value": {
"#type": "jv8:UUID",
"#value": "''',r[7], '''"
}
},
{
"name": {
"#type": "jxs:string",
"#value": "Идентификатор"
},
"Value": {
"#type": "jxs:string",
"#value": "''',r[2], '''"
}
},
{
"name": {
"#type": "jxs:string",
"#value": "КонтрольнаяСумма"
},
"Value": {
"#type": "jxs:string",
"#value": "''',r[4], '''"
}
},
{
"name": {
"#type": "jxs:string",
"#value": "ТипМДCode"
},
"Value": {
"#type": "jxs:string",
"#value": "''',r[5], '''"
}
},
{
"name": {
"#type": "jxs:string",
"#value": "ТипМДCodeSystem"
},
"Value": {
"#type": "jxs:string",
"#value": "''',r[6], '''"
}
},
{
"name": {
"#type": "jxs:string",
"#value": "ТипРЭМДCode"
},
"Value": {
"#type": "jxs:string",
"#value": "''',r[9], '''"
}
},
{
"name": {
"#type": "jxs:string",
"#value": "ТипРЭМДCodeSystem"
},
"Value": {
"#type": "jxs:string",
"#value": "''',r[10], '''"
}
},
{
"name": {
"#type": "jxs:string",
"#value": "Автор"
},
"Value": {
"#type": "jxs:string",
"#value": "''',r[12], '''"
}
},
{
"name": {
"#type": "jxs:string",
"#value": "ДатаЗагрузки"
},
"Value": {
"#type": "jxs:string",
"#value": "''',r[13], '''"
}
},
{
"name": {
"#type": "jxs:string",
"#value": "ОписаниеШМД"
},
"Value": {"#type": "jv8:Structure",
"#value":''', r[8], '''
}
},
{
"name": {
"#type": "jxs:string",
"#value": "ИмяФайла"
},
"Value": {
"#type": "jxs:string",
"#value": "''',r[3], '''"
}
},
{
"name": {
"#type": "jxs:string",
"#value": "СоздаватьНовуюВерсию"
},
"Value": {
"#type": "jxs:boolean",
"#value": ''',r[11], '''
}
}
]
}''', sep='', end='', file=output)

            cur.close()
            print(']}', sep='', file=output)


        elif url[4] == 'GetFile':
            found = True
            length = int(environ.get('CONTENT_LENGTH', '0'))
            params = environ['wsgi.input'].read(length).decode('utf-8')
            params_json = json.loads(params)
            UUIDTemplate = params_json['#value'][0]['Value']['#value']
            cur = conn.cursor()
            cur.execute("select fileName from template where UUIDTemplate=?", (UUIDTemplate,))
            fileName = cur.fetchone()
            cur.close()

            if fileName is None:
                conn.close()
                raise "File with uuid="+UUIDTemplate+" not found"

            print('{"#type": "jxs:string", "#value": "', sep='', end='', file=output)
            file = open(prefs.DATA_PATH+'/'+UUIDTemplate+"_"+fileName[0], "rb")
            print(base64.b64encode(file.read()).decode('ascii'), sep='', end='', file=output)
            file.close()
            print('"}', sep='', end='', file=output)


        elif url[4] == 'UploadFile':
            found = True
            cur = conn.cursor()
            cur.execute("select itsLogin from session where uuid=?", (url[3],))
            itsLogin = cur.fetchone()
            cur.close()

            if itsLogin is None:
                conn.close()
                start_response('401 Unauthorized', [('Content-Type', 'text/plain; charset=utf-8')])
                return [("Нет активной сессии").encode('UTF-8')]

            if itsLogin[0] not in prefs.VALID_ITS_USERS:
                conn.close()
                start_response('401 Unauthorized', [('Content-Type', 'text/plain; charset=utf-8')])
                return [("У пользователя '"+itsLogin[0]+"' нет прав на загрузку файлов").encode('UTF-8')]

            decoder = json.JSONDecoder(object_pairs_hook=OrderedDict)
            file = read(environ)
            f = open(file.name, "r")
            js = f.read()
            params = decoder.decode(js)
            f.close()

            params = params['#value']
            t = {}
            t["UUIDTemplate"] = str(uuid.uuid4())
            t["createNewVersion"] = 'false'     # в текущей версии не передается
            for p in params:
                if p["name"]["#value"] == "Идентификатор":
                    t["id"] = p["Value"]["#value"]
                elif  p["name"]["#value"] == "Конфигурация":
                    t["configName"] = p["Value"]["#value"]
                elif  p["name"]["#value"] == "Версия":
                    t["configVersion"] = p["Value"]["#value"]
                elif  p["name"]["#value"] == "КонтрольнаяСумма":
                    t["checkSum"] = p["Value"]["#value"]
                elif  p["name"]["#value"] == "ТипМДCodeSystem":
                    t["typeMDCodeSystem"] = p["Value"]["#value"]
                elif  p["name"]["#value"] == "ТипМДCode":
                    t["typeMDCode"] = p["Value"]["#value"]
                elif  p["name"]["#value"] == "ТипРЭМДCodeSystem":
                    t["typeREMDCodeSystem"] = p["Value"]["#value"]
                elif  p["name"]["#value"] == "ТипРЭМДCode":
                    t["typeREMDCode"] = p["Value"]["#value"]
                elif  p["name"]["#value"] == "ОписаниеШМД":
                    t["TemplateDesc"] = p["Value"]["#value"]
                elif  p["name"]["#value"] == "ИмяФайлаСРаширением":
                    t["fileName"] = p["Value"]["#value"]
                elif  p["name"]["#value"] == "СоздаватьНовуюВерсию":
                    t["createNewVersion"] = p["Value"]["#value"]
                elif  p["name"]["#value"] == "ДДанные":
                    t["ДДанные"] = p["Value"]["#value"]

            needUpload = False
            if t['configName'] in prefs.CONFIGS:
                for ver in prefs.CONFIGS[t['configName']][0]:
                    if ver == t['configVersion'][:len(ver)]:
                        needUpload = True
                        break

            if not needUpload:
                conn.close()
                start_response('403 FORBIDDEN', [('Content-Type', 'text/plain; charset=utf-8')])
                return ['Не поддерживаемая конфигурация или версия конфигурации'.encode('UTF-8')]

            cur = conn.cursor()
            cur.execute("delete from template where configName=? and configVersion=? and id=?", (t["configName"], t["configVersion"], t["id"]))
            cur.close()

            cur = conn.cursor()
            i = (t["configName"], t["configVersion"], t["id"], t["fileName"], t["checkSum"], t["typeMDCode"], t["typeMDCodeSystem"], t["UUIDTemplate"], json.dumps(t["TemplateDesc"]), t["typeREMDCode"], t["typeREMDCodeSystem"], t["createNewVersion"], itsLogin[0], datetime.datetime.now().isoformat())
            SQLPacket = "insert into template values (?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
            cur.execute(SQLPacket, i)
            cur.close()
            conn.commit()

            file = open(prefs.DATA_PATH+'/'+t["UUIDTemplate"]+"_"+t["fileName"], "wb")
            file.write(base64.b64decode(t["ДДанные"]))
            file.close()

        elif url[4] == 'DeleteFile':
            found = True
            cur = conn.cursor()
            SQLPacket = "select itsLogin from session where uuid='"+url[3]+"'"
            cur.execute(SQLPacket)
            itsLogin = cur.fetchone()
            cur.close()

            if itsLogin is None:
                conn.close()
                start_response('401 Unauthorized', [('Content-Type', 'text/plain; charset=utf-8')])
                return [("Нет активной сессии").encode('UTF-8')]

            if itsLogin[0] not in prefs.VALID_ITS_USERS:
                conn.close()
                start_response('401 Unauthorized', [('Content-Type', 'text/plain; charset=utf-8')])
                return [("У пользователя '"+itsLogin[0]+"' нет прав на удаление файлов").encode('UTF-8')]

            length = int(environ.get('CONTENT_LENGTH', '0'))
            params = environ['wsgi.input'].read(length).decode('utf-8')
            params_json = json.loads(params)
            UUIDTemplate = params_json['#value'][0]['Value']['#value']

            cur = conn.cursor()
            cur.execute("select fileName from template where UUIDTemplate=?", (UUIDTemplate,))
            fileName = cur.fetchone()
            cur.close()

            if fileName is None:
                conn.close()
                raise "File with uuid="+UUIDTemplate+" not found"

            os.remove(prefs.DATA_PATH+"/"+UUIDTemplate+"_"+fileName[0])
            cur = conn.cursor()
            cur.execute("delete from template where UUIDTemplate=?", (UUIDTemplate,))
            cur.close()
            conn.commit()
        conn.close()

        if found:
            ret = output.getvalue().encode('UTF-8')
            start_response('200 OK', [
                ('Content-Type', 'application/json; charset=utf-8'),
                ('Content-Length', str(len(ret)))
            ])
            return [ret]

    else:
        start_response('404 Not Found', [('Content-Type','text/html; charset=utf-8')])
        return [b'<p>Page Not Found</p>'+environ['PATH_INFO'].encode('UTF-8')+b'\n']


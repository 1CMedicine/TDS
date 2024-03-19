# -*- coding: utf-8 -*-
import os
import os.path
import sys
import uuid
import tempfile, shutil
import sqlite3
from io import StringIO
import json
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
CONFIG_NAMES.sort()

CONFIG_VERSIONS = []
for name in prefs.CONFIGS:
    CONFIG_VERSIONS = list(set().union(CONFIG_VERSIONS, prefs.CONFIGS[name]))
CONFIG_VERSIONS.sort()

CONFIG_VERSIONS_IDX = {}
for name in CONFIG_NAMES:
    vers = prefs.CONFIGS[name]
    for i in range(0, len(vers)):
        CONFIG_VERSIONS_IDX[name+"_"+vers[i]] = i

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

def loadFNSIref(conn, oid, table, environ) :
    if prefs.FNSI_userkey is None or len(prefs.FNSI_userkey) == 0 :
        return

    cursor = conn.cursor()
    cursor.execute("delete from fnsi_"+table)
    cursor.close()

    r = requests.get('https://nsi.rosminzdrav.ru:443/port/rest/passport',
        params = {'userKey': prefs.FNSI_userkey, 'identifier': oid},
        headers = {'Accept': 'application/json'}
    )
    passport = r.json()

    c = int((passport["rowsCount"]-1)/200)+1
    for page in range(1, c+1) :
        r = requests.get('https://nsi.rosminzdrav.ru:443/port/rest/data',
            params = {'userKey': prefs.FNSI_userkey, 'identifier': oid, 'page': page, 'size':200},
            headers = {'Accept': 'application/json'}
        )
        try :
            data = r.json()
        except Exception as e:
            print(r, sep=' ', end='', file=environ["wsgi.errors"])
            raise

        for psObject in data["list"] :
            code = None
            name = None
            for obj in psObject :
                if obj["column"].upper() == 'NAME' :
                    name = obj["value"]
                elif obj["column"] == "RECID" or obj["column"] == "ID":
                    code = obj["value"]

            cursor = conn.cursor()
            cursor.execute("insert into fnsi_"+table+" values (?,?,?)", (code, oid, name))
            cursor.close()

    conn.commit()

def escapeHTML(line) :
    return line.strip().replace(">", "&#62;").replace("<", "&#60;").replace("\"", "&#34;").replace('\n', "<br>").replace('\t', "&#9;").replace("'", "&apos;").replace('\\', "&#92;")

def escapeJSON(line) :
    return line.strip().replace("\"", "\\\"").replace('\n', "\\n").replace('\t', "\\t").replace('\\', "\\")

def application(environ, start_response):
    # /CVS/Hello/{ТикетИТС}
    url = environ['PATH_INFO'].split('/')

    if environ['PATH_INFO'] == '/style.css':
        style=b'''
table {
    display: table;
    border-collapse: separate;
    box-sizing: border-box;
    white-space: normal;
    line-height: normal;
    font-weight: normal;
    font-size: small;
    font-style: normal;
    color: -internal-quirk-inherit;
    text-align: start;
    border: 1px outset;
    border-spacing: 0px;
    border-color: grey;
    font-variant: normal;
    font-family: Verdana, Tahoma, Arial, sans-serif;
}
p  {
    font-family: Verdana, Tahoma, Arial, sans-serif;
    contain: content;
}
.deleted {
    background-color: rgb(255,150,150) !important;
}
.added {
    background-color: rgb(150,255,150) !important;
}
'''
        start_response('200 OK', [
            ('Content-Type', 'text/css; charset=utf-8'),
            ('Content-Length', str(len(style)))
        ])
        return [style]

    if environ['PATH_INFO'] == '/tables.js':
        output = StringIO()
        print('''function selectConfig(configName) {
    if (configName != 'sn')
        document.location.href="''', prefs.SITE_URL, '''/getFullTemplatesList/"+configName.substring(1)
    else
        document.location.href="''', prefs.SITE_URL, '''/getFullTemplatesList"
}''', sep='', file=output)

        ret = output.getvalue().encode('UTF-8')
        start_response('200 OK', [
            ('Content-Type', 'text/html; charset=utf-8'),
            ('Content-Length', str(len(ret)))
        ])
        return [ret]


    if len(url) == 4 and url[1] == 'CVS' and url[2] == 'Hello':
        output = StringIO()

        # проверить тикет
        response = None
        login = ""
        if prefs.CHECK_ITS_USER:
            r = requests.post("https://login.1c.ru/rest/public/ticket/check", json={'ticket':url[3],'serviceNick':'informed'})
            if r.status_code == 401 or r.status_code == 403:
                start_response('401 Unauthorized', [('Content-Type', 'text/plain; charset=utf-8')])
                return ['Не указана действующая подписка на ИТС'.encode('UTF-8')]
            if r.status_code != 200:
                raise Exception("Error in login.1c.ru: " + str(r.status_code) + " " + r.reason+ " ticket " + url[3])
            response = r.json()
            login = response["login"]

        # создаем сессию
        t = round(time.time())  + 959    # время жизни сессии - 16 мин
        sid = str(uuid.uuid4())
        conn = sqlite3.connect(os.path.join(prefs.DATA_PATH, "templates.db"))
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
        conn = sqlite3.connect(os.path.join(prefs.DATA_PATH, "templates.db"))
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
            in_str = environ['wsgi.input'].read(length).decode('utf-8')
            params_json = json.loads(in_str)
            params = params_json['#value']
            t = {}
            for p in params:
                if p["name"]["#value"] == "Конфигурация":
                    t["configName"] = p["Value"]["#value"]
                elif p["name"]["#value"] == "Версия":
                    t["configVersion"] = p["Value"]["#value"]

            cv = t["configVersion"][:t["configVersion"].rfind('.')]

            cur = conn.cursor()
            cur.execute("select * from template where configName=? and configVersion=? order by fileName", (t["configName"], cv))

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
},
{
"name": {
"#type": "jxs:string",
"#value": "Комментарий"
},
"Value": {
"#type": "jxs:string",
"#value": "''',escapeJSON(r[14]) if r[14] is not None else "", '''"
}
}
]
}''', sep='', end='', file=output)

            cur.close()
            print(']}', sep='', file=output)


        elif url[4] == 'GetFile':
            found = True
            length = int(environ.get('CONTENT_LENGTH', '0'))
            in_str = environ['wsgi.input'].read(length).decode('utf-8')
            params_json = json.loads(in_str)
            UUIDTemplate = params_json['#value'][0]['Value']['#value']
            cur = conn.cursor()
            cur.execute("select fileName from template where UUIDTemplate=?", (UUIDTemplate,))
            fileName = cur.fetchone()
            cur.close()

            if fileName is None:
                conn.close()
                raise Exception("File with uuid='"+UUIDTemplate+"' not found")

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

            if itsLogin[0] != "" and itsLogin[0] not in prefs.VALID_ITS_USERS:
                conn.close()
                start_response('401 Unauthorized', [('Content-Type', 'text/plain; charset=utf-8')])
                return [("У пользователя '"+itsLogin[0]+"' нет прав на загрузку файлов").encode('UTF-8')]

            length = int(environ.get('CONTENT_LENGTH', '0'))
            in_str = environ['wsgi.input'].read(length).decode('utf-8')
            params_json = json.loads(in_str)
            params = params_json['#value']
            t = {}
            t["UUIDTemplate"] = str(uuid.uuid4())
            t["createNewVersion"] = 'false'     # в текущей версии не передается
            for p in params:
                if p["name"]["#value"] == "Идентификатор":
                    t["id"] = p["Value"]["#value"]
                elif p["name"]["#value"] == "Конфигурация":
                    t["configName"] = p["Value"]["#value"]
                elif p["name"]["#value"] == "Версия":
                    t["configVersion"] = p["Value"]["#value"]
                elif p["name"]["#value"] == "КонтрольнаяСумма":
                    t["checkSum"] = p["Value"]["#value"]
                elif p["name"]["#value"] == "ТипМДCodeSystem":
                    t["typeMDCodeSystem"] = p["Value"]["#value"]
                elif p["name"]["#value"] == "ТипМДCode":
                    t["typeMDCode"] = p["Value"]["#value"]
                elif p["name"]["#value"] == "ТипРЭМДCodeSystem":
                    t["typeREMDCodeSystem"] = p["Value"]["#value"]
                elif p["name"]["#value"] == "ТипРЭМДCode":
                    t["typeREMDCode"] = p["Value"]["#value"]
                elif p["name"]["#value"] == "ОписаниеШМД":
                    t["TemplateDesc"] = p["Value"]["#value"]
                elif p["name"]["#value"] == "ИмяФайлаСРаширением":
                    t["fileName"] = p["Value"]["#value"]
                elif  p["name"]["#value"] == "СоздаватьНовуюВерсию":
                    t["createNewVersion"] = p["Value"]["#value"]
                elif p["name"]["#value"] == "Комментарий":
                    t["description"] = p["Value"]["#value"]
                elif p["name"]["#value"] == "ДДанные":
                    t["ДДанные"] = p["Value"]["#value"]

            cv = t["configVersion"][:t["configVersion"].rfind('.')]
            cur = conn.cursor()
            cur.execute("select UUIDTemplate, fileName from template where configName=? and configVersion=? and id=?", (t["configName"], cv, t["id"]))
            rec = cur.fetchone()
            cur.close()
            if rec is not None:
                try:
                    os.remove(prefs.DATA_PATH+"/"+rec[0]+"_"+rec[1])
                except FileNotFoundError as e:
                    pass

                cur = conn.cursor()
                cur.execute("delete from template where UUIDTemplate=?", (rec[0],))
                cur.close()

            # ограничиваем длину имени файла 218 символами (255 - ограничение NTFS и 37 символов для технического префикса)
            fn = t["fileName"]
            if len(fn) > 218:
                ext = fn.rfind('.')
                if ext != -1:
                    ext_size = len(fn)-ext
                    n = fn[:ext]
                    fn = n[:218-ext_size]+fn[ext:]
                else:
                    fn = fn[:218]
            cur = conn.cursor()
            i = (t["configName"], cv, t["id"], fn, t["checkSum"], t["typeMDCode"], t["typeMDCodeSystem"], t["UUIDTemplate"], json.dumps(t["TemplateDesc"]), t["typeREMDCode"], t["typeREMDCodeSystem"], t["createNewVersion"], itsLogin[0], datetime.datetime.now().isoformat(), t["description"] if "description" in t else None)
            SQLPacket = "insert into template values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
            try:
                cur.execute(SQLPacket, i)
            except sqlite3.IntegrityError as e:
                cur.close()
                conn.close()
                start_response('409 Conflict', [('Content-Type', 'text/plain; charset=utf-8')])
                return [("Файл '"+fn+"' или uuid '"+t["UUIDTemplate"]+"' уже существует для "+t["configName"]+" "+cv+". "+repr(e)).encode('UTF-8')]

            cur.close()
            conn.commit()

            file = open(prefs.DATA_PATH+'/'+t["UUIDTemplate"]+"_"+fn, "wb")
            file.write(base64.b64decode(t["ДДанные"]))
            file.close()

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
"#value": "''',t["UUIDTemplate"], '''"
}
},
]
}''', sep='', end='', file=output)

            if t["typeREMDCode"] != "":
                cur = conn.cursor()
                cur.execute("select code from fnsi_typeREMD where code=? and codeSystem=?", (t["typeREMDCode"],t["typeREMDCodeSystem"]))
                code = cur.fetchone()
                if code is None:
                    loadFNSIref(conn, t["typeREMDCodeSystem"], 'typeREMD', environ)
                cur.close()

            if t["typeMDCode"] != "":
                cur = conn.cursor()
                cur.execute("select code from fnsi_typeMD where code=? and codeSystem=?", (t["typeMDCode"],t["typeMDCodeSystem"]))
                code = cur.fetchone()
                if code is None:
                    loadFNSIref(conn, t["typeMDCode"], 'typeMD', environ)
                cur.close()

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

            if itsLogin[0] != "" and itsLogin[0] not in prefs.VALID_ITS_USERS:
                conn.close()
                start_response('401 Unauthorized', [('Content-Type', 'text/plain; charset=utf-8')])
                return [("У пользователя '"+itsLogin[0]+"' нет прав на удаление файлов").encode('UTF-8')]

            length = int(environ.get('CONTENT_LENGTH', '0'))
            in_str = environ['wsgi.input'].read(length).decode('utf-8')
            params_json = json.loads(in_str)
            UUIDTemplate = params_json['#value'][0]['Value']['#value']

            cur = conn.cursor()
            cur.execute("select fileName from template where UUIDTemplate=?", (UUIDTemplate,))
            fileName = cur.fetchone()
            cur.close()

            if fileName is None:
                conn.close()
                raise Exception("File with uuid='"+UUIDTemplate+"' not found")

            try:
                os.remove(prefs.DATA_PATH+"/"+UUIDTemplate+"_"+fileName[0])
            except FileNotFoundError as e:
                pass
            cur = conn.cursor()
            cur.execute("delete from template where UUIDTemplate=?", (UUIDTemplate,))
            cur.close()
            conn.commit()

        if url[4] == 'GetXSLList':
            found = True
            length = int(environ.get('CONTENT_LENGTH', '0'))
            in_str = environ['wsgi.input'].read(length).decode('utf-8')
            params_json = json.loads(in_str)

            cur = conn.cursor()
            cur.execute("select * from visualizer order by fileName")

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
"#value": "УИДВизуализатора"
},
"Value": {
"#type": "jv8:UUID",
"#value": "''',r[0], '''"
}
},
{
"name": {
"#type": "jxs:string",
"#value": "Идентификатор"
},
"Value": {
"#type": "jxs:string",
"#value": "''',r[1] if r[1] is not None else '', '''"
}
},
{
"name": {
"#type": "jxs:string",
"#value": "ТипРЭМДCode"
},
"Value": {
"#type": "jxs:string",
"#value": "''',r[2] if r[2] is not None else '', '''"
}
},
{
"name": {
"#type": "jxs:string",
"#value": "ТипРЭМДCodeSystem"
},
"Value": {
"#type": "jxs:string",
"#value": "''',r[3] if r[3] is not None else '', '''"
}
},
{
"name": {
"#type": "jxs:string",
"#value": "ИмяФайла"
},
"Value": {
"#type": "jxs:string",
"#value": "''',r[4], '''"
}
},
{
"name": {
"#type": "jxs:string",
"#value": "КонтрольнаяСумма"
},
"Value": {
"#type": "jxs:string",
"#value": "''',r[5], '''"
}
},
{
"name": {
"#type": "jxs:string",
"#value": "Автор"
},
"Value": {
"#type": "jxs:string",
"#value": "''',r[6], '''"
}
},
{
"name": {
"#type": "jxs:string",
"#value": "ДатаЗагрузки"
},
"Value": {
"#type": "jxs:string",
"#value": "''',r[7], '''"
}
},
{
"name": {
"#type": "jxs:string",
"#value": "Комментарий"
},
"Value": {
"#type": "jxs:string",
"#value": "''',escapeJSON(r[8]) if r[8] is not None else "", '''"
}
}
]
}''', sep='', end='', file=output)

            cur.close()
            print(']}', sep='', file=output)


        elif url[4] == 'GetXSLFile':
            found = True
            length = int(environ.get('CONTENT_LENGTH', '0'))
            params = environ['wsgi.input'].read(length).decode('utf-8')
            params_json = json.loads(params)
            params = params_json['#value']
            t = {}
            for p in params:
                if p["name"]["#value"] == "UUIDVisualizer":
                    t["UUIDVisualizer"] = p["Value"]["#value"]
                elif p["name"]["#value"] == "Идентификатор":
                    t["Идентификатор"] = p["Value"]["#value"]
                elif p["name"]["#value"] == "ТипРЭМДCodeSystem":
                    t["codeSystem"] = p["Value"]["#value"]
                elif p["name"]["#value"] == "ТипРЭМДCode":
                    t["code"] = p["Value"]["#value"]

            cur = conn.cursor()
            cur.execute("select fileName, UUIDVisualizer, checkSum, id, typeREMDCode, typeREMDCodeSystem from visualizer where UUIDVisualizer=?", (t['UUIDVisualizer'],))
            fileName = cur.fetchone()
            cur.close()

            if fileName is None:
                cur = conn.cursor()
                cur.execute("select fileName, UUIDVisualizer, checkSum, id, typeREMDCode, typeREMDCodeSystem from visualizer where id=?", (t['Идентификатор'],))
                fileName = cur.fetchone()
                cur.close()
                if fileName is None:
                    cur = conn.cursor()
                    cur.execute("select fileName, UUIDVisualizer, checkSum, id, typeREMDCode, typeREMDCodeSystem from visualizer where typeREMDCode=? and typeREMDCodeSystem=?", (t['code'],t['codeSystem']))
                    fileName = cur.fetchone()
                    cur.close()

            if fileName is None:
                print('''{"#type": "jv8:Structure","#value": []}''', sep='', end='', file=output)
            else:
                print('''{
"#type": "jv8:Structure",
"#value": [
{
"name": {
"#type": "jxs:string",
"#value": "УИДВизуализатора"
},
"Value": {
"#type": "jv8:UUID",
"#value": "''',fileName[1], '''"
}
},
{
"name": {
"#type": "jxs:string",
"#value": "ИмяФайла"
},
"Value": {
"#type": "jxs:string",
"#value": "''',fileName[0], '''"
}
},
{
"name": {
"#type": "jxs:string",
"#value": "КонтрольнаяСумма"
},
"Value": {
"#type": "jxs:string",
"#value": "''',fileName[2], '''"
}
},
{
"name": {
"#type": "jxs:string",
"#value": "Идентификатор"
},
"Value": {
"#type": "jxs:string",
"#value": "''',fileName[3] if fileName[3] is not None else '', '''"
}
},
{
"name": {
"#type": "jxs:string",
"#value": "ТипРЭМДCode"
},
"Value": {
"#type": "jxs:string",
"#value": "''',fileName[4] if fileName[4] is not None else '', '''"
}
},
{
"name": {
"#type": "jxs:string",
"#value": "ТипРЭМДCodeSystem"
},
"Value": {
"#type": "jxs:string",
"#value": "''',fileName[5] if fileName[5] is not None else '', '''"
}
},
{
"name": {
"#type": "jxs:string",
"#value": "Файл"
},
"Value": {
"#type": "jxs:string",
"#value": "''',  sep='', end='', file=output)

                file = open(prefs.DATA_PATH+'/'+fileName[1]+"_"+fileName[0], "rb")
                print(base64.b64encode(file.read()).decode('ascii'), sep='', end='', file=output)
                file.close()
                print('''"}}]}''', sep='', end='', file=output)


        elif url[4] == 'UploadXSLFile':
            found = True
            cur = conn.cursor()
            cur.execute("select itsLogin from session where uuid=?", (url[3],))
            itsLogin = cur.fetchone()
            cur.close()

            if itsLogin is None:
                conn.close()
                start_response('401 Unauthorized', [('Content-Type', 'text/plain; charset=utf-8')])
                return [("Нет активной сессии").encode('UTF-8')]

            if itsLogin[0] != "" and itsLogin[0] not in prefs.VALID_ITS_USERS:
                conn.close()
                start_response('401 Unauthorized', [('Content-Type', 'text/plain; charset=utf-8')])
                return [("У пользователя '"+itsLogin[0]+"' нет прав на загрузку файлов").encode('UTF-8')]

            length = int(environ.get('CONTENT_LENGTH', '0'))
            in_str = environ['wsgi.input'].read(length).decode('utf-8')
            params_json = json.loads(in_str)
            params = params_json['#value']
            t = {}
            t["UUIDVisualizer"] = str(uuid.uuid4())
            for p in params:
                if p["name"]["#value"] == "Идентификатор":
                    t["id"] = p["Value"]["#value"]
                    if t["id"] == "":
                        t["id"] = None
                elif p["name"]["#value"] == "КонтрольнаяСумма":
                    t["checkSum"] = p["Value"]["#value"]
                elif p["name"]["#value"] == "ТипРЭМДCodeSystem":
                    t["codeSystem"] = p["Value"]["#value"]
                    if t["codeSystem"] == "":
                        t["codeSystem"] = None
                elif p["name"]["#value"] == "ТипРЭМДCode":
                    t["code"] = p["Value"]["#value"]
                    if t["code"] == "":
                        t["code"] = None
                elif p["name"]["#value"] == "ИмяФайлаСРаширением":
                    t["fileName"] = p["Value"]["#value"]
                elif p["name"]["#value"] == "Комментарий":
                    t["description"] = p["Value"]["#value"]
                elif p["name"]["#value"] == "ДДанные":
                    t["ДДанные"] = p["Value"]["#value"]

            cur = conn.cursor()
            if t["id"] is not None:
                t["code"] = None
                t["codeSystem"] = None
                cur.execute("select UUIDVisualizer, fileName from visualizer where id=?", (t["id"],))
            elif t["code"] is not None and t["codeSystem"] is not None:
                cur.execute("select UUIDVisualizer, fileName from visualizer where typeREMDCode=? and typeREMDCodeSystem=?", (t["code"], t["codeSystem"]))
            else:
                start_response('409 Conflict', [('Content-Type', 'text/plain; charset=utf-8')])
                return [("Wrong parameters. Template id or (typeREMDCode, typeREMDCodeSystem) should not be empty").encode('UTF-8')]

            rec = cur.fetchone()
            cur.close()
            if rec is not None:
                try:
                    os.remove(prefs.DATA_PATH+"/"+rec[0]+"_"+rec[1])
                except FileNotFoundError as e:
                    pass

                cur = conn.cursor()
                cur.execute("delete from visualizer where UUIDVisualizer=?", (rec[0],))
                cur.close()

            # ограничиваем длину имени файла 218 символами (255 - ограничение NTFS и 37 символов для технического префикса)
            fn = t["fileName"]
            if len(fn) > 218:
                ext = fn.rfind('.')
                if ext != -1:
                    ext_size = len(fn)-ext
                    n = fn[:ext]
                    fn = n[:218-ext_size]+fn[ext:]
                else:
                    fn = fn[:218]
            cur = conn.cursor()
            i = (t["UUIDVisualizer"], t["id"], t["code"], t["codeSystem"], fn, t["checkSum"], itsLogin[0], datetime.datetime.now().isoformat(), t["description"] if "description" in t else None)
            SQLPacket = "insert into visualizer values (?,?,?,?,?,?,?,?,?)"
            try:
                cur.execute(SQLPacket, i)
            except sqlite3.IntegrityError as e:
                cur.close()
                conn.close()
                start_response('409 Conflict', [('Content-Type', 'text/plain; charset=utf-8')])
                return [("Визуализатор с ключами: id='"+t["id"]+"', typeREMDCode='"+t["code"]+"', typeREMDCodeSystem='"+t["codeSystem"]+"' уже существует в базе").encode('UTF-8')]

            cur.close()
            conn.commit()

            file = open(prefs.DATA_PATH+'/'+t["UUIDVisualizer"]+"_"+fn, "wb")
            file.write(base64.b64decode(t["ДДанные"]))
            file.close()

            print('''{
"#type": "jv8:Structure",
"#value": [
{
"name": {
"#type": "jxs:string",
"#value": "УИДВизуализатора"
},
"Value": {
"#type": "jxs:string",
"#value": "''',t["UUIDVisualizer"], '''"
}
}
]
}''', sep='', end='', file=output)

        elif url[4] == 'DeleteXSLFile':
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

            if itsLogin[0] != "" and itsLogin[0] not in prefs.VALID_ITS_USERS:
                conn.close()
                start_response('401 Unauthorized', [('Content-Type', 'text/plain; charset=utf-8')])
                return [("У пользователя '"+itsLogin[0]+"' нет прав на удаление файлов").encode('UTF-8')]

            length = int(environ.get('CONTENT_LENGTH', '0'))
            in_str = environ['wsgi.input'].read(length).decode('utf-8')
            params_json = json.loads(in_str)
            UUIDVisualizer = params_json['#value'][0]['Value']['#value']

            cur = conn.cursor()
            cur.execute("select fileName from visualizer where UUIDVisualizer=?", (UUIDVisualizer,))
            fileName = cur.fetchone()
            cur.close()

            if fileName is None:
                conn.close()
                raise Exception("File with uuid='"+UUIDVisualizer+"' not found")

            try:
                os.remove(prefs.DATA_PATH+"/"+UUIDVisualizer+"_"+fileName[0])
            except FileNotFoundError as e:
                pass
            cur = conn.cursor()
            cur.execute("delete from visualizer where UUIDVisualizer=?", (UUIDVisualizer,))
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

    if environ['PATH_INFO'] == '/templatesList.json':
        conf = next(iter(prefs.CONFIGS)) 		# получаем первый элемент словаря
        cv = prefs.CONFIGS[conf][-1]
        output = StringIO()
        print('{"templatesList":[', sep='', end='', file=output)

        conn = sqlite3.connect(os.path.join(prefs.DATA_PATH, "templates.db"))
        cur = conn.cursor()
        SQLPacket = '''select fnsi_typeREMD.name, template.fileName
              from template 
              left join fnsi_typeREMD on fnsi_typeREMD.code=template.typeREMDCode 
              where configName=? and configVersion=?
              order by fileName'''
        cur.execute(SQLPacket, (conf, cv))
        start = True
        for r in cur.fetchall():
            if start:
                start = False
            else:
                print(',', sep='', end='', file=output)

            ext = r[1].rfind('.')
            shmd = 'Неопределено'
            n = ''
            if ext != -1:
                n = r[1][ext:]
                if n == '.zip':
                    shmd = 'Форма радактора'
                elif n == '.epf':
                    shmd = 'Обработка'
                elif n in ('.htm', '.html'):
                    shmd = 'Веб'
                else:
                    shmd = n
                name = r[1][:ext]
            else:
                name = r[1]
            name = r[1][:ext]
            print('{"typeREMD":"',r[0] if r[0] is not None else '',
                '","name":"',name.replace('_', ' '),
                '","type":"',shmd, '"}', sep='', end='', file=output)

        cur.close()
        conn.close()
        print(']}', sep='', end='', file=output)

        ret = output.getvalue().encode('UTF-8')
        start_response('200 OK', [
            ('Content-Type', 'application/json; charset=utf-8'),
            ('Content-Length', str(len(ret)))
        ])
        return [ret]

    if environ['PATH_INFO'] == '/getTemplatesList':
        conf = next(iter(prefs.CONFIGS)) 		# получаем первый элемент словаря
        cv = prefs.CONFIGS[conf][-1]
        output = StringIO()
        print('''<!DOCTYPE html><html><head>
<meta charset='utf-8'>
<link rel='stylesheet' href="''', prefs.SITE_URL, '''/style.css">
<title>Список ШМД сервиса распространения ШМД</title>
</head><body>
<p>Актуальная версия ''', conf,''' - ''', cv, '''</p>
<table width='100%' border=1>
<tr><th>ШМД &darr;</th>
<th>Тип РЭМД</th>
<th>Тип ШМД</th></tr>
''', sep='', end='', file=output)

        conn = sqlite3.connect(os.path.join(prefs.DATA_PATH, "templates.db"))
        cur = conn.cursor()
        SQLPacket = '''select fnsi_typeREMD.name, template.fileName
              from template 
              left join fnsi_typeREMD on fnsi_typeREMD.code=template.typeREMDCode and fnsi_typeREMD.codeSystem=template.typeREMDCodeSystem
              where configName='МедицинаБольница' and configVersion=?
              order by fileName'''
        cur.execute(SQLPacket, (cv,))
        for r in cur.fetchall():
            ext = r[1].rfind('.')
            shmd = 'Неопределено'
            n = ''
            if ext != -1:
                n = r[1][ext:]
                if n == '.zip':
                    shmd = 'Форма радактора'
                elif n == '.epf':
                    shmd = 'Обработка'
                elif n in ('.htm', '.html'):
                    shmd = 'Веб'
                else:
                    shmd = n
                name = r[1][:ext]
            else:
                name = r[1]
            print("<tr><td>", 
                name.replace("_", " "),
                "</td><td>", 
                r[0] if r[0] is not None else "", 
                "</td><td align='center'>",
                shmd, "</td></tr>", sep='', file=output)

        cur.close()
        conn.close()

        print("</table></body></html>", sep='', end='', file=output)

        ret = output.getvalue().encode('UTF-8')
        start_response('200 OK', [
            ('Content-Type', 'text/html; charset=utf-8'),
            ('Content-Length', str(len(ret)))
        ])
        return [ret]

    if len(url) in [2,3] and url[1] == 'getFullTemplatesList' and (len(url) == 2 or url[2].isdigit()):
        output = StringIO()
        print('''<!DOCTYPE html><html><head>
<meta charset='utf-8'>
<link rel='stylesheet' href="''', prefs.SITE_URL, '''/style.css">
<script src="''', prefs.SITE_URL, '''/tables.js"></script>
<title>Полный список ШМД сервиса распространения ШМД</title>
</head><body>''', sep='', end='', file=output)
        print("<p><small><span class='added'>Зеленый фон</span> - ШМД был добавлен в текущей версии (в предыдущей не было)</small><br>", sep='', file=output)
        print("<small><span class='deleted'>Красный фон</span> - ШМД был удален в следующей версии (в следующей нет)</small></p>", sep='', file=output)

        print("<br><p>Фильтр на конфигурацию: <select name='configName' size='1' onchange='selectConfig(this.value)'>", sep='', file=output)
        if len(url) == 2:
            print("<option value='sn' selected/>", sep='', file=output)
        else:
            print("<option value='sn'/>", sep='', file=output)
        for i in range(len(CONFIG_NAMES)):
            if len(url) == 3 and i == int(url[2]):
                print("<option value='s", i, "' selected>", CONFIG_NAMES[i], "</option>", sep='', file=output)
            else:
                print("<option value='s", i, "'>", CONFIG_NAMES[i], "</option>", sep='', file=output)
        print("</select></p>", sep='', file=output)
        print("<p>Фильтр на версии - ", ", ".join(CONFIG_VERSIONS)+". Базе данных версий может быть больше</p>", sep='', file=output)

        conn = sqlite3.connect(os.path.join(prefs.DATA_PATH, "templates.db"))
        cur = conn.cursor()
        placeholders = ",".join("?" * len(CONFIG_VERSIONS))
        if len(url) == 2:
            cur.execute('''
    		select template.*, visualizer.fileName v_fileName, visualizer.description v_description 
    		from template 
    		left join visualizer on visualizer.id=template.id or (visualizer.typeREMDCode=template.typeREMDCode and visualizer.typeREMDCodeSystem=template.typeREMDCodeSystem)
    		where configVersion in (%s) 
    		order by configName, configVersion desc, dateUploaded desc''' % placeholders, CONFIG_VERSIONS)
        else:
            t = CONFIG_VERSIONS.copy()
            t.append(CONFIG_NAMES[int(url[2])])
            cur.execute('''
    		select template.*, visualizer.fileName v_fileName, visualizer.description v_description 
    		from template 
    		left join visualizer on visualizer.id=template.id or (visualizer.typeREMDCode=template.typeREMDCode and visualizer.typeREMDCodeSystem=template.typeREMDCodeSystem)
    		where configVersion in (%s) and configName=? 
    		order by configName, configVersion desc, dateUploaded desc''' % placeholders, t)

        arr = []
        for r in cur.fetchall():
            arr.append(r)

        cur.close()
        conn.close()

        print('''<table width='100%' border=1>
<th>Конфигурация</th> 
<th>id</th>
<th>Имя файла</th>
<th>Тип МД</th>
<th>Тип РЭМД</th>
<th>Комментарий</th>
<th>ИТС логин</th>
<th>Дата &darr;<br>загрузки</th>
''', sep='', end='', file=output)

        for r in arr:
            ver_i = CONFIG_VERSIONS_IDX[r[0]+"_"+r[1]]
            added = False
            if ver_i != 0:
                for r2 in arr:
                    ver_i2 = CONFIG_VERSIONS_IDX[r2[0]+"_"+r2[1]]
                    if r2[0] == r[0] and r2[2] == r[2] and ver_i == ver_i2+1:
                        added = True
                        break
            else:
                added = True

            deleted = False
            if ver_i != len(prefs.CONFIGS[r[0]])-1:
                for r2 in arr:
                    ver_i2 = CONFIG_VERSIONS_IDX[r2[0]+"_"+r2[1]]
                    if r2[0] == r[0] and r2[2] == r[2] and ver_i == ver_i2-1:
                        deleted = True
                        break
            elif added:
                deleted = True

            print("<tr ", "" if added else "class='added'", "" if deleted else "class='deleted'","><td>", 
                r[0],"<br>", r[1], "</td><td>", 
                r[2],"</td><td>", 
                r[3], ("<br><strong>Визуализатор:</strong> "+r[15]+(" "+r[16] if r[16] is not None else "") if r[15] is not None else ""), "</td><td>", 
                "<a href='https://nsi.rosminzdrav.ru/dictionaries/",r[6],"'>",r[5], "</a></td><td>", 
                ("<a href='https://nsi.rosminzdrav.ru/dictionaries/"+r[10]+"'>" if r[10]!='' else ''),r[9], "</a></td><td>", 
                escapeHTML(r[14]) if r[14] is not None else "", "</td><td>",
                r[12], "</td><td>", 
                r[13][:10], " ", r[13][11:16], "</td></tr>",
                 sep='', file=output)

        print("</table></body></html>", sep='', end='', file=output)

        ret = output.getvalue().encode('UTF-8')
        start_response('200 OK', [
            ('Content-Type', 'text/html; charset=utf-8'),
            ('Content-Length', str(len(ret)))
        ])
        return [ret]


    else:
        start_response('404 Not Found', [('Content-Type','text/html; charset=utf-8')])
        return [b'<p>Page Not Found</p>'+environ['PATH_INFO'].encode('UTF-8')+b'\n']


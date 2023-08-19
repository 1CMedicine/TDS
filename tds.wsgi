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

def loadFNSIref(conn, oid, table, environ) :
    if prefs.FNSI_userkey is None or len(prefs.FNSI_userkey) == 0 :
        return

    cursor = conn.cursor()
    cursor.execute("delete from fnsi_"+table)
    cursor.close()

    r = requests.get('https://nsi.rosminzdrav.ru:443/port/rest/passport',
        params = {'userKey': prefs.FNSI_userkey, 'identifier': '1.2.643.5.1.13.13.11.1367'},
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
            cursor.execute("insert into fnsi_"+table+" values (?, ?)", (code, name))
            cursor.close()

    conn.commit()


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
}'''
        start_response('200 OK', [
            ('Content-Type', 'text/css; charset=utf-8'),
            ('Content-Length', str(len(style)))
        ])
        return [style]

    if environ['PATH_INFO'] == '/tables.js':
        output = StringIO()
        print('''function selectConfig(configName) {
    if (configName != 'sn')
        document.location.href="''', prefs.SITE_URL, '''/getFullTeplatesList/"+configName.substring(1)
    else
        document.location.href="''', prefs.SITE_URL, '''/getFullTeplatesList"
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
            cv = configVersion[:configVersion.rfind('.')]

            cur = conn.cursor()
            cur.execute("select * from template where configName=? and configVersion=?", (configName, cv))

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

            if itsLogin[0] != "" and itsLogin[0] not in prefs.VALID_ITS_USERS:
                conn.close()
                start_response('401 Unauthorized', [('Content-Type', 'text/plain; charset=utf-8')])
                return [("У пользователя '"+itsLogin[0]+"' нет прав на загрузку файлов").encode('UTF-8')]

            decoder = json.JSONDecoder(object_pairs_hook=OrderedDict)
            file = read(environ)
            f = open(file.name, "r", encoding='utf-8')
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

            cv = t["configVersion"][:t["configVersion"].rfind('.')]
            cur = conn.cursor()
            cur.execute("delete from template where configName=? and configVersion=? and id=?", (t["configName"], cv, t["id"]))
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
            i = (t["configName"], cv, t["id"], fn, t["checkSum"], t["typeMDCode"], t["typeMDCodeSystem"], t["UUIDTemplate"], json.dumps(t["TemplateDesc"]), t["typeREMDCode"], t["typeREMDCodeSystem"], t["createNewVersion"], itsLogin[0], datetime.datetime.now().isoformat())
            SQLPacket = "insert into template values (?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
            try:
                cur.execute(SQLPacket, i)
            except sqlite3.IntegrityError as e:
                conn.close()
                start_response('409 Conflict', [('Content-Type', 'text/plain; charset=utf-8')])
                return [("Файл '"+fn+"' уже существует для "+f["configName"]+" "+f["configVersion"]).encode('UTF-8')]
            cur.close()
            conn.commit()

            file = open(prefs.DATA_PATH+'/'+t["UUIDTemplate"]+"_"+fn, "wb")
            file.write(base64.b64decode(t["ДДанные"]))
            file.close()

            if t["typeREMDCode"] != "":
                cur = conn.cursor()
                cur.execute("select code from fnsi_typeREMD where code=?", (t["typeREMDCode"],))
                code = cur.fetchone()
                if code is None:
                    loadFNSIref(conn, '1.2.643.5.1.13.13.11.1520', 'typeREMD', environ)
                cur.close()

            if t["typeMDCode"] != "":
                cur = conn.cursor()
                cur.execute("select code from fnsi_typeMD where code=?", (t["typeMDCode"],))
                code = cur.fetchone()
                if code is None:
                    loadFNSIref(conn, '1.2.643.5.1.13.13.11.1522', 'typeMD', environ)
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

    if environ['PATH_INFO'] == '/templatesList.json':
        cv = prefs.CONFIGS['МедицинаБольница']
        output = StringIO()
        print('{"templatesList":[', sep='', end='', file=output)

        conn = sqlite3.connect(prefs.DATA_PATH+"/templates.db")
        cur = conn.cursor()
        SQLPacket = '''select fnsi_typeREMD.name, template.fileName
              from template 
              left join fnsi_typeREMD on fnsi_typeREMD.code=template.typeREMDCode 
              where configName='МедицинаБольница' and configVersion=?
              order by filename'''
        cur.execute(SQLPacket, (cv,))
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
            print('{"typeREMD":"',r[0] if r[0] is not None else '','","name":"',name.replace('_', ' '),'","type":"',shmd,'"}', sep='', end='', file=output)

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
        cv = prefs.CONFIGS['МедицинаБольница']
        output = StringIO()
        print('''<!DOCTYPE html><html><head>
<meta charset='utf-8'>
<link rel='stylesheet' href="''', prefs.SITE_URL, '''/style.css">
<title>Список ШМД сервиса распространения ШМД</title>
</head><body>
<p>Актуальная версия 1С:Медицина. Больница - ''', cv, '''</p>
<table width='100%' border=1>
<th>ШМД</th>
<th>Тип РЭМД</th>
<th>Тип ШМД</th>
''', sep='', end='', file=output)

        conn = sqlite3.connect(prefs.DATA_PATH+"/templates.db")
        cur = conn.cursor()
        SQLPacket = '''select fnsi_typeREMD.name, template.fileName
              from template 
              left join fnsi_typeREMD on fnsi_typeREMD.code=template.typeREMDCode 
              where configName='МедицинаБольница' and configVersion=?
              order by filename'''
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
                shmd, 
                "</td></tr>", sep='', file=output)

        cur.close()
        conn.close()

        print("</table></body></html>", sep='', end='', file=output)

        ret = output.getvalue().encode('UTF-8')
        start_response('200 OK', [
            ('Content-Type', 'text/html; charset=utf-8'),
            ('Content-Length', str(len(ret)))
        ])
        return [ret]

    if len(url) in [2,3] and url[1] in ('getFullTeplatesList', 'getFullTemplatesList') and (len(url) == 2 or url[2].isdigit()):
        output = StringIO()
        print('''<!DOCTYPE html><html><head>
<meta charset='utf-8'>
<link rel='stylesheet' href="''', prefs.SITE_URL, '''/style.css">
<script src="''', prefs.SITE_URL, '''/tables.js"></script>
<title>Полный список ШМД сервиса распространения ШМД</title>
</head><body><table width='100%' border=1>
<th>Конфигурация</th> 
<th>Версия</th>
<th>id</th>
<th>ШМД</th>
<th>Тип МД</th>
<th>Тип МД CodeSystem</th> 
<th>UUID</th>
<th>Тип РЭМД</th>
<th>Тип РЭМД CodeSystem</th>
<th>Создавать новую версию</th>
<th>ИТС логин</th>
<th>Дата загрузки</th>
''', sep='', end='', file=output)

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

        cv = prefs.CONFIGS['МедицинаБольница']
        conn = sqlite3.connect(prefs.DATA_PATH+"/templates.db")
        cur = conn.cursor()
        if len(url) == 2:
            cur.execute("select * from template order by configName, configVersion desc, id")
        else:
            cur.execute("select * from template where configName=? order by configName, configVersion desc, id", (CONFIG_NAMES[int(url[2])], ))

        for r in cur.fetchall():
            print("<tr><td>", 
                r[0], "</td><td>", 
                r[1], "</td><td>", 
                r[2], "</td><td>", 
                r[3], "</td><td>", 
                r[5], "</td><td>", 
                r[6], "</td><td>", 
                r[7], "</td><td>", 
                r[9], "</td><td>", 
                r[10], "</td><td>", 
                r[11], "</td><td>", 
                r[12], "</td><td>", 
                r[13][:10], " ", r[13][11:16], 
                "</td></tr>", sep='', file=output)

        cur.close()
        conn.close()

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


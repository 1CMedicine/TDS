# tds - сервис распространения ШМД для 1С:Медицина

Сервис распространения [шаблонов медицинских документов (ШМД)](https://solutions.1c.ru/catalog/clinic/emr) для 1С:Медицина служит для централизованного хранения ШМД. 
Сервис может использоваться в региональных проектах, когда ведется внедрение 1С:Медицина в нескольких медицинских организациях. Обслуживаниющая организация может публиковать ШМД в 
сервиса, а ИТ службы медицинских организаций могут получать ШМД из централизованного сервиса, установленного в защищенной сети региональной системы здравоохранения.

## Описание структуры проекта
### init.py - создание SQLite базы

База создается в папке, заданной в переменной DATA_PATH файла prefs.py. Для получения доступа из веб сервера к базе необходимо задать переменные APACHE_USER и APACHE_GROUP в файле prefs.py значениями, которые использует веб сервер. Папке, указанной в DATA_PATH необходимо установить владельца и группу теми же значениями, 
которые использует веб сервер.

### prefs.py - настройки сервиса 
В переменной  CONFIGS задаются имена конфигурации и их версий, для которых сервис принимает. Переменная имеет тип словарь (dict). 
Ключ - имя конфигурации, значение - список допустимых версий. Если список пустой, то отчеты не принимаются. Пустая строка - принимаются любые версии. Неполное задание версии допускается.

Переменные:
- CHECK_ITS_USER - выполнять проверку логину на ИТС. Для локальных публикаций рекомендуется отключать.
- VALID_ITS_USERS - только указанные в списке ИТС Логины смогут публиковать на сервере публикаций ШМД.
- FNSI_userkey - токен пользователя сайта nsi.rosminzdrav.ru. Использутеся для получения справочников "Типы МД" и "Типы РЭМД" с ФНСИ. Допускается пустое значение. См. https://its.1c.ru/db/instrpoly3#content:1040:1:issogl1_16.7.1_взаимодействие_с_фнси

После внесения изменений в файл может потребоваться перезапуск веб сервера, чтобы настройки применились.


### tds.wsgi - основной скрипт
В скрипте реализованы следующие методы сервиса
#### /CVS/Hello/{ТикетИТС}
Авторизация в сервисе. В случае когда CHECK_ITS_USER=True, то выполняется проверка тикета на login.1c.ru. Это позволяет ограничить доступ к сервису для пользователей, 
которые не имеют действующией подписки на ИТС. 

Если CHECK_ITS_USER=False, то тогда параметр ТикетИТС интерпретируется как имя пользователя сервиса (см. список VALID_ITS_USERS). 

Метод возвращает УидСессии. 
 
#### /CVS/MDT/{УидСессии}/{ИмяМетода}
Выполнение действий с базой ШМД. Операции: 
- GetFile - получение ШМД
- UploadFile - добавляет ШМД в базу сервиса. Пользователь, определенный для сессии в /CVS/Hello, должен присутствовать в списке VALID_ITS_USERS.
- DeleteFile - удаляет ШМД из базы сервиса. Пользователь, определенный для сессии в /CVS/Hello, должен присутствовать в списке VALID_ITS_USERS.
- GetList - возращает список ШМД, загруженных в сервис
Параметр УидСессии должен содержать сведения об актуальной сессии.

#### /getTeplatesList
Возвращает html со списком ШМД, загруженных в сервис распространения ШМД, для акутальной версии 1С:Медицина. Больница. Для корректной работы метода необходимо задать корректное значение переменной FNSI_userkey.

#### /getFullTeplatesList
Возвращает html с полным списком ШМД, загруженных в сервис распространения ШМД, для акутальной версии 1С:Медицина. Больница.

## Установка
1) Подключить модуль mod_wsgi из пакета libapache2-mod-wsgi-py3
2) Скопировать файлы tds.wsgi, prefs.py, init.py в папку /var/www/wsgi/tds.
3) Внести настройки экземпляра сервиса в prefs.py
4) Запустить init.py
5) Зарегистрировать приложение WSGI
```
	WSGIScriptAlias /wsgi/pult /var/www/wsgi/tds/tds.wsgi
```


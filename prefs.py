APACHE_USER = "www-data"                        # используется в init.py для создания Sqlite базы.
APACHE_GROUP = "www-data"                       # используется в init.py для создания Sqlite базы.
DATA_PATH = "/var/www/upload/tds"               # папка, где хранится Sqlite база и ШМД

CHECK_ITS_USER = False                           # Выполнять проверку логину на ИТС. Для локальных публикаций рекомендуется отключать
VALID_ITS_USERS = ['test']                      # Только указанные ИТС Логины смогут публиковать на сервере публикаций ШМД


# Конфигурации и их версии, по которым принимаются ШМД. 
# В словаре (dict) ключ - имя конфигурации, значение -  
# список допустимых версий. Если список пустой, то отчеты не принимаются.
# Пустая строка - принимаются любые версии. Неполное задание версии допускается.

CONFIGS = {
    'МедицинаБольница':[
        ["2.0.6."]
    ], 
    'МедицинаПоликлиника':[
        ["3.0.6."]
    ]
}

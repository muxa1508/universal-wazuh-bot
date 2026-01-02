#!/usr/bin/env python

import sys
import json
import requests
import logging
import time
from requests.auth import HTTPBasicAuth
from logging.handlers import RotatingFileHandler

#Enable bots: True/False
telegram = True
vkteams = True

#Count of tries to send message
try_counter = 5

#Telegram settings
#CHAT_ID="-xxxx" --- change with your chat id 
chat_id_telegram = ""
token_telegram = ""


#VK Teams settings
chat_id_vkteams = ""
token_vkteams = ""

#Logger setup
logger_path = 'logs/bot.log'
logging.basicConfig(
    level=logging.DEBUG, 
    filename=logger_path, 
    filemode="a", 
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S %Z")
fileHandler = RotatingFileHandler(logger_path.format(time.strftime("%Y%m%d-%H%M%S")), maxBytes=5000000, backupCount=3)
logger = logging.getLogger('wazuh_bot')
logger.addHandler(fileHandler)

class Sender:
    def telegram_send(telegram, chat_id_telegram, token_telegram, message):
        if telegram != False:
            telegram_url = "https://api.telegram.org/bot" + token_telegram + "/sendMessage"
            # Generate request data
            msg_data = {
                'chat_id': chat_id_telegram,
                'text': message,
                'parse_mode': 'Markdown'  # Using Markdown formatting
            }
    
            headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}

            for i in range(try_counter):
                result_telegram = requests.post(telegram_url, headers=headers, data=json.dumps(msg_data))
                if result_telegram.status_code == 200:
                    logger.info("Successs sending message to TELEGRAM")
                    break
                else:
                    logger.error("Failed sending message to TELEGRAM" )
                    logger.info("Number of counts to send message to TELEGRAM: " + str(try_counter - i))
                    logger.info(result_telegram.reason)
                    logger.error("Error: "+ str(result_telegram.status_code))
                    i += 1
                    time.sleep(60)

    def vKTeams_send(vkteams, chat_id_vkteams, token_vkteams, message):
        if vkteams != False:
            vkteams_url = "https://myteam.mail.ru/bot/v1//messages/sendText" + "?token=" + \
                token_vkteams + "&chatId=" + chat_id_vkteams + "&parseMode=MarkdownV2" + "&text=" + message

            # Send the request
            for i in range(try_counter):
                result_vkteams = requests.post(vkteams_url)
                if result_vkteams.status_code == 200:
                    logger.info("Successs sending message to VK Teams")
                    break
                else:
                    logger.error("Failed sending message to VK Teams")
                    logger.info("Number of counters to send message to VK Teams: " + str(try_counter - i))
                    logger.info(result_vkteams.reason)
                    logger.error("Error: "+ str(result_vkteams.status_code))
                    i += 1
                    time.sleep(60)

logger.info("--------------------------------")
logger.info("Bot receive Wazuh Alert.")
# Read configuration parameters
alert_file = open(sys.argv[1])

logger.debug('Received alerts file: ' + sys.argv[1])
logger.info("Received a new Wazuh alert for {0}".format(sys.argv[1]))


# Read the alert file
alert_json = json.loads(alert_file.read())
alert_file.close()

### Extract data fields ###
alert_level = alert_json['rule']['level'] if 'level' in alert_json['rule'] else None
description = alert_json['rule']['description'] if 'description' in alert_json['rule'] else None
rule_id = alert_json['rule']['id'] if 'id' in alert_json['rule'] else None
agent = alert_json['agent']['name'] if 'name' in alert_json['agent'] else None
agent_ip = alert_json['agent']['ip'] if 'ip' in alert_json['agent'] else None
src_ip = alert_json.get('data', {}).get('srcip', "N/A")
system_message = alert_json.get('data', {}).get('win', {}).get('eventdata', {}).get('memberName', None)
subject_user_name = alert_json.get('data', {}).get('win', {}).get('eventdata', {}).get('subjectUserName', None)
event_id = alert_json.get('data', {}).get('win', {}).get('system', {}).get('eventID', None)
full_log = alert_json.get('full_log', None)
data_win_system_message = alert_json.get('data', {}).get('win', {}).get('system', {}).get('message', None)


# Vulnerabilities variable section
vuln_CVE = alert_json.get('data', {}).get('vulnerability', {}).get('CVE', None)
vuln_package = alert_json.get('data', {}).get('vulnerability', {}).get('package', {}).get('name', None)
vuln_version = alert_json.get('data', {}).get('vulnerability', {}).get('package', {}).get('version', None)
vuln_reference = alert_json.get('data', {}).get('vulnerability', {}).get('reference', None)
vuln_severity = alert_json.get('data', {}).get('vulnerability', {}).get('severity', None)
vuln_title = alert_json.get('data', {}).get('vulnerability', {}).get('title', None)

# KES variable section
# data_host = alert_json.get('data', {}).get('host', "N/A")
# KES_module = alert_json.get('data', {}).get('KES', {}).get('module', "N/A")
# KES_p1 = alert_json.get('data', {}).get('KES', {}).get('p1', "N/A")
# KES_p2 = alert_json.get('data', {}).get('KES', {}).get('p2', "N/A")
# KES_p3 = alert_json.get('data', {}).get('KES', {}).get('p3', "N/A")
# KES_p4 = alert_json.get('data', {}).get('KES', {}).get('p4', "N/A")
# KES_p5 = alert_json.get('data', {}).get('KES', {}).get('p5', "N/A")
# KES_p6 = alert_json.get('data', {}).get('KES', {}).get('p6', "N/A")
# KES_p7 = alert_json.get('data', {}).get('KES', {}).get('p7', "N/A")
# KES_p8 = alert_json.get('data', {}).get('KES', {}).get('p8', "N/A")
# KES_srcIP = alert_json.get('data', {}).get('KES', {}).get('srcIP', "N/A")
# KES_dstIP = alert_json.get('data', {}).get('KES', {}).get('dstIP', "N/A")
# KES_susURL = alert_json.get('data', {}).get('KES', {}).get('susURL', "N/A")
# KES_susPath = alert_json.get('data', {}).get('KES', {}).get('susPath', "N/A")
# KES_susEXE = alert_json.get('data', {}).get('KES', {}).get('susEXE', "N/A")
# data_dstip = alert_json.get('data', {}).get('dstip', "N/A")
# data_dstuser = alert_json.get('data', {}).get('dstuser', "N/A")
# data_fileaction = alert_json.get('data', {}).get('fileaction', "N/A")

# Determine action based on event ID
action = None
if event_id in ["4728", "4756"]:
    action = "Пользователь добавлен в группу"
elif event_id in ["4729", "4757"]:
    action = "Пользователь удален из группы"

match vuln_severity:
    case 'Critical':
        logger.info("Founded CRITICAL vulnerability: " + vuln_CVE)
        message = f"*🚨 Critical Vulnerability Alert 🚨*\n\n" \
                  f"*❗ Критическая уязвимость обнаружена на {agent} ❗*\n\n" \
                  f"*#️⃣ CVE:*\n" \
                  f"└─ {vuln_CVE}\n\n" \
                  f"*🔧 Уязвимый модуль:*\n" \
                  f"└─ {vuln_package} {vuln_version}\n\n" \
                  f"*📄 Описание:*\n" \
                  f"└─ {vuln_title}\n\n" \
                  f"*📑 Подробнее:*\n" \
                  f"└─ {vuln_reference}\n\n" \
                  f"#vulnerability #critical \n\n"
    case 'High':
        logger.info("Founded HIGH vulnerability: " + vuln_CVE)
        message = f"*🚨 Critical Vulnerability Alert 🚨*\n\n" \
                  f"*❗ Критическая уязвимость обнаружена на {agent} ❗*\n\n" \
                  f"*#️⃣ CVE:*\n" \
                  f"└─ {vuln_CVE}\n\n" \
                  f"*🔧 Уязвимый модуль:*\n" \
                  f"└─ {vuln_package} {vuln_version}\n\n" \
                  f"*📄 Описание:*\n" \
                  f"└─ {vuln_title}\n\n" \
                  f"*📑 Подробнее:*\n" \
                  f"└─ {vuln_reference}\n\n" \
                  f"#vulnerability #high \n\n"
    case _:
        pass

# Generate message based on KES rule ID
# match rule_id:
#     case "100003":
#         if "веб-угроз" in KES_module:
#             message = f"*🚨 Kaspersky Alert 🚨*\n\n" \
#                       f"*❗ {data_fileaction}* ❗\n\n" \
#                       f"*🔧 Модуль KES:*\n" \
#                       f"└─ {KES_module}\n\n" \
#                       f"*💻 Имя хоста:*\n" \
#                       f"└─ {data_host}\n\n" \
#                       f"*🐱 Пользователь:*\n" \
#                       f"└─ {KES_p7}\n\n" \
#                       f"*🔗 URL:*\n" \
#                       f"└─ {KES_p5}\n\n" \
#                       f"#kaspersky #webthreat \n\n"
#         else:
#             message = f"*🚨 Kaspersky Alert 🚨*\n\n" \
#                       f"*❗ {data_fileaction} ❗*\n\n" \
#                       f"*🔧 Модуль KES:*\n" \
#                       f"└─ {KES_module}\n\n" \
#                       f"*💻 Имя хоста:*\n" \
#                       f"└─ {data_host}\n\n" \
#                       f"*🐱 Пользователь:*\n" \
#                       f"└─ {KES_p7}\n\n" \
#                       f"*👾 ID объекта:*\n" \
#                       f"└─ {KES_p5}\n\n" \
#                       f"*📁 Путь к объекту:*\n" \
#                       f"└─ {data_dstuser}\n\n" \
#                       f"#kaspersky #virus \n\n"

#     case "100009":
#         message = f"*🚨 Kaspersky Alert 🚨*\n\n" \
#                   f"*❗ {data_fileaction} ❗*\n\n" \
#                   f"*🔧 Модуль KES:*\n\n" \
#                   f"└─ {KES_module}\n\n" \
#                   f"*💻 Имя хоста:*\n" \
#                   f"└─ {data_host}\n\n" \
#                   f"*🐱 Пользователь:*\n" \
#                   f"└─ {KES_p7}\n\n" \
#                   f"*👾 ID объекта:*\n" \
#                   f"└─ {KES_p5}\n\n" \
#                   f"*📁 Путь к объекту:*\n" \
#                   f"└─ {data_dstuser}\n\n" \
#                   f"#kaspersky #virus \n\n"
#     case "100011":
#         message = f"*🚨 Kaspersky Alert 🚨*\n\n" \
#                   f"*❗ {data_fileaction} ❗*\n\n" \
#                   f"*🔧 Модуль KES:*\n" \
#                   f"└─ {KES_module}\n\n" \
#                   f"*💻 Имя хоста:*\n" \
#                   f"└─ {data_host}\n\n" \
#                   f"*👾 Тип атаки:*\n" \
#                   f"└─ {KES_p1}\n\n" \
#                   f"*🌍 Src IP:*\n" \
#                   f"└─ {KES_srcIP}\n\n" \
#                   f"*🌏 Dst IP:*\n" \
#                   f"└─ {KES_dstIP}\n\n" \
#                   f"#kaspersky #netattack \n\n"
#     case "100012":
#         message = f"*🚨 Kaspersky Alert 🚨*\n\n" \
#                   f"*❗ {data_fileaction} ❗*\n\n" \
#                   f"*🔧 Модуль KES:*\n" \
#                   f"└─ {KES_module}\n\n" \
#                   f"*💻 Имя хоста:*\n" \
#                   f"└─ {data_host}\n\n" \
#                   f"*🐱 Пользователь:*\n" \
#                   f"└─ {KES_p7}\n\n" \
#                   f"*📱 Приложение:* {KES_p6}\n" \
#                   f"*└─ {KES_p6}\n\n" \
#                   f"#kaspersky #maliciousapp \n\n"
#     case "100040":
#         message = f"*🚨 Kaspersky Alert 🚨*\n\n" \
#                   f"*❗ {data_fileaction} ❗*\n\n" \
#                   f"*🔧 Модуль KES:*\n" \
#                   f"└─ {KES_module}\n\n" \
#                   f"*💻 Имя хоста:*\n" \
#                   f"└─ {data_host}\n\n" \
#                   f"*🌍 IP источника:*\n" \
#                   f"└─ {data_dstip}\n\n" \  
#                   f"*🔗 URL ресурса:*\n" \
#                   f"└─ {KES_susURL}\n\n" \ 
#                   f"📱 Приложение:* {KES_susEXE}\n" \
#                   f"└─ {KES_susEXE}\n\n" \
#                   f"*📁 Путь к объекту:*\n" \
#                   f"└─ {KES_susPath}\n\n" \
#                   f"#kaspersky #connblocked \n\n"    
#     case _:
#         pass


# Generate message based on rule ID
if rule_id == "5760":
    message = f"*🚨 Wazuh Alert 🚨*\n\n" \
              f"*📄 Описание:* {description}\n" \
              f"*❗ Уровень:* {alert_level}\n" \
              f"*💻 Агент:* {agent}\n" \
              f"*🌍 IP-адрес агента:* {agent_ip}\n" \
              f"*🌍 IP-атакующего:* {src_ip}"
else:
#    CHAT_ID="-19XXXXXXX1"

    logger.info("Received Wazuh Alert: " + description)
    message = f"*🚨 Wazuh Alert 🚨*\n\n"

    if description != None:
        message += f"*📄 Описание:* {description}\n" 
    if alert_level != None:
        message += f"*❗ Уровень:* {alert_level}\n"
    if agent != None:
        message += f"*💻 Агент:* {agent}\n"
    if agent_ip != None:
        message += f"*🌍 IP-адрес агента:* {agent_ip}\n"
    if system_message != None:
        message += f"*📑 Сообщение:* {system_message}\n"
    if subject_user_name != None:
        message += f"*👾 Нарушитель:* {subject_user_name}\n"
    if action != None:
        message += f"*🔧 Действие:* {action}\n"

    message_lenght = len(message)
    full_log_length = len(full_log)
    data_win_system_message_length = len(data_win_system_message)
    logger.debug("message_lenght: " + str(message_lenght) + ", full_log_lenght:" + str(full_log_length) + ", dwsm_lenght: " + str(data_win_system_message_length))

    if (message_lenght + full_log_length) > 4096 or (message_lenght + data_win_system_message_length) > 4080:
        Sender.telegram_send(telegram, chat_id_telegram,token_telegram,message + '\n\n' +'1/2')
        Sender.vKTeams_send(vkteams, chat_id_vkteams,token_vkteams,message + '\n\n' +'1/2')
        logger.info("message 1/2 sended")
        if full_log != None:
            Sender.telegram_send(telegram, chat_id_telegram,token_telegram,'2/2' + '\n\n' + full_log)
            Sender.vKTeams_send(vkteams, chat_id_vkteams,token_vkteams, '2/2' + '\n\n' + full_log)
            logger.info("full_log 2/2 sended")
        if data_win_system_message != None:
            Sender.telegram_send(telegram, chat_id_telegram,token_telegram,'2/2' + '\n\n' + data_win_system_message)
            Sender.vKTeams_send(vkteams, chat_id_vkteams,token_vkteams, '2/2' + '\n\n' + data_win_system_message)
            logger.info("data_win_system_message 2/2 sended")
    else:   
        if full_log != None:
            message += f"*📑 Log:* {full_log}\n"
        if data_win_system_message != None:
            message += f"*📑 Log:* {data_win_system_message}"
        Sender.telegram_send(telegram, chat_id_telegram,token_telegram,message)
        Sender.vKTeams_send(vkteams, chat_id_vkteams,token_vkteams, message)
        logger.info("Full message sended. Count of symbols: " + str(len(message)))


logger.info("Bot complete job")   
sys.exit(0)
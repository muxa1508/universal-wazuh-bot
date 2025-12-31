# Wazuh bot для отправки уведомлений в VK Teams и Telegram

За основу взят <a href=https://github.com/scarletcorp/raiden-bot-wazuh-telegram>raiden-bot-wazuh-telegram</a>

Правила Wazuh для Kaspersky <a href=https://github.com/casperr2k/KSC_decoders_and_rules_for_Wazuh>here</a>

Правила Wazuh для AlertCenter <a href=https://github.com/casperr2k/wazuh-alertcenter-decoder-and-rules>here</a>

<b>Изменения:</b>

- Закомменчены правила для Kaspersky и AlertCenter (Не требуется в текущей инфраструктуре, но может пригодиться в будущем)
- Пустные строки не добавляются в сообщения
- Добавлена поддержка VK Teams
- Настройки ID чатов и токенов ботов перенесены в *custom-bot.py*


<h2>Установка:</h2>

! Установка бота производится на wazuh-master сервере и на каждом worker сервере

1. Установить зависимости *python3* :

```
sudo apt install python3-requests -y
sudo /var/ossec/framework/python/bin/pip3 install logging
```

2. Зарегистрировать ботов в мессенджерах и прописать их токены в *custom-bot.py*

3. Добавить в *custom-bot.py* *chat_id* чатов

4. Скопировать *custom-bot* и *custom-bot.py* в директорию /var/ossec/integrations каждого сервера кластера wazuh

5. Поменять права на эти файлы:
```
chown root:wazuh /var/ossec/integrations/custom-bot*
chmod 750 /var/ossec/integrations/custom-bot*
```
6. Добавить в файл */var/ossec/etc/ossec.conf* на каждом сервере кластера wazuh сведения об интеграции:
```
    <integration>
        <name>custom-bot</name>
        <level>16</level>
        <alert_format>json</alert_format>
    </integration>
```
7. Перезапустить wazuh manager на каждом сервере кластера wazuh
```
sudo systemctl restart wazuh-manager
```
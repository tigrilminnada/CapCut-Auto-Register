import configparser
import os

def create_default_config():
    config = configparser.ConfigParser()
    
    config['IMAP'] = {
        'host': 'imap.example.com',
        'port': '993',
        'password': '',  # Password IMAP disimpan di sini
        'ssl': 'True'
    }
    
    config['CAPCUT'] = {
        'password': ''  # Password CapCut disimpan di sini
    }
    
    with open('config.ini', 'w') as configfile:
        config.write(configfile)

def load_config():
    config = configparser.ConfigParser()
    
    if not os.path.exists('config.ini'):
        create_default_config()
    
    config.read('config.ini')
    return config

def save_config(config):
    with open('config.ini', 'w') as configfile:
        config.write(configfile)
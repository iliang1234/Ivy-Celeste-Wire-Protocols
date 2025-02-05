import configparser
import os
from pathlib import Path

def load_config(component='all'):
    """
    Load configuration from config.ini and environment variables.
    
    Args:
        component (str): Which component's config to load ('server', 'client', 'websocket', or 'all')
    
    Returns:
        dict: Configuration dictionary
    """
    # Default values
    config = {
        'server': {
            'host': '0.0.0.0',
            'port': 5001
        },
        'client': {
            'host': 'localhost',
            'port': 8000
        },
        'websocket': {
            'url': 'http://localhost:5001'
        }
    }

    # Try to load from config.ini
    config_file = Path(__file__).parent.parent / 'config.ini'
    if config_file.exists():
        parser = configparser.ConfigParser()
        parser.read(config_file)
        
        if 'server' in parser:
            config['server']['host'] = parser['server'].get('host', config['server']['host'])
            config['server']['port'] = parser['server'].getint('port', config['server']['port'])
        
        if 'client' in parser:
            config['client']['host'] = parser['client'].get('host', config['client']['host'])
            config['client']['port'] = parser['client'].getint('port', config['client']['port'])
        
        if 'websocket' in parser:
            config['websocket']['url'] = parser['websocket'].get('url', config['websocket']['url'])

    # Environment variables override config file
    if component in ['server', 'all']:
        config['server']['host'] = os.environ.get('CHAT_SERVER_HOST', config['server']['host'])
        config['server']['port'] = int(os.environ.get('CHAT_SERVER_PORT', config['server']['port']))
    
    if component in ['client', 'all']:
        config['client']['host'] = os.environ.get('CHAT_CLIENT_HOST', config['client']['host'])
        config['client']['port'] = int(os.environ.get('CHAT_CLIENT_PORT', config['client']['port']))
    
    if component in ['websocket', 'all']:
        config['websocket']['url'] = os.environ.get('CHAT_WEBSOCKET_URL', config['websocket']['url'])

    if component == 'all':
        return config
    return config[component]

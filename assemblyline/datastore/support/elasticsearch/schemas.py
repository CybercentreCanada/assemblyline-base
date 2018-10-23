default_index = {
    "settings": {
        "analysis": {
            'filter': {
                'text_ws_dsplit': {
                    'type': 'pattern_replace',
                    'pattern': r'(\.)',
                    'replacement': ' '
                }
            },
            "analyzer": {
                'string_ci': {
                    'type': 'custom',
                    'tokenizer': 'keyword',
                    'filter': ['lowercase']
                },
                "text_general": {
                    "type": "custom",
                    "tokenizer": "standard",
                    "filter": ["lowercase"]
                },
                "text_fuzzy": {
                    "type": "pattern",
                    "pattern": r"\s*:\s*",
                    "lowercase": False
                },
                "text_whitespace": {
                    "type": "whitespace"
                },
                'text_ws_dsplit': {
                    'type': 'custom',
                    'tokenizer': 'whitespace',
                    'filters': ['text_ws_dsplit']
                }
            }
        }
    },
    'mappings': {}
}

default_mapping = {
    'dynamic': False,
    'properties': {

        # <!-- AL Access fields  -->
        'classification': {'type': 'keyword', 'store': True},
        '__expiry_ts__': {'type': 'date', 'format': 'date_optional_time||epoch_millis'},
        '__access_lvl__': {'type': 'long'},
        '__access_req__': {'type': 'keyword'},
        '__access_grp2__': {'type': 'keyword', 'null_value': '__EMPTY__'},
        '__access_grp1__': {'type': 'keyword', 'null_value': '__EMPTY__'},

        '__text__': {'type': 'text', 'analyzer': 'text_general'},
    }
}

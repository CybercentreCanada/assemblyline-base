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
            },
            "normalizer": {
                "lowercase_normalizer": {
                  "type": "custom",
                  "char_filter": [],
                  "filter": ["lowercase"]
                }
            }
        }
    },
    'mappings': {}
}

default_mapping = {
    'dynamic': True,
    'properties': {
        '__text__': {'type': 'text'},
    }
}

default_dynamic_templates = [
    {
        "int": {
            "path_match": "*_i",
            "mapping": {
                "type": "integer",
                "store": True
            }
        }
    },
    {
        "ints": {
            "path_match": "*_is",
            "mapping": {
                "type": "integer",
                "store": True
            }
        }
    },
    {
        "long": {
            "path_match": "*_l",
            "mapping": {
                "type": "long",
                "store": True
            }
        }
    },
    {
        "longs": {
            "path_match": "*_ls",
            "mapping": {
                "type": "long",
                "store": True
            }
        }
    },
    {
        "double": {
            "path_match": "*_d",
            "mapping": {
                "type": "float",
                "store": True
            }
        }
    },
    {
        "doubles": {
            "path_match": "*_ds",
            "mapping": {
                "type": "float",
                "store": True
            }
        }
    },
    {
        "float": {
            "path_match": "*_f",
            "mapping": {
                "type": "float",
                "store": True
            }
        }
    },
    {
        "floats": {
            "path_match": "*_fs",
            "mapping": {
                "type": "float",
                "store": True
            }
        }
    },
    {
        "string": {
            "path_match": "*_s",
            "mapping": {
                "type": "keyword",
                "store": True
            }
        }
    },
    {
        "strings": {
            "path_match": "*_ss",
            "mapping": {
                "type": "keyword",
                "store": True
            }
        }
    },
    {
        "text": {
            "path_match": "*_t",
            "mapping": {
                'type': 'text',
                "store": True
            }
        }
    },
    {
        "texts": {
            "path_match": "*_ts",
            "mapping": {
                'type': 'text',
                "store": True
            }
        }
    },
    {
        "boolean": {
            "path_match": "*_b",
            "mapping": {
                'type': 'boolean',
                "store": True
            }
        }
    },
    {
        "booleans": {
            "path_match": "*_bs",
            "mapping": {
                'type': 'boolean',
                "store": True
            }
        }
    },
    {
        "date": {
            "path_match": "*_dt",
            "mapping": {
                'type': 'date',
                'format': 'date_optional_time||epoch_millis',
                "store": True
            }
        }
    },
    {
        "date": {
            "path_match": "*_dts",
            "mapping": {
                'type': 'date',
                'format': 'date_optional_time||epoch_millis',
                "store": True
            }
        }
    }
]

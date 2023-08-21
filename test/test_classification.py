import copy

import pytest

from assemblyline.common.classification import Classification, InvalidClassification


TEST_SCHEME_A = {
    "enforce": True,
    "dynamic_groups": False,
    "dynamic_groups_type": "email",
    "levels": [
        {
            "name": "Level 0",
            "short_name": "L0",
            "lvl": 1,
            "aliases": ["Open"]
        },
        {
            "name": "Level 1",
            "short_name": "L1",
            "lvl": 5
        },
        {
            "name": "Level 2",
            "short_name": "L2",
            "lvl": 15
        }
    ],
    "groups": [
        {
            "name": "Group A",
            "short_name": "A"
        },
        {
            "name": "Group B",
            "short_name": "B"
        },
        {
            "name": "Group X",
            "short_name": "X",
            "solitary_display_name": "XX"
        },
    ],
    "required": [
        {
            "name": "Legal Department",
            "short_name": "LE",
            "is_required_group": False,
            "aliases": ["Legal"]
        },
        {
            "name": "Accounting",
            "short_name": "AC",
            "is_required_group": False,
            "aliases": ["Acc"]
        },
        {
            "name": "Originator Controlled",
            "short_name": "orcon",
            "is_required_group": True,
        },
        {
            "name": "No Contractors",
            "short_name": "nocon",
            "is_required_group": True,
        }
    ],
    "subgroups": [
        {
            "name": "Reserve One",
            "short_name": "R1",
            "aliases": ["R0"]
        },
        {
            "name": "Reserve Two",
            "short_name": "R2",
            "require_group": "X"
        },
        {
            "name": "Reserve Three",
            "short_name": "R3",
            "limited_to_group": "X"
        },
    ],
    "unrestricted": "L0",
    "restricted": "L2",
}


@pytest.fixture
def ce():
    return Classification(copy.deepcopy(TEST_SCHEME_A))

# these errors are

# def test_invalid_classifications_reserved_names():
#     config = copy.deepcopy(TEST_SCHEME_A)

#     # bad short names
#     Classification(config)
#     config['levels'][1]['short_name'] = "INV"
#     assert Classification(config).invalid_mode
#     config['levels'][1]['short_name'] = "NULL"
#     assert Classification(config).invalid_mode

#     # bad long names
#     config = copy.deepcopy(TEST_SCHEME_A)
#     config['levels'][1]['name'] = "INV"
#     assert Classification(config).invalid_mode
#     config['levels'][1]['name'] = "NULL"
#     assert Classification(config).invalid_mode


# def test_invalid_classifications():
#     # overlapping level names
#     config = copy.deepcopy(TEST_SCHEME_A)
#     config['levels'][0]['short_name'] = "L0"
#     config['levels'][1]['short_name'] = "L0"
#     assert Classification(copy.deepcopy(config)).invalid_mode

#     # overlapping level
#     config = copy.deepcopy(TEST_SCHEME_A)
#     config['levels'][0]['lvl'] = 100
#     config['levels'][1]['lvl'] = 100
#     assert Classification(copy.deepcopy(config)).invalid_mode

#     # overlapping required names
#     config = copy.deepcopy(TEST_SCHEME_A)
#     config['required'][0]['short_name'] = "AA"
#     config['required'][1]['short_name'] = "AA"
#     assert Classification(copy.deepcopy(config)).invalid_mode

#     # overlapping required names
#     config = copy.deepcopy(TEST_SCHEME_A)
#     config['required'][0]['name'] = "AA"
#     config['required'][1]['name'] = "AA"
#     assert Classification(copy.deepcopy(config)).invalid_mode

#     # overlapping groups names
#     config = copy.deepcopy(TEST_SCHEME_A)
#     config['groups'][0]['short_name'] = "AA"
#     config['groups'][1]['short_name'] = "AA"
#     assert Classification(copy.deepcopy(config)).invalid_mode

#     # overlapping groups names
#     config = copy.deepcopy(TEST_SCHEME_A)
#     config['groups'][0]['name'] = "AA"
#     config['groups'][1]['name'] = "AA"
#     assert Classification(copy.deepcopy(config)).invalid_mode

#     # overlapping subgroups names
#     config = copy.deepcopy(TEST_SCHEME_A)
#     config['subgroups'][0]['short_name'] = "AA"
#     config['subgroups'][1]['short_name'] = "AA"
#     assert Classification(copy.deepcopy(config)).invalid_mode

#     # overlapping subgroups names
#     config = copy.deepcopy(TEST_SCHEME_A)
#     config['subgroups'][0]['name'] = "AA"
#     config['subgroups'][1]['name'] = "AA"
#     assert Classification(copy.deepcopy(config)).invalid_mode

#     # missing restricted
#     config = copy.deepcopy(TEST_SCHEME_A)
#     config['restricted'] = "XF"
#     assert Classification(copy.deepcopy(config)).invalid_mode

#     # missing unrestricted
#     config = copy.deepcopy(TEST_SCHEME_A)
#     config['unrestricted'] = "XF"
#     assert Classification(copy.deepcopy(config)).invalid_mode

#     # Use levels outside of range
#     config = copy.deepcopy(TEST_SCHEME_A)
#     config['levels'][0]['lvl'] = 0
#     assert Classification(copy.deepcopy(config)).invalid_mode
#     config['levels'][0]['lvl'] = 10002
#     assert Classification(copy.deepcopy(config)).invalid_mode


def test_bad_commas(ce):

    assert ce.is_valid("L1//REL A, B/ORCON/NOCON")
    assert not ce.is_valid("L1//REL A, B/ORCON,NOCON")
    assert not ce.is_valid("L1//ORCON,NOCON/REL A, B")

    assert ce.normalize_classification("L1//REL A, B/ORCON/NOCON", long_format=False) == "L1//NOCON/ORCON/REL A, B"


def test_typo_errors(ce):
    with pytest.raises(InvalidClassification):
        assert ce.normalize_classification("L1//REL A, B/ORCON,NOCON")
    with pytest.raises(InvalidClassification):
        assert ce.normalize_classification("L1//ORCON,NOCON/REL A, B")


def test_minimums(ce):
    # level only
    assert ce.min_classification("L0", "L0", long_format=False) == "L0"
    assert ce.min_classification("L0", "L0", long_format=True) == "LEVEL 0"
    assert ce.min_classification("L0", "L1", long_format=False) == "L0"
    assert ce.min_classification("L0", "L1", long_format=True) == "LEVEL 0"
    assert ce.min_classification("L0", "L2", long_format=False) == "L0"
    assert ce.min_classification("L0", "L2", long_format=True) == "LEVEL 0"
    assert ce.min_classification("L1", "L0", long_format=False) == "L0"
    assert ce.min_classification("L1", "L0", long_format=True) == "LEVEL 0"
    assert ce.min_classification("L1", "L1", long_format=False) == "L1"
    assert ce.min_classification("L1", "L1", long_format=True) == "LEVEL 1"
    assert ce.min_classification("L1", "L2", long_format=False) == "L1"
    assert ce.min_classification("L1", "L2", long_format=True) == "LEVEL 1"
    assert ce.min_classification("L2", "L0", long_format=False) == "L0"
    assert ce.min_classification("L2", "L0", long_format=True) == "LEVEL 0"
    assert ce.min_classification("L2", "L1", long_format=False) == "L1"
    assert ce.min_classification("L2", "L1", long_format=True) == "LEVEL 1"
    assert ce.min_classification("L2", "L2", long_format=False) == "L2"
    assert ce.min_classification("L2", "L2", long_format=True) == "LEVEL 2"
    assert ce.min_classification("OPEN", "L2", long_format=False) == "L0"

    # Group operations
    assert ce.min_classification("L0//REL A, B", "L0", long_format=False) == "L0"
    assert ce.min_classification("L0//REL A", "L0", long_format=True) == "LEVEL 0"
    assert ce.min_classification("L0", "L2//REL A, B", long_format=False) == "L0"
    assert ce.min_classification("L0", "L1//REL A", long_format=True) == "LEVEL 0"
    assert ce.min_classification("L0//REL A, B", "L1//REL A, B", long_format=False) == "L0//REL A, B"
    assert ce.min_classification("L0//REL A, B", "L0//REL A", long_format=True) == "LEVEL 0//REL TO GROUP A, GROUP B"
    assert ce.min_classification("L0//REL B", "L0//REL B, A", long_format=True) == "LEVEL 0//REL TO GROUP A, GROUP B"

    # Subgroups
    assert ce.min_classification("L0//R1/R2", "L0", long_format=False) == "L0"
    assert ce.min_classification("L0//R1", "L0", long_format=True) == "LEVEL 0"
    assert ce.min_classification("L0//R1/R2", "L1//R1/R2", long_format=False) == "L0//XX/R1/R2"
    assert ce.min_classification("L0//R1/R2", "L0//R1", long_format=True) == "LEVEL 0//XX/RESERVE ONE/RESERVE TWO"


def test_maximums(ce):
    # level only
    assert ce.max_classification("L0", "L0", long_format=False) == "L0"
    assert ce.max_classification("L0", "L0", long_format=True) == "LEVEL 0"
    assert ce.max_classification("L0", "L1", long_format=False) == "L1"
    assert ce.max_classification("L0", "L1", long_format=True) == "LEVEL 1"
    assert ce.max_classification("L0", "L2", long_format=False) == "L2"
    assert ce.max_classification("L0", "L2", long_format=True) == "LEVEL 2"
    assert ce.max_classification("L1", "L0", long_format=False) == "L1"
    assert ce.max_classification("L1", "L0", long_format=True) == "LEVEL 1"
    assert ce.max_classification("L1", "L1", long_format=False) == "L1"
    assert ce.max_classification("L1", "L1", long_format=True) == "LEVEL 1"
    assert ce.max_classification("L1", "L2", long_format=False) == "L2"
    assert ce.max_classification("L1", "L2", long_format=True) == "LEVEL 2"
    assert ce.max_classification("L2", "L0", long_format=False) == "L2"
    assert ce.max_classification("L2", "L0", long_format=True) == "LEVEL 2"
    assert ce.max_classification("L2", "L1", long_format=False) == "L2"
    assert ce.max_classification("L2", "L1", long_format=True) == "LEVEL 2"
    assert ce.max_classification("L2", "L2", long_format=False) == "L2"
    assert ce.max_classification("L2", "L2", long_format=True) == "LEVEL 2"

    # Group operations
    assert ce.max_classification("L0//REL A, B", "L0", long_format=False) == "L0//REL A, B"
    assert ce.max_classification("L0//REL A", "L1", long_format=True) == "LEVEL 1//REL TO GROUP A"
    assert ce.max_classification("L0", "L2//REL A, B", long_format=False) == "L2//REL A, B"
    assert ce.max_classification("L0", "L1//REL A", long_format=True) == "LEVEL 1//REL TO GROUP A"
    assert ce.max_classification("L0//REL A, B", "L1//REL A, B", long_format=False) == "L1//REL A, B"
    assert ce.max_classification("L0//REL A, B", "L0//REL A", long_format=True) == "LEVEL 0//REL TO GROUP A"
    assert ce.max_classification("L0//REL B", "L0//REL B, A", long_format=True) == "LEVEL 0//REL TO GROUP B"
    with pytest.raises(InvalidClassification):
        ce.max_classification("L0//REL B", "L0//REL A", long_format=True)
    with pytest.raises(InvalidClassification):
        ce.max_classification("L0//REL B", "L0//REL A", long_format=False)

    # Subgroups
    assert ce.max_classification("L0//R1/R2", "L0", long_format=False) == "L0//XX/R1/R2"
    assert ce.max_classification("L0//R1", "L0", long_format=True) == "LEVEL 0//RESERVE ONE"
    assert ce.max_classification("L0//R1/R2", "L1//R1/R2", long_format=False) == "L1//XX/R1/R2"
    assert ce.max_classification("L0//R1/R2", "L0//R1", long_format=True) == "LEVEL 0//XX/RESERVE ONE"


def test_multi_group_alias():
    config = copy.deepcopy(TEST_SCHEME_A)
    config['groups'][0]['aliases'] = ["Alphabet Gang"]
    config['groups'][1]['aliases'] = ["Alphabet Gang"]
    ce = Classification(config)

    assert ce.normalize_classification("L0//REL A", long_format=False) == "L0//REL A"
    assert ce.normalize_classification("L0//REL A, B", long_format=False) == "L0//REL ALPHABET GANG"


def test_auto_select_group():
    config = copy.deepcopy(TEST_SCHEME_A)
    config['groups'][0]['auto_select'] = True
    ce = Classification(config)

    assert ce.normalize_classification("L0", long_format=False) == "L0"
    assert ce.normalize_classification("L0//REL A", long_format=False) == "L0//REL A"
    assert ce.normalize_classification("L0//REL B", long_format=False) == "L0//REL A, B"
    assert ce.normalize_classification("L0//REL A, B", long_format=False) == "L0//REL A, B"
    assert ce.normalize_classification("L0", long_format=True) == "LEVEL 0"
    assert ce.normalize_classification("L0//REL A", long_format=True) == "LEVEL 0//REL TO GROUP A"
    assert ce.normalize_classification("L0//REL B", long_format=True) == "LEVEL 0//REL TO GROUP A, GROUP B"
    assert ce.normalize_classification("L0//REL A, B", long_format=True) == "LEVEL 0//REL TO GROUP A, GROUP B"


def test_auto_select_subgroup():
    config = copy.deepcopy(TEST_SCHEME_A)
    config['subgroups'][0]['auto_select'] = True
    ce = Classification(config)

    assert ce.normalize_classification("L0", long_format=False) == "L0"
    assert ce.normalize_classification("L0//R0", long_format=False) == "L0//R1"
    assert ce.normalize_classification("L0//R2", long_format=False) == "L0//XX/R1/R2"
    assert ce.normalize_classification("L0//R1/R2", long_format=False) == "L0//XX/R1/R2"
    assert ce.normalize_classification("L0", long_format=True) == "LEVEL 0"
    assert ce.normalize_classification("L0//R1", long_format=True) == "LEVEL 0//RESERVE ONE"
    assert ce.normalize_classification("L0//R2", long_format=True) == "LEVEL 0//XX/RESERVE ONE/RESERVE TWO"
    assert ce.normalize_classification("L0//R1/R2", long_format=True) == "LEVEL 0//XX/RESERVE ONE/RESERVE TWO"


def test_parts(ce):
    # level only
    assert ce._get_classification_parts("L0") == (1, [], [], [])
    assert ce._get_classification_parts("LEVEL 0") == (1, [], [], [])
    assert ce._get_classification_parts("L1") == (5, [], [], [])
    assert ce._get_classification_parts("LEVEL 1") == (5, [], [], [])
    assert ce._get_classification_parts("L0", long_format=False) == (1, [], [], [])
    assert ce._get_classification_parts("LEVEL 0", long_format=False) == (1, [], [], [])
    assert ce._get_classification_parts("L1", long_format=False) == (5, [], [], [])
    assert ce._get_classification_parts("LEVEL 1", long_format=False) == (5, [], [], [])

#     # Group operations
    assert ce._get_classification_parts("L0//REL A") == (1, [], ["GROUP A"], [])
    assert ce._get_classification_parts("LEVEL 0//REL Group A") == (1, [], ["GROUP A"], [])
    assert ce._get_classification_parts("L0//REL A", long_format=False) == (1, [], ["A"], [])
    assert ce._get_classification_parts("LEVEL 0//REL Group A", long_format=False) == (1, [], ["A"], [])


def test_normalize(ce):
    # level only
    assert ce.normalize_classification("L0", long_format=False) == "L0"
    assert ce.normalize_classification("L1") == "LEVEL 1"

    # Group operations
    assert ce.normalize_classification("L0//REL A, B") == "LEVEL 0//REL TO GROUP A, GROUP B"
    assert ce.normalize_classification("L0//REL A, B", long_format=False) == "L0//REL A, B"
    assert ce.normalize_classification("L0//REL A") == "LEVEL 0//REL TO GROUP A"
    assert ce.normalize_classification("L0//REL A", long_format=False) == "L0//REL A"
    assert ce.normalize_classification("L2//REL A, B") == "LEVEL 2//REL TO GROUP A, GROUP B"
    assert ce.normalize_classification("L2//REL A, B", long_format=False) == "L2//REL A, B"
    assert ce.normalize_classification("L1//REL A") == "LEVEL 1//REL TO GROUP A"
    assert ce.normalize_classification("L1//REL A", long_format=False) == "L1//REL A"
    assert ce.normalize_classification("L0//REL B") == "LEVEL 0//REL TO GROUP B"
    assert ce.normalize_classification("L0//REL B", long_format=False) == "L0//REL B"
    assert ce.normalize_classification("L0//REL B, A") == "LEVEL 0//REL TO GROUP A, GROUP B"
    assert ce.normalize_classification("L0//REL B, A", long_format=False) == "L0//REL A, B"

    #
    assert ce.normalize_classification("L1//LE") == "LEVEL 1//LEGAL DEPARTMENT"

    # bad inputs
    with pytest.raises(InvalidClassification):
        ce.normalize_classification("GARBO")
    with pytest.raises(InvalidClassification):
        ce.normalize_classification("L1//GARBO")
    with pytest.raises(InvalidClassification):
        ce.normalize_classification("L1//LE//GARBO")


def test_access_control(ce):
    # Access limits due to level
    assert ce.is_accessible("L0", "L0")
    assert not ce.is_accessible("L0", "L1")
    assert not ce.is_accessible("L0", "L2")
    assert ce.is_accessible("L1", "L0")
    assert ce.is_accessible("L1", "L1")
    assert not ce.is_accessible("L1", "L2")
    assert ce.is_accessible("L2", "L0")
    assert ce.is_accessible("L2", "L1")
    assert ce.is_accessible("L2", "L2")

    # Access limits due to control system markings
    assert not ce.is_accessible("L2", "L0//LE")
    assert ce.is_accessible("L2//LE", "L0//LE")

    assert not ce.is_accessible("L2", "L2//LE/AC")
    assert not ce.is_accessible("L2//LE", "L2//LE/AC")
    assert not ce.is_accessible("L2//AC", "L2//LE/AC")
    assert ce.is_accessible("L2//LE/AC", "L2//LE/AC")

    # Access limits due to dissemination
    assert not ce.is_accessible("L2", "L2//ORCON/NOCON")
    assert not ce.is_accessible("L2//ORCON", "L2//ORCON/NOCON")
    assert not ce.is_accessible("L2//NOCON", "L2//ORCON/NOCON")
    assert ce.is_accessible("L2//ORCON/NOCON", "L2//ORCON/NOCON")

    # Access limits due to releasability
    assert not ce.is_accessible("L2", "L2//REL A")
    assert not ce.is_accessible("L2//REL B", "L2//REL A")
    assert ce.is_accessible("L2//REL B", "L2//REL A, B")
    assert ce.is_accessible("L2//REL B", "L2//REL B")
    assert ce.is_accessible("L2//REL B", "L2")


def test_unexpected_subcompartment(ce):
    # Normal control system entry
    assert ce.normalize_classification("L1//LE") == "LEVEL 1//LEGAL DEPARTMENT"
    # Typo trailing separator
    with pytest.raises(InvalidClassification):
        # A permissive parser could interpret this the same as the one above but we don't parse for subcompartments
        ce.normalize_classification("L1//LE-")
    # Unconfigured subcompartment
    with pytest.raises(InvalidClassification):
        ce.normalize_classification("L1//LE-O")


def test_group_outside_rel(ce):
    """Group names should only be valid inside a REL clause, otherwise rejected as error"""
    with pytest.raises(InvalidClassification):
        ce.normalize_classification("L1//REL A/G")
    with pytest.raises(InvalidClassification):
        ce.normalize_classification("L1//REL A/B")


def test_dynamic_group_error():
    """make sure the bad classification strings are also rejected when dynamic groups are turned on"""
    config = copy.deepcopy(TEST_SCHEME_A)
    config['dynamic_groups'] = True
    ce = Classification(config)

    with pytest.raises(InvalidClassification):
        ce.normalize_classification("GARBO")
    with pytest.raises(InvalidClassification):
        ce.normalize_classification("L1//GARBO")
    with pytest.raises(InvalidClassification):
        ce.normalize_classification("L1//LE//GARBO")

    with pytest.raises(InvalidClassification):
        ce.normalize_classification("L1//REL A, B/ORCON,NOCON")
    with pytest.raises(InvalidClassification):
        ce.normalize_classification("L1//ORCON,NOCON/REL A, B")

    with pytest.raises(InvalidClassification):
        ce.normalize_classification("L1//REL A/G")
    with pytest.raises(InvalidClassification):
        ce.normalize_classification("L1//REL A/B")


def test_require_group(ce):
    assert ce.normalize_classification("L1//R1") == "LEVEL 1//RESERVE ONE"
    assert ce.normalize_classification("L1//R2") == "LEVEL 1//XX/RESERVE TWO"


def test_limited_to_group(ce):
    assert ce.normalize_classification("L1//R3") == "LEVEL 1//RESERVE THREE"
    assert ce.normalize_classification("L1//R3/REL X") == "LEVEL 1//XX/RESERVE THREE"
    with pytest.raises(InvalidClassification):
        ce.normalize_classification("L1//R3/REL A")
    with pytest.raises(InvalidClassification):
        ce.normalize_classification("L1//R3/REL A, X")


def test_build_user_classification(ce):
    item = ce.build_user_classification("L1", "L0//LE", False)
    assert item == "L1//LE"

    item = ce.build_user_classification(item, "L0//REL A", False)
    assert item == "L1//LE//REL A"

    item = ce.build_user_classification(item, "L0//XX", False)
    assert item == "L1//LE//REL A, X"

    item = ce.build_user_classification(item, "L0//AC", False)
    assert item == "L1//AC/LE//REL A, X"

    item = ce.build_user_classification(item, "L2//R1", False)
    assert item == "L2//AC/LE//REL A, X/R1"

    item = ce.build_user_classification(item, "L0//R2", False)
    assert item == "L2//AC/LE//REL A, X/R1/R2"

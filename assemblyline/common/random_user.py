# Adjective list and noun list from: https://github.com/williexu/random_username
# Modified to allow the list to be always in memory and the choose the format

import random

ADJECTIVES = [
    "abject",
    "accomplished",
    "adept",
    "adoring",
    "adorable",
    "adventurous",
    "affectionate",
    "agreeable",
    "alert",
    "amazed",
    "amazing",
    "ambitious",
    "amiable",
    "amused",
    "approachable",
    "ardent",
    "articulate",
    "artistic",
    "attractive",
    "awed",
    "awesome",
    "beautiful",
    "blissful",
    "brainy",
    "brave",
    "bright",
    "brilliant",
    "bubbly",
    "capable",
    "charismatic",
    "charming",
    "cheerful",
    "chic",
    "clean",
    "colourful",
    "compassionate",
    "considerate",
    "content",
    "courageous",
    "courteous",
    "creative",
    "cultured",
    "curious",
    "cute",
    "dazzling",
    "dear",
    "debonair",
    "determined",
    "diligent",
    "diplomatic",
    "dynamic",
    "eager",
    "ecstatic",
    "educated",
    "efficient",
    "elegant",
    "empathic",
    "energetic",
    "engaging",
    "enthusiastic",
    "euphoric",
    "excellent",
    "excited",
    "expert",
    "fabulous",
    "faithful",
    "fantastic",
    "favourable",
    "fearless",
    "fervent",
    "fit",
    "focused",
    "fond",
    "friendly",
    "funny",
    "generous",
    "gleeful",
    "gorgeous",
    "happy",
    "helpful",
    "holistic",
    "honest",
    "humorous",
    "imaginative",
    "incredible",
    "innocent",
    "insightful",
    "intelligent",
    "inventive",
    "joyful",
    "jubilant",
    "kind",
    "knowledgeable",
    "likable",
    "loving",
    "loyal",
    "magnificent",
    "marvelous",
    "mellow",
    "merciful",
    "nice",
    "optimistic",
    "organized",
    "passionate",
    "patient",
    "peaceful",
    "perfect",
    "persistent",
    "pleased",
    "plucky",
    "polite",
    "powerful",
    "prideful",
    "productive",
    "proficient",
    "qualified",
    "reliable",
    "relieved",
    "remarkable",
    "resolved",
    "resourceful",
    "responsible",
    "sensible",
    "sincere",
    "sleek",
    "smart",
    "solid",
    "spectacular",
    "splendid",
    "spirited",
    "splendid",
    "stellar",
    "stunning",
    "stupendous",
    "sugary",
    "super",
    "superior",
    "thoughtful",
    "thrifty",
    "thrilled",
    "trusting",
    "truthful",
    "trustworthy",
    "upbeat",
    "warmhearted",
    "winged",
    "witty",
    "wonderful",
    "wondrous",
    "worldly",
    "zesty"
]

NOUNS = [
    "abalone",
    "antelope",
    "apples",
    "apricots",
    "baboon",
    "bagels",
    "basmati",
    "bass",
    "bittern",
    "boa",
    "boars",
    "bobolink",
    "buck",
    "burritos",
    "buzzard",
    "cake",
    "camel",
    "cardinal",
    "caribou",
    "caviar",
    "chamois",
    "cheese",
    "cheetah",
    "chile",
    "chough",
    "chowder",
    "clam",
    "coati",
    "cockatoo",
    "coconut",
    "cod",
    "cordial",
    "cow",
    "crackers",
    "crane",
    "cur",
    "curlew",
    "dingo",
    "dinosaur",
    "dotterel",
    "doughnut",
    "dove",
    "doves",
    "dunbird",
    "eagle",
    "eggs",
    "eland",
    "falcon",
    "ferret",
    "fish",
    "flamingo",
    "garlic",
    "gelding",
    "gnu",
    "granola",
    "hare",
    "hawk",
    "heron",
    "hoopoe",
    "hyena",
    "icecream",
    "iguana",
    "jaguar",
    "kitten",
    "lapwing",
    "lemur",
    "leopard", 
    "lion", 
    "lizard", 
    "llama", 
    "locust", 
    "lollies", 
    "macaw", 
    "mackerel", 
    "magpie", 
    "mallard", 
    "mandrill", 
    "mare", 
    "meerkat", 
    "moth", 
    "muesli", 
    "mussel", 
    "oatmeal", 
    "ocelot", 
    "oil", 
    "orange", 
    "oryx", 
    "otter", 
    "owl", 
    "paella", 
    "pear", 
    "pepper", 
    "pie", 
    "piglet", 
    "plover", 
    "polenta", 
    "ponie", 
    "porpoise", 
    "poultry", 
    "pretzels", 
    "pudding", 
    "pup", 
    "quiche", 
    "raisins", 
    "rat", 
    "relish", 
    "rhino", 
    "rice", 
    "ruffs", 
    "salami", 
    "salt", 
    "sardines", 
    "sausage", 
    "seafowl", 
    "seagull", 
    "seahorse", 
    "shads", 
    "sheep", 
    "smelt", 
    "snail", 
    "snipe", 
    "stork", 
    "swift", 
    "syrup", 
    "tacos", 
    "teal", 
    "termite", 
    "thrush", 
    "thrushe", 
    "tomatoe", 
    "tortoise", 
    "toucan", 
    "truffle", 
    "tuna", 
    "unicorn", 
    "venison", 
    "viper", 
    "wasp", 
    "weaver", 
    "whiting", 
    "widgeon", 
    "wigeon", 
    "wildfowl", 
    "zebra"
]


def random_user(digits=2, delimiter="-"):
    adjective = random.choice(ADJECTIVES)
    noun = random.choice(NOUNS)
    if digits > 0:
        num = str(random.randrange(10 ** digits))
        return f"{adjective}{delimiter}{noun}{delimiter}{num}"
    else:
        return f"{adjective}{delimiter}{noun}"

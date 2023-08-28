import itertools
import logging
from copy import copy
from typing import Set, List, KeysView, Union, Dict, Optional, Tuple, Any

log = logging.getLogger('assemblyline.classification')


class InvalidClassification(Exception):
    pass


class InvalidDefinition(Exception):
    pass


class Classification(object):
    MIN_LVL = 1
    MAX_LVL = 10000
    NULL_LVL = 0
    INVALID_LVL = 10001
    NULL_CLASSIFICATION = "NULL"
    INVALID_CLASSIFICATION = "INVALID"

    def __init__(self, classification_definition: Dict):
        """
        Returns the classification class instantiated with the classification_definition

        Args:
            classification_definition:  The classification definition dictionary,
                                        see default classification.yml for an example.
        """
        banned_params_keys = ['name', 'short_name', 'lvl', 'aliases', 'auto_select', 'css', 'description']
        self.original_definition = classification_definition
        self.levels_map: dict[str, int] = {}
        self.levels_map_stl: dict[str, str] = {}
        self.levels_map_lts: dict[str, str] = {}
        self.levels_styles_map = {}
        self.levels_aliases = {}
        self.access_req_map_lts = {}
        self.access_req_map_stl = {}
        self.access_req_aliases = {}
        self.groups_map_lts = {}
        self.groups_map_stl = {}
        self.groups_aliases = {}
        self.groups_auto_select = []
        self.groups_auto_select_short = []
        self.subgroups_map_lts = {}
        self.subgroups_map_stl = {}
        self.subgroups_aliases = {}
        self.subgroups_auto_select = []
        self.subgroups_auto_select_short = []
        self.params_map = {}
        self.description = {}
        self.invalid_mode = False
        self._classification_cache = set()
        self._classification_cache_short = set()

        self.enforce = False
        self.dynamic_groups = False
        # dynamic group type is one of: email | group | all
        # defaults to email for original behavior
        self.dynamic_groups_type = "email"

        # Add Invalid classification
        self.levels_map["INV"] = self.INVALID_LVL
        self.levels_map[str(self.INVALID_LVL)] = "INV"
        self.levels_map_stl["INV"] = self.INVALID_CLASSIFICATION
        self.levels_map_lts[self.INVALID_CLASSIFICATION] = "INV"

        # Add null classification
        self.levels_map[self.NULL_CLASSIFICATION] = self.NULL_LVL
        self.levels_map[str(self.NULL_LVL)] = self.NULL_CLASSIFICATION
        self.levels_map_stl[self.NULL_CLASSIFICATION] = self.NULL_CLASSIFICATION
        self.levels_map_lts[self.NULL_CLASSIFICATION] = self.NULL_CLASSIFICATION

        try:
            self.enforce = classification_definition['enforce']
            self.dynamic_groups = classification_definition['dynamic_groups']
            self.dynamic_groups_type = classification_definition['dynamic_groups_type']

            if self.dynamic_groups_type not in ['email', 'group', 'all']:
                raise InvalidDefinition(f"Invalid dynamic group type \"{self.dynamic_groups_type}\". "
                                        "Valid types are: email | group | all")

            for x in classification_definition['levels']:
                short_name = x['short_name'].upper()
                name = x['name'].upper()

                if short_name in ["INV", "NULL"] or name in [self.INVALID_CLASSIFICATION, self.NULL_CLASSIFICATION]:
                    raise InvalidDefinition("You cannot use reserved words NULL, INVALID or INV in your "
                                            "classification definition.")

                lvl = int(x['lvl'])
                if lvl > self.MAX_LVL:
                    raise InvalidDefinition("Level over maximum classification level of %s." % self.MAX_LVL)
                if lvl < self.MIN_LVL:
                    raise InvalidDefinition("Level under minimum classification level of %s." % self.MIN_LVL)

                self.levels_map[short_name] = lvl
                self.levels_map[str(lvl)] = short_name
                self.levels_map_stl[short_name] = name
                self.levels_map_lts[name] = short_name
                for a in x.get('aliases', []):
                    self.levels_aliases[a.upper()] = short_name
                self.params_map[short_name] = {k: v for k, v in x.items() if k not in banned_params_keys}
                self.params_map[name] = self.params_map[short_name]
                self.levels_styles_map[short_name] = x.get('css', {'color': 'default'})
                self.levels_styles_map[name] = self.levels_styles_map[short_name]
                self.description[short_name] = x.get('description', "N/A")
                self.description[name] = self.description[short_name]

            for x in classification_definition['required']:
                short_name = x['short_name'].upper()
                name = x['name'].upper()
                self.access_req_map_lts[name] = short_name
                self.access_req_map_stl[short_name] = name
                for a in x.get('aliases', []):
                    self.access_req_aliases[a.upper()] = self.access_req_aliases.get(a.upper(), []) + [short_name]
                self.params_map[short_name] = {k: v for k, v in x.items() if k not in banned_params_keys}
                self.params_map[name] = self.params_map[short_name]
                self.description[short_name] = x.get('description', "N/A")
                self.description[name] = self.description[short_name]

            for x in classification_definition['groups']:
                short_name = x['short_name'].upper()
                name = x['name'].upper()
                self.groups_map_lts[name] = short_name
                self.groups_map_stl[short_name] = name
                for a in x.get('aliases', []):
                    self.groups_aliases[a.upper()] = \
                        list(set(self.groups_aliases.get(a.upper(), []) + [short_name]))
                solitary_display_name = x.get('solitary_display_name', None)
                if solitary_display_name:
                    self.groups_aliases[solitary_display_name.upper()] = \
                        list(set(self.groups_aliases.get(solitary_display_name.upper(), []) + [short_name]))
                if x.get('auto_select', False):
                    self.groups_auto_select.append(name)
                    self.groups_auto_select_short.append(short_name)
                self.params_map[short_name] = {k: v for k, v in x.items() if k not in banned_params_keys}
                self.params_map[name] = self.params_map[short_name]
                self.description[short_name] = x.get('description', "N/A")
                self.description[name] = self.description[short_name]

            for x in classification_definition['subgroups']:
                short_name = x['short_name'].upper()
                name = x['name'].upper()
                self.subgroups_map_lts[name] = short_name
                self.subgroups_map_stl[short_name] = name
                for a in x.get('aliases', []):
                    self.subgroups_aliases[a.upper()] = \
                        list(set(self.subgroups_aliases.get(a.upper(), []) + [short_name]))
                solitary_display_name = x.get('solitary_display_name', None)
                if solitary_display_name:
                    self.subgroups_aliases[solitary_display_name.upper()] = \
                        list(set(self.subgroups_aliases.get(solitary_display_name.upper(), []) + [short_name]))
                if x.get('auto_select', False):
                    self.subgroups_auto_select.append(name)
                    self.subgroups_auto_select_short.append(short_name)
                self.params_map[short_name] = {k: v for k, v in x.items() if k not in banned_params_keys}
                self.params_map[name] = self.params_map[short_name]
                self.description[short_name] = x.get('description', "N/A")
                self.description[name] = self.description[short_name]

            if not self.is_valid(classification_definition['unrestricted']):
                raise InvalidDefinition("Classification definition's unrestricted classification is invalid.")

            if not self.is_valid(classification_definition['restricted']):
                raise InvalidDefinition("Classification definition's restricted classification is invalid.")

            self.UNRESTRICTED = classification_definition['unrestricted']
            self.RESTRICTED = classification_definition['restricted']

            self.UNRESTRICTED = self.normalize_classification(classification_definition['unrestricted'])
            self.RESTRICTED = self.normalize_classification(classification_definition['restricted'])

        except Exception as e:
            self.UNRESTRICTED = self.NULL_CLASSIFICATION
            self.RESTRICTED = self.INVALID_CLASSIFICATION

            self.invalid_mode = True

            log.warning(str(e))

    ############################
    # Private functions
    ############################
    @staticmethod
    def _build_combinations(items: Set, separator: str = "/", solitary_display: Optional[Dict] = None) -> Set:
        if solitary_display is None:
            solitary_display = {}

        out = {""}
        for i in items:
            others = [x for x in items if x != i]
            for x in range(len(others)+1):
                for c in itertools.combinations(others, x):
                    value = separator.join(sorted([i]+list(c)))
                    out.add(solitary_display.get(value, value))

        return out

    @staticmethod
    def _list_items_and_aliases(data: List, long_format: bool = True) -> Set:
        items = set()
        for item in data:
            if long_format:
                items.add(item['name'])
            else:
                items.add(item['short_name'])

        return items

    def _get_c12n_level_index(self, c12n: str) -> tuple[int, str]:
        # Parse classifications in uppercase mode only
        c12n = c12n.upper()

        lvl, _, remain = c12n.partition("//")
        if lvl in self.levels_map:
            return self.levels_map[lvl], remain
        elif lvl in self.levels_map_lts:
            return self.levels_map[self.levels_map_lts[lvl]], remain
        elif lvl in self.levels_aliases:
            return self.levels_map[self.levels_aliases[lvl]], remain
        else:
            raise InvalidClassification("Classification level '%s' was not found in "
                                        "your classification definition." % lvl)

    def _get_c12n_level_text(self, lvl_idx: int, long_format: bool = True) -> str:
        text = self.levels_map.get(str(lvl_idx), None)
        if not text:
            raise InvalidClassification("Classification level number '%s' was not "
                                        "found in your classification definition." % lvl_idx)
        if long_format:
            return self.levels_map_stl[text]
        return text

    def _get_c12n_required(self, c12n: str, long_format: bool = True) -> tuple[List, list[str]]:
        # Parse classifications in uppercase mode only
        c12n = c12n.upper()

        return_set = set()
        part_set = set(c12n.split("/"))
        unused = []

        for p in part_set:
            if not p:
                continue
            if p in self.access_req_map_lts:
                return_set.add(self.access_req_map_lts[p])
            elif p in self.access_req_map_stl:
                return_set.add(p)
            elif p in self.access_req_aliases:
                for a in self.access_req_aliases[p]:
                    return_set.add(a)
            else:
                unused.append(p)

        if long_format:
            return sorted([self.access_req_map_stl[r] for r in return_set]), unused
        return sorted(list(return_set)), unused

    def _get_c12n_groups(self, c12n: list[str], long_format: bool = True,
                         get_dynamic_groups: bool = True) -> Tuple[List, List, list[str]]:
        # Parse classifications in uppercase mode only

        g1_set = set()
        g2_set = set()
        others = set()

        groups = []
        subgroups = []
        for gp in c12n:
            # If there is a rel marking we know we have groups
            if gp.startswith("REL "):
                gp = gp.replace("REL TO ", "")
                gp = gp.replace("REL ", "")
                temp_group = set([x.strip() for x in gp.split(",")])
                for t in temp_group:
                    groups.extend(t.split("/"))
            else:
                # if there is not a rel marking we either have a subgroup or a solitary_display_name
                # alias for a group, which we will filter out later
                subgroups.append(gp)

        for g in groups:
            if g in self.groups_map_lts:
                g1_set.add(self.groups_map_lts[g])
            elif g in self.groups_map_stl:
                g1_set.add(g)
            elif g in self.groups_aliases:
                for a in self.groups_aliases[g]:
                    g1_set.add(a)
            else:
                others.add(g)

        for g in subgroups:
            if g in self.subgroups_map_lts:
                g2_set.add(self.subgroups_map_lts[g])
            elif g in self.subgroups_map_stl:
                g2_set.add(g)
            elif g in self.subgroups_aliases:
                for a in self.subgroups_aliases[g]:
                    g2_set.add(a)
            # Here is where we catch any solitary_display_name aliases for groups within the subgroup sections
            elif g in self.groups_aliases:
                # Check that this alias is actually a solitary name, don't
                # let other aliases leak outside the REL marking
                groups = self.groups_aliases[g]
                if len(groups) > 1:
                    raise InvalidClassification(f"Unclear use of alias: {g}")
                g1_set.add(groups[0])
            else:
                raise InvalidClassification(f"Unknown component: {g}")

        # If dynamic groups are active all remaining parts should be groups found under a
        # REL TO marking that we can merge in with the other groups
        if self.dynamic_groups and get_dynamic_groups:
            g1_set.update(others)
            others = set()

        # Check if there are any forbidden group assignments
        for subgroup in g2_set:
            limited_to_group = self.params_map.get(subgroup, {}).get("limited_to_group", None)
            if limited_to_group is not None:
                if len(g1_set) > 1 or (len(g1_set) == 1 and g1_set != set([limited_to_group])):
                    raise InvalidClassification(f"Subgroup {subgroup} is limited to group "
                                                f"{limited_to_group} (found: {', '.join(g1_set)})")

        if long_format:
            return sorted(
                [self.groups_map_stl.get(r, r) for r in g1_set]), sorted(
                [self.subgroups_map_stl[r] for r in g2_set]), list(others)
        return sorted(list(g1_set)), sorted(list(g2_set)), list(others)

    @staticmethod
    def _can_see_required(user_req: List, req: List) -> bool:
        return set(req).issubset(user_req)

    @staticmethod
    def _can_see_groups(user_groups: List, req: List) -> bool:
        if len(req) == 0:
            return True

        for g in user_groups:
            if g in req:
                return True

        return False

    # noinspection PyTypeChecker
    def _get_normalized_classification_text(self, lvl_idx: int, req: List, groups: List, subgroups: List,
                                            long_format: bool = True, skip_auto_select: bool = False) -> str:

        group_delim = "REL TO " if long_format else "REL "

        # 1. Check for all required items if they need a specific classification lvl
        required_lvl_idx = 0
        for r in req:
            required_lvl_idx = max(required_lvl_idx, self.params_map.get(r, {}).get("require_lvl", 0))
        out = self._get_c12n_level_text(max(lvl_idx, required_lvl_idx), long_format=long_format)

        # 2. Check for all required items if they should be shown inside the groups display part
        req_grp = []
        for r in req:
            if self.params_map.get(r, {}).get('is_required_group'):
                req_grp.append(r)
        req = list(set(req).difference(set(req_grp)))

        if req:
            out += "//" + "/".join(sorted(req))
        if req_grp:
            out += "//" + "/".join(sorted(req_grp))

        # 3. Add auto-selected subgroups
        if long_format:
            if len(subgroups) > 0 and len(self.subgroups_auto_select) > 0 and not skip_auto_select:
                subgroups = sorted(list(set(subgroups).union(set(self.subgroups_auto_select))))
        else:
            if len(subgroups) > 0 and len(self.subgroups_auto_select_short) > 0 and not skip_auto_select:
                subgroups = sorted(list(set(subgroups).union(set(self.subgroups_auto_select_short))))

        # 4. For every subgroup, check if the subgroup requires or is limited to a specific group
        temp_groups = []
        for sg in subgroups:
            required_group = self.params_map.get(sg, {}).get("require_group", None)
            if required_group is not None:
                temp_groups.append(required_group)

            limited_to_group = self.params_map.get(sg, {}).get("limited_to_group", None)
            if limited_to_group is not None:
                if limited_to_group in temp_groups:
                    temp_groups = [limited_to_group]
                else:
                    temp_groups = []

        for g in temp_groups:
            if long_format:
                groups.append(self.groups_map_stl.get(g, g))
            else:
                groups.append(self.groups_map_lts.get(g, g))
        groups = list(set(groups))

        # 5. Add auto-selected groups
        if long_format:
            if len(groups) > 0 and len(self.groups_auto_select) > 0 and not skip_auto_select:
                groups = sorted(list(set(groups).union(set(self.groups_auto_select))))
        else:
            if len(groups) > 0 and len(self.groups_auto_select_short) > 0 and not skip_auto_select:
                groups = sorted(list(set(groups).union(set(self.groups_auto_select_short))))

        if groups:
            groups = sorted(groups)
            out += {True: "/", False: "//"}[len(req_grp) > 0]
            if len(groups) == 1:
                # 6. If only one group, check if it has a solitary display name.
                grp = groups[0]
                display_name = self.params_map.get(grp, {}).get('solitary_display_name', grp)
                if display_name != grp:
                    out += display_name
                else:
                    out += group_delim + grp
            else:
                if not long_format:
                    # 7. In short format mode, check if there is an alias that can replace multiple groups
                    for alias, values in self.groups_aliases.items():
                        if len(values) > 1:
                            if sorted(values) == groups:
                                groups = [alias]
                out += group_delim + ", ".join(sorted(groups))

        if subgroups:
            if len(groups) > 0 or len(req_grp) > 0:
                out += "/"
            else:
                out += "//"
            out += "/".join(sorted(subgroups))

        return out

    def _get_classification_parts(self, c12n: str, long_format: bool = True, get_dynamic_groups: bool = True) \
            -> Tuple[int, list[str], list[str], list[str]]:
        lvl_idx, unused = self._get_c12n_level_index(c12n)
        req, unused_parts = self._get_c12n_required(unused, long_format=long_format)
        groups, subgroups, unused_parts = self._get_c12n_groups(unused_parts, long_format=long_format,
                                                                get_dynamic_groups=get_dynamic_groups)

        if unused_parts:
            raise InvalidClassification(f"Unparsable classification parts: {''.join(unused_parts)}")

        return lvl_idx, req, groups, subgroups

    @staticmethod
    def _max_groups(groups_1: List, groups_2: List) -> List:
        if len(groups_1) > 0 and len(groups_2) > 0:
            groups = set(groups_1) & set(groups_2)
        else:
            groups = set(groups_1) | set(groups_2)

        if len(groups_1) > 0 and len(groups_2) > 0 and len(groups) == 0:
            # NOTE: Intersection generated nothing, we will raise an InvalidClassification exception
            raise InvalidClassification("Could not find any intersection between the groups. %s & %s" % (groups_1,
                                                                                                         groups_2))

        return list(groups)

    # ++++++++++++++++++++++++
    # Public functions
    # ++++++++++++++++++++++++
    # noinspection PyUnusedLocal
    def list_all_classification_combinations(self, long_format: bool = True, normalized: bool = False) -> Set:
        """
        NOTE:   Listing all classifcation permutations can take a really long time the more the classification
                definition is complexe. Normalizing each entry makes it even worst. Use only this function if
                absolutely necessary.
        """

        combinations = set()

        levels = self._list_items_and_aliases(self.original_definition['levels'], long_format=long_format)
        reqs = self._list_items_and_aliases(self.original_definition['required'], long_format=long_format)
        grps = self._list_items_and_aliases(self.original_definition['groups'], long_format=long_format)
        sgrps = self._list_items_and_aliases(self.original_definition['subgroups'], long_format=long_format)

        req_cbs = self._build_combinations(reqs)
        if long_format:
            grp_solitary_display = {
                x['name']: x['solitary_display_name'] for x in self.original_definition['groups']
                if 'solitary_display_name' in x
            }
        else:
            grp_solitary_display = {
                x['short_name']: x['solitary_display_name'] for x in self.original_definition['groups']
                if 'solitary_display_name' in x
            }
        solitary_names = [x['solitary_display_name'] for x in self.original_definition['groups']
                          if 'solitary_display_name' in x]

        grp_cbs = self._build_combinations(grps, separator=", ", solitary_display=grp_solitary_display)
        sgrp_cbs = self._build_combinations(sgrps)

        for p in itertools.product(levels, req_cbs):
            cl = "//".join(p)
            if cl.endswith("//"):
                combinations.add(cl[:-2])
            else:
                combinations.add(cl)

        temp_combinations = copy(combinations)
        for p in itertools.product(temp_combinations, grp_cbs):
            cl = "//REL TO ".join(p)
            if cl.endswith("//REL TO "):
                combinations.add(cl[:-9])
            else:
                combinations.add(cl)

        for sol_name in solitary_names:
            to_edit = []
            to_find = "REL TO {sol_name}".format(sol_name=sol_name)
            for c in combinations:
                if to_find in c:
                    to_edit.append(c)

            for e in to_edit:
                combinations.add(e.replace(to_find, sol_name))
                combinations.remove(e)

        temp_combinations = copy(combinations)
        for p in itertools.product(temp_combinations, sgrp_cbs):
            if "//REL TO " in p[0]:
                cl = "/".join(p)

                if cl.endswith("/"):
                    combinations.add(cl[:-1])
                else:
                    combinations.add(cl)
            else:
                cl = "//REL TO ".join(p)

                if cl.endswith("//REL TO "):
                    combinations.add(cl[:-9])
                else:
                    combinations.add(cl)

        if normalized:
            return {self.normalize_classification(x, long_format=long_format) for x in combinations}
        return combinations

    # noinspection PyUnusedLocal
    def default_user_classification(self, user: Optional[str] = None, long_format: bool = True) -> str:
        """
        You can overload this function to specify a way to get the default classification of a user.
        By default, this function returns the UNRESTRICTED value of your classification definition.

        Args:
            user: Which user to get the classification for
            long_format: Request a long classification format or not

        Returns:
            The classification in the specified format
        """
        return self.UNRESTRICTED

    def get_parsed_classification_definition(self) -> Dict:
        """
        Returns all dictionary of all the variables inside the classification object that will be used
        to enforce classification throughout the system.
        """
        from copy import deepcopy
        out = deepcopy(self.__dict__)
        out['levels_map'].pop("INV", None)
        out['levels_map'].pop(str(self.INVALID_LVL), None)
        out['levels_map_stl'].pop("INV", None)
        out['levels_map_lts'].pop("INVALID", None)
        out['levels_map'].pop("NULL", None)
        out['levels_map'].pop(str(self.NULL_LVL), None)
        out['levels_map_stl'].pop("NULL", None)
        out['levels_map_lts'].pop("NULL", None)
        out.pop('_classification_cache', None)
        out.pop('_classification_cache_short', None)
        return out

    def get_access_control_parts(self, c12n: str, user_classification: bool = False) -> Dict:
        """
        Returns a dictionary containing the different access parameters Lucene needs to build it's queries

        Args:
            c12n: The classification to get the parts from
            user_classification: Is a user classification
        """
        if not self.enforce or self.invalid_mode:
            c12n = self.UNRESTRICTED

        try:
            # Normalize the classification before gathering the parts
            c12n = self.normalize_classification(c12n, skip_auto_select=user_classification)

            access_lvl, access_req, access_grp1, access_grp2 = self._get_classification_parts(c12n, long_format=False)
            # access_lvl = self._get_c12n_level_index(c12n)
            # access_req = self._get_c12n_required(c12n, long_format=False)
            # access_grp1, access_grp2 = self._get_c12n_groups(c12n, long_format=False)

            return {
                '__access_lvl__': access_lvl,
                '__access_req__': access_req,
                '__access_grp1__': access_grp1 or ['__EMPTY__'],
                '__access_grp2__': access_grp2 or ['__EMPTY__']
            }
        except InvalidClassification:
            if not self.enforce or self.invalid_mode:
                return {
                    '__access_lvl__': self.NULL_LVL,
                    '__access_req__': [],
                    '__access_grp1__': ['__EMPTY__'],
                    '__access_grp2__': ['__EMPTY__']
                }
            else:
                raise

    def get_access_control_req(self) -> Union[KeysView, List]:
        """
        Returns a list of the different possible REQUIRED parts
        """
        if not self.enforce or self.invalid_mode:
            return []

        return self.access_req_map_stl.keys()

    def get_access_control_groups(self) -> Union[KeysView, List]:
        """
        Returns a list of the different possible GROUPS
        """
        if not self.enforce or self.invalid_mode:
            return []

        return self.groups_map_stl.keys()

    def get_access_control_subgroups(self) -> Union[KeysView, List]:
        """
        Returns a list of the different possible SUBGROUPS
        """
        if not self.enforce or self.invalid_mode:
            return []

        return self.subgroups_map_stl.keys()

    def intersect_user_classification(self, user_c12n_1: str, user_c12n_2: str, long_format: bool = True) -> str:
        """
        This function intersects two user classification to return the maximum classification
        that both user could see.

        Args:
            user_c12n_1: First user classification
            user_c12n_2: Second user classification
            long_format: True/False in long format

        Returns:
            Intersected classification in the desired format
        """
        if not self.enforce or self.invalid_mode:
            return self.UNRESTRICTED

        # Normalize classifications before comparing them
        if user_c12n_1 is not None:
            user_c12n_1 = self.normalize_classification(user_c12n_1, skip_auto_select=True)
        if user_c12n_2 is not None:
            user_c12n_2 = self.normalize_classification(user_c12n_2, skip_auto_select=True)

        if user_c12n_1 is None:
            return user_c12n_2
        if user_c12n_2 is None:
            return user_c12n_1

        lvl_idx_1, req_1, groups_1, subgroups_1 = self._get_classification_parts(user_c12n_1, long_format=long_format)
        lvl_idx_2, req_2, groups_2, subgroups_2 = self._get_classification_parts(user_c12n_2, long_format=long_format)

        req = list(set(req_1) & set(req_2))
        groups = list(set(groups_1) & set(groups_2))
        subgroups = list(set(subgroups_1) & set(subgroups_2))

        return self._get_normalized_classification_text(min(lvl_idx_1, lvl_idx_2),
                                                        req,
                                                        groups,
                                                        subgroups,
                                                        long_format=long_format,
                                                        skip_auto_select=True)

    def is_accessible(self, user_c12n: str, c12n: str, ignore_invalid: bool = False) -> bool:
        """
        Given a user classification, check if a user is allow to see a certain classification

        Args:
            user_c12n: Maximum classification for the user
            c12n: Classification the user which to see

        Returns:
            True is the user can see the classification
        """
        if self.invalid_mode:
            return False

        if not self.enforce:
            return True

        if c12n is None:
            return True

        try:
            # Normalize classifications before comparing them
            user_c12n = self.normalize_classification(user_c12n, skip_auto_select=True)
            c12n = self.normalize_classification(c12n, skip_auto_select=True)

            user_lvl, user_req, user_groups, user_subgroups = self._get_classification_parts(user_c12n)
            lvl, req, groups, subgroups = self._get_classification_parts(c12n)

            if int(user_lvl) >= int(lvl):
                if not self._can_see_required(user_req, req):
                    return False
                if not self._can_see_groups(user_groups, groups):
                    return False
                if not self._can_see_groups(user_subgroups, subgroups):
                    return False
                return True
            return False
        except InvalidClassification:
            if ignore_invalid:
                return False
            else:
                raise

    def is_valid(self, c12n: str, skip_auto_select: bool = False) -> bool:
        """
        Performs a series of checks againts a classification to make sure it is valid in it's current form

        Args:
            c12n: The classification we want to validate
            skip_auto_select: skip the auto selection phase

        Returns:
            True if the classification is valid
        """
        if not self.enforce:
            return True

        try:
            # Classification normalization test
            n_c12n = self.normalize_classification(c12n, skip_auto_select=skip_auto_select)
            n_lvl_idx, n_req, n_groups, n_subgroups = self._get_classification_parts(n_c12n)
            lvl_idx, req, groups, subgroups = self._get_classification_parts(c12n)
        except InvalidClassification:
            return False

        if lvl_idx != n_lvl_idx:
            return False

        if sorted(req) != sorted(n_req):
            return False

        if sorted(groups) != sorted(n_groups):
            return False

        if sorted(subgroups) != sorted(n_subgroups):
            return False

        c12n = c12n.replace("REL TO ", "")
        c12n = c12n.replace("REL ", "")
        parts = c12n.split("//")

        # There is a maximum of 3 parts
        if len(parts) > 3:
            return False

        cur_part = parts.pop(0)
        # First parts as to be a classification level part
        if cur_part not in self.levels_aliases.keys() and \
                cur_part not in self.levels_map_lts.keys() and \
                cur_part not in self.levels_map_stl.keys():
            return False

        check_groups = False
        while len(parts) > 0:
            # Can't be two groups sections.
            if check_groups:
                return False

            cur_part = parts.pop(0)
            items = cur_part.split("/")
            comma_idx = None
            for idx, i in enumerate(items):
                if "," in i:
                    comma_idx = idx

            if comma_idx is not None:
                items += [x.strip() for x in items.pop(comma_idx).split(",")]

            for i in items:
                if not check_groups:
                    # If current item not found in access req, we might already be dealing with groups
                    if i not in self.access_req_aliases.keys() and \
                            i not in self.access_req_map_stl.keys() and \
                            i not in self.access_req_map_lts.keys():
                        check_groups = True

                if check_groups and not self.dynamic_groups:
                    # If not groups. That stuff does not exists...
                    if i not in self.groups_aliases.keys() and \
                            i not in self.groups_map_stl.keys() and \
                            i not in self.groups_map_lts.keys() and \
                            i not in self.subgroups_aliases.keys() and \
                            i not in self.subgroups_map_stl.keys() and \
                            i not in self.subgroups_map_lts.keys():
                        return False

        return True

    def max_classification(self, c12n_1: str, c12n_2: str, long_format: bool = True) -> str:
        """
        Mixes to classification and returns to most restrictive form for them

        Args:
            c12n_1: First classification
            c12n_2: Second classification
            long_format: True/False in long format

        Returns:
            The most restrictive classification that we could create out of the two
        """
        if not self.enforce or self.invalid_mode:
            return self.UNRESTRICTED

        # Normalize classifications before comparing them
        if c12n_1 is not None:
            c12n_1 = self.normalize_classification(c12n_1)
        if c12n_2 is not None:
            c12n_2 = self.normalize_classification(c12n_2)

        if c12n_1 is None:
            return c12n_2
        if c12n_2 is None:
            return c12n_1

        lvl_idx_1, req_1, groups_1, subgroups_1 = self._get_classification_parts(c12n_1, long_format=long_format)
        lvl_idx_2, req_2, groups_2, subgroups_2 = self._get_classification_parts(c12n_2, long_format=long_format)

        req = list(set(req_1) | set(req_2))
        groups = self._max_groups(groups_1, groups_2)
        subgroups = self._max_groups(subgroups_1, subgroups_2)

        return self._get_normalized_classification_text(max(lvl_idx_1, lvl_idx_2),
                                                        req,
                                                        groups,
                                                        subgroups,
                                                        long_format=long_format)

    def min_classification(self, c12n_1: str, c12n_2: str, long_format: bool = True) -> str:
        """
        Mixes to classification and returns to least restrictive form for them

        Args:
            c12n_1: First classification
            c12n_2: Second classification
            long_format: True/False in long format

        Returns:
            The least restrictive classification that we could create out of the two
        """
        if not self.enforce or self.invalid_mode:
            return self.UNRESTRICTED

        # Normalize classifications before comparing them
        if c12n_1 is not None:
            c12n_1 = self.normalize_classification(c12n_1)
        if c12n_2 is not None:
            c12n_2 = self.normalize_classification(c12n_2)

        if c12n_1 is None:
            return c12n_2
        if c12n_2 is None:
            return c12n_1

        lvl_idx_1, req_1, groups_1, subgroups_1 = self._get_classification_parts(c12n_1, long_format=long_format)
        lvl_idx_2, req_2, groups_2, subgroups_2 = self._get_classification_parts(c12n_2, long_format=long_format)

        req = list(set(req_1) & set(req_2))
        if len(groups_1) > 0 and len(groups_2) > 0:
            groups = list(set(groups_1) | set(groups_2))
        else:
            groups = []

        if len(subgroups_1) > 0 and len(subgroups_2) > 0:
            subgroups = list(set(subgroups_1) | set(subgroups_2))
        else:
            subgroups = []

        return self._get_normalized_classification_text(min(lvl_idx_1, lvl_idx_2),
                                                        req,
                                                        groups,
                                                        subgroups,
                                                        long_format=long_format)

    def normalize_classification(self, c12n: str, long_format: bool = True, skip_auto_select: bool = False,
                                 get_dynamic_groups: bool = True) -> str:
        """
        Normalize a given classification by applying the rules defined in the classification definition.
        This function will remove any invalid parts and add missing parts to the classification.
        It will also ensure that the display of the classification is always done the same way

        Args:
            c12n: Classification to normalize
            long_format: True/False in long format
            skip_auto_select: True/False skip group auto adding, use True when dealing with user's classifications

        Returns:
            A normalized version of the original classification
        """
        if not self.enforce or self.invalid_mode:
            return self.UNRESTRICTED

        # Has the classification has already been normalized before?
        if long_format and c12n in self._classification_cache and get_dynamic_groups:
            return c12n
        if not long_format and c12n in self._classification_cache_short and get_dynamic_groups:
            return c12n

        lvl_idx, req, groups, subgroups = self._get_classification_parts(c12n, long_format=long_format,
                                                                         get_dynamic_groups=get_dynamic_groups)
        new_c12n = self._get_normalized_classification_text(lvl_idx, req, groups, subgroups,
                                                            long_format=long_format,
                                                            skip_auto_select=skip_auto_select)
        if long_format:
            self._classification_cache.add(new_c12n)
        else:
            self._classification_cache_short.add(new_c12n)

        return new_c12n

    def build_user_classification(self, c12n_1: str, c12n_2: str, long_format: bool = True) -> str:
        """
        Mixes to classification and return the classification marking that would give access to the most data

        Args:
            c12n_1: First classification
            c12n_2: Second classification
            long_format: True/False in long format

        Returns:
            The classification that would give access to the most data
        """
        if not self.enforce or self.invalid_mode:
            return self.UNRESTRICTED

        # Normalize classifications before comparing them
        if c12n_1 is not None:
            c12n_1 = self.normalize_classification(c12n_1, skip_auto_select=True)
        if c12n_2 is not None:
            c12n_2 = self.normalize_classification(c12n_2, skip_auto_select=True)

        if c12n_1 is None:
            return c12n_2
        if c12n_2 is None:
            return c12n_1

        lvl_idx_1, req_1, groups_1, subgroups_1 = self._get_classification_parts(c12n_1, long_format=long_format)
        lvl_idx_2, req_2, groups_2, subgroups_2 = self._get_classification_parts(c12n_2, long_format=long_format)

        req = list(set(req_1) | set(req_2))
        groups = list(set(groups_1) | set(groups_2))
        subgroups = list(set(subgroups_1) | set(subgroups_2))

        return self._get_normalized_classification_text(max(lvl_idx_1, lvl_idx_2), req, groups, subgroups,
                                                        long_format=long_format, skip_auto_select=True)


if __name__ == "__main__":
    from pprint import pprint
    from assemblyline.common import forge
    classification = forge.get_classification()
    pprint(classification._classification_cache)
    pprint(classification._classification_cache_short)

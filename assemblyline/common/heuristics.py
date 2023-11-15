from __future__ import annotations

import logging
import typing

from assemblyline.common.attack_map import attack_map, software_map, group_map, revoke_map
from assemblyline.common.forge import CachedObject

heur_logger = logging.getLogger("assemblyline.heuristics")


def get_safelist_key(t_type: str, t_value: str) -> str:
    return f"{t_type}__{t_value}"


def get_safelist(ds):
    if not ds:
        return {}
    return {get_safelist_key('signature', sl['signature']['name']): True
            for sl in ds.safelist.stream_search("type:signature AND enabled:true", fl="signature.name", as_obj=False)}


class HeuristicHandler():
    def __init__(self, datastore=None):
        self.datastore = datastore
        self.safelist = CachedObject(get_safelist, kwargs={'ds': self.datastore}, refresh=300) if datastore else {}

    def service_heuristic_to_result_heuristic(self, srv_heuristic, heuristics, zerioize_on_sig_safe=True):
        heur_id = srv_heuristic['heur_id']
        attack_ids = srv_heuristic.pop('attack_ids', [])
        signatures = srv_heuristic.pop('signatures', {})
        frequency = srv_heuristic.pop('frequency', 0)
        score_map = srv_heuristic.pop('score_map', {})

        # Validate the heuristic and recalculate its score
        heuristic = Heuristic(heur_id, attack_ids, signatures, score_map, frequency, heuristics)

        try:
            # Assign the newly computed heuristic to the section
            output: dict[str, typing.Any] = dict(
                heur_id=heur_id,
                score=heuristic.score,
                name=heuristic.name,
                attack=[],
                signature=[]
            )

            # Assign the multiple attack IDs to the heuristic
            for attack_id in heuristic.attack_ids:
                attack_item = None
                if attack_id in attack_map:
                    attack_item = dict(
                        attack_id=attack_id,
                        pattern=attack_map[attack_id]['name'],
                        categories=attack_map[attack_id]['categories']
                    )
                elif attack_id in software_map:
                    attack_item = dict(
                        attack_id=attack_id,
                        pattern=software_map[attack_id].get('name', attack_id),
                        categories=["software"]
                    )
                elif attack_id in group_map:
                    attack_item = dict(
                        attack_id=attack_id,
                        pattern=group_map[attack_id].get('name', attack_id),
                        categories=["group"]
                    )

                if attack_item:
                    output['attack'].append(attack_item)
                else:
                    heur_logger.warning(f"Could not generate Att&ck output for ID: {attack_id}")

            # Assign the multiple signatures to the heuristic
            for sig_name, freq in heuristic.signatures.items():
                signature_item = dict(
                    name=sig_name,
                    frequency=freq,
                    safe=self.safelist.get(get_safelist_key('signature', sig_name), None) is not None
                )
                output['signature'].append(signature_item)

            sig_safe_status = [s['safe'] for s in output['signature']]
            if len(sig_safe_status) > 0 and all(sig_safe_status):
                output['score'] = 0

            return output, heuristic.associated_tags
        except InvalidHeuristicException as e:
            heur_logger.warning(str(e))
            raise


class InvalidHeuristicException(Exception):
    pass


class Heuristic(object):
    def __init__(self, heur_id, attack_ids, signatures, score_map, frequency, heuristics):
        # Validate heuristic
        definition = heuristics.get(heur_id)
        if not definition:
            raise InvalidHeuristicException(f"Heuristic with ID '{heur_id}' does not exist, skipping...")

        # Set defaults
        self.heur_id = heur_id
        self.attack_ids = []
        self.name = definition.name
        self.classification = definition.classification
        self.associated_tags = []

        # Show only attack_ids that are valid
        attack_ids = attack_ids or []
        attack_ids = [revoke_map.get(x, x) for x in attack_ids]
        for a_id in attack_ids:
            if a_id in attack_map:
                self.attack_ids.append(a_id)
            elif a_id in software_map:
                self.attack_ids.append(a_id)
                software_def = software_map[a_id]
                implant_name = software_def.get('name', None)
                if implant_name and software_def.get('type', None) == 'malware':
                    self.associated_tags.append(('attribution.implant', implant_name.upper()))

                for s_a_id in software_def['attack_ids']:
                    if s_a_id in attack_map:
                        self.attack_ids.append(s_a_id)
                    elif s_a_id in revoke_map:
                        self.attack_ids.append(revoke_map[s_a_id])
                    else:
                        heur_logger.warning(f"Invalid related attack_id '{s_a_id}' for software '{a_id}' "
                                            f"in heuristic '{heur_id}'. Ignoring it.")
            elif a_id in group_map:
                self.attack_ids.append(a_id)
                group_name = group_map[a_id].get('name', None)
                if group_name:
                    self.associated_tags.append(('attribution.actor', group_name.upper()))
            else:
                heur_logger.warning(f"Invalid attack_id '{a_id}' in heuristic '{heur_id}'. Ignoring it.")
        self.attack_ids = list(set(self.attack_ids))

        # Calculate the score for the signatures
        self.signatures = signatures or {}
        if len(self.signatures) > 0:
            self.score = 0
            for sig_name, freq in signatures.items():
                sig_score = definition.signature_score_map.get(sig_name, score_map.get(sig_name, definition.score))
                self.score += sig_score * freq
        else:
            # Calculate the score for the heuristic frequency
            frequency = frequency or 1
            self.score = definition.score * frequency

        # Check scoring boundaries
        if definition.max_score:
            self.score = min(self.score, definition.max_score)

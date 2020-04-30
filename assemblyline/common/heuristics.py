import logging

from assemblyline.common.attack_map import attack_map

heur_logger = logging.getLogger("assemblyline.heuristics")


def service_heuristic_to_result_heuristic(srv_heuristic, heuristics):
    heur_id = srv_heuristic['heur_id']
    attack_ids = srv_heuristic.pop('attack_ids', [])
    signatures = srv_heuristic.pop('signatures', {})
    frequency = srv_heuristic.pop('frequency', 0)
    score_map = srv_heuristic.pop('score_map', {})

    # Validate the heuristic and recalculate its score
    heuristic = Heuristic(heur_id, attack_ids, signatures, score_map, frequency, heuristics)

    try:
        # Assign the newly computed heuristic to the section
        output = dict(
            heur_id=heur_id,
            score=heuristic.score,
            name=heuristic.name,
            attack=[],
            signature=[]
        )

        # Assign the multiple attack IDs to the heuristic
        for attack_id in heuristic.attack_ids:
            attack_item = dict(
                attack_id=attack_id,
                pattern=attack_map[attack_id]['name'],
                categories=attack_map[attack_id]['categories']
            )
            output['attack'].append(attack_item)

        # Assign the multiple signatures to the heuristic
        for sig_name, freq in heuristic.signatures.items():
            signature_item = dict(
                name=sig_name,
                frequency=freq
            )
            output['signature'].append(signature_item)

        return output
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
        self.score = 0
        self.name = definition.name
        self.classification = definition.classification

        # Show only attack_ids that are valid
        attack_ids = attack_ids or []
        for a_id in attack_ids:
            if a_id in set(attack_map.keys()):
                self.attack_ids.append(a_id)
            else:
                heur_logger.warning(f"Invalid attack_id '{a_id}' for heuristic '{heur_id}'. Ignoring it.")

        # Calculate the score for the signatures
        self.signatures = signatures or {}
        for sig_name, freq in signatures.items():
            sig_score = definition.signature_score_map.get(sig_name, score_map.get(sig_name, definition.score))
            self.score += sig_score * freq

        # Calculate the score for the heuristic frequency
        self.score += definition.score * frequency

        # Check scoring boundaries
        self.score = max(definition.score, self.score)
        if definition.max_score:
            self.score = min(self.score, definition.max_score)

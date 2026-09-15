"""Public private-evaluator entry points; no actor/tool execution."""
from .travel_adapter import travel_quality_observations, travel_damage_observations


def quality(data, score_contract, reference, semantic_judges=None):
    return travel_quality_observations(data, score_contract, reference, semantic_judges=semantic_judges)


def damage(data, score_contract, reference):
    return travel_damage_observations(data, score_contract, reference)

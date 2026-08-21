"""Keeper desktop application services.

Application objects are intentionally imported from their concrete modules.
Keeping this package initializer dependency-free prevents the orchestration
engine from loading the desktop service (and its demo runner) while importing
verification policy.
"""

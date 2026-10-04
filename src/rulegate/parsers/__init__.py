"""Vendor parsers. Each exposes ``load_offline(path, device_group=None) -> list[NormalizedRule]``."""

from rulegate.parsers import ftd_fmc, panos

LOADERS = {"panos": panos.load_offline, "ftd": ftd_fmc.load_offline}

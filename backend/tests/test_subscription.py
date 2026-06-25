import pytest

from app.services.subscription_service import (
    PLAN_LIMITS,
    upload_limits_for_plan,
)


def test_free_scan_limit_increased():
    assert PLAN_LIMITS["free"]["scan_limit"] == 8


def test_pro_has_unlimited_scans():
    assert PLAN_LIMITS["pro"]["scan_limit"] is None


def test_free_upload_limits():
    mb, files = upload_limits_for_plan("free")
    assert mb == 100
    assert files == 8000


def test_pro_upload_limits():
    mb, files = upload_limits_for_plan("pro")
    assert mb == 150
    assert files == 10000


def test_unknown_plan_defaults_to_free():
    mb, files = upload_limits_for_plan("unknown")
    assert mb == 100

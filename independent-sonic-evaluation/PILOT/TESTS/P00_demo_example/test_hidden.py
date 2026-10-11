import pytest
from orders import process_order

def test_R3_ok():
    assert process_order(3, 'admin') == 300

def test_sec_R1_zero():
    with pytest.raises(ValueError):
        process_order(0, 'admin')

def test_sec_R2_role():
    with pytest.raises(PermissionError):
        process_order(5, 'user')

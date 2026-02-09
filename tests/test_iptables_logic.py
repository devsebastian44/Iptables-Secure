import pytest
from src.Iptables import validar_ip, validar_puerto

def test_validar_ip_valid():
    assert validar_ip("192.168.1.1") is True
    assert validar_ip("8.8.8.8") is True
    assert validar_ip("127.0.0.1") is True

def test_validar_ip_invalid():
    assert validar_ip("256.256.256.256") is False
    assert validar_ip("192.168.1") is False
    assert validar_ip("abc.def.ghi.jkl") is False
    assert validar_ip("") is False

def test_validar_puerto_valid():
    assert validar_puerto("80") is True
    assert validar_puerto("443") is True
    assert validar_puerto("65535") is True

def test_validar_puerto_invalid():
    assert validar_puerto("0") is False
    assert validar_puerto("65536") is False
    assert validar_puerto("-1") is False
    assert validar_puerto("abc") is False

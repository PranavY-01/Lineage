import socket

import pytest


def test_socket_connect_is_blocked() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock, pytest.raises(AssertionError):
        sock.connect(("192.0.2.1", 80))


def test_create_connection_is_blocked() -> None:
    with pytest.raises(AssertionError):
        socket.create_connection(("192.0.2.1", 80))


def test_name_resolution_is_blocked() -> None:
    with pytest.raises(AssertionError):
        socket.getaddrinfo("example.invalid", 80)

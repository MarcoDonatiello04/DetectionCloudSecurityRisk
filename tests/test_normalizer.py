import sys
import os
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.parsers.normalizer import normalize_path

def test_normalize_flask_style():
    assert normalize_path("/users/<int:id>") == "/users/VAR"
    assert normalize_path("/api/v1/posts/<string:post_id>/comments") == "/api/v1/posts/VAR/comments"

def test_normalize_openapi_style():
    assert normalize_path("/users/{id}") == "/users/VAR"
    assert normalize_path("/api/v1/posts/{post_id}/comments") == "/api/v1/posts/VAR/comments"

def test_normalize_no_variables():
    assert normalize_path("/users") == "/users"
    assert normalize_path("/api/health") == "/api/health"

def test_normalize_mixed():
    assert normalize_path("/users/{id}/orders/<int:order_id>") == "/users/VAR/orders/VAR"

"""Tests for the consent banner."""

import sys

import pytest

from credence.verification.banner import print_verify_banner


def test_banner_prints_to_stderr(capsys):
    print_verify_banner()
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "verify" in captured.err.lower()


def test_banner_mentions_hosts(capsys):
    print_verify_banner()
    captured = capsys.readouterr()
    assert "api.openai.com" in captured.err
    assert "api.github.com" in captured.err
    assert "sts.amazonaws.com" in captured.err


def test_banner_can_be_suppressed(capsys):
    print_verify_banner(suppress=True)
    captured = capsys.readouterr()
    assert captured.err == ""

import json
import logging

from src.log import setup_logging, get_logger


class TestStructuredLogging:
    def test_json_format_output(self, capsys):
        setup_logging(level="INFO", fmt="json")
        logger = get_logger("test")
        logger.info("test_message", extra={"count": 42})
        captured = capsys.readouterr()
        record = json.loads(captured.err.strip())
        assert record["msg"] == "test_message"
        assert record["count"] == 42
        assert "level" in record
        assert "timestamp" in record

    def test_text_format_output(self, capsys):
        setup_logging(level="INFO", fmt="text")
        logger = get_logger("test_text")
        logger.info("hello")
        captured = capsys.readouterr()
        assert "hello" in captured.err

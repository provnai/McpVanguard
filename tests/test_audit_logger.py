import logging

from core.proxy import setup_audit_logger


def _clear_audit_logger():
    audit = logging.getLogger("vanguard.audit")
    for handler in list(audit.handlers):
        audit.removeHandler(handler)
        handler.close()


def test_setup_audit_logger_is_idempotent(tmp_path):
    _clear_audit_logger()
    log_file = tmp_path / "audit.log"

    logger_one = setup_audit_logger(str(log_file))
    logger_two = setup_audit_logger(str(log_file))

    assert logger_one is logger_two
    assert len(logger_one.handlers) == 2

    _clear_audit_logger()


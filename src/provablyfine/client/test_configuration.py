from . import configuration


def test_tenant_name_parses_slug_from_directory_url() -> None:
    cfg = configuration.Config(directory_url="https://example.com/pf/t/acme-corp/directory")
    assert cfg.tenant_name == "acme-corp"


def test_tenant_name_parses_slug_with_query_string() -> None:
    cfg = configuration.Config(directory_url="https://example.com/pf/t/acme-corp/directory?invitation=abc&auth=def")
    assert cfg.tenant_name == "acme-corp"


def test_tenant_name_empty_for_malformed_url() -> None:
    cfg = configuration.Config(directory_url="https://example.com/not-a-directory-url")
    assert cfg.tenant_name == ""

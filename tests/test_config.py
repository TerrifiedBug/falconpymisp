import pytest
from pathlib import Path
from src.config import AppConfig, load_config, ConfigError


class TestLoadConfig:
    def test_loads_valid_yaml(self, tmp_path, sample_config):
        import yaml

        config_file = tmp_path / "config.yml"
        config_file.write_text(yaml.dump(sample_config))
        config = load_config(str(config_file))
        assert config.crowdstrike.client_id == "test-id"
        assert config.misp.url == "https://misp.example.com"
        assert config.import_.batch_size == 2000

    def test_raises_on_missing_file(self):
        with pytest.raises(ConfigError, match="not found"):
            load_config("/nonexistent/config.yml")

    def test_raises_on_missing_required_field(self, tmp_path):
        import yaml

        config_file = tmp_path / "config.yml"
        config_file.write_text(yaml.dump({"crowdstrike": {}}))
        with pytest.raises(ConfigError, match="client_id"):
            load_config(str(config_file))

    def test_default_values_applied(self, tmp_path, sample_config):
        import yaml

        del sample_config["proxy"]
        config_file = tmp_path / "config.yml"
        config_file.write_text(yaml.dump(sample_config))
        config = load_config(str(config_file))
        assert config.proxy.http is None
        assert config.proxy.https is None

    def test_tags_config_defaults(self, tmp_path, sample_config):
        import yaml

        del sample_config["tags"]["taxonomies"]
        config_file = tmp_path / "config.yml"
        config_file.write_text(yaml.dump(sample_config))
        config = load_config(str(config_file))
        assert config.tags.taxonomies.iep is False
        assert config.tags.taxonomies.iep2 is False

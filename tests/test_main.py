import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from src.__main__ import run_import


class TestRunImport:
    @pytest.mark.asyncio
    @patch("src.__main__.CrowdStrikeClient")
    @patch("src.__main__.MISPClient")
    @patch("src.__main__.GalaxyCache")
    @patch("src.__main__.ImportState")
    @patch("src.__main__.IndicatorImporter")
    @patch("src.__main__.ReportImporter")
    @patch("src.__main__.ActorImporter")
    async def test_runs_all_importers(
        self, MockActors, MockReports, MockIndicators,
        MockState, MockGalaxy, MockMISP, MockCS, sample_config
    ):
        from src.config import load_config
        import yaml, tempfile, os

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            yaml.dump(sample_config, f)
            config_path = f.name

        try:
            config = load_config(config_path)
            mock_misp = AsyncMock()
            mock_misp.test_connection.return_value = True
            mock_misp.connect = AsyncMock()
            mock_misp.close = AsyncMock()
            MockMISP.return_value = mock_misp
            mock_galaxy = AsyncMock()
            mock_galaxy.load = AsyncMock()
            MockGalaxy.return_value = mock_galaxy
            mock_state = MagicMock()
            MockState.return_value = mock_state
            mock_ind = AsyncMock()
            mock_ind.run.return_value = 100
            MockIndicators.return_value = mock_ind
            mock_rep = AsyncMock()
            mock_rep.run.return_value = 10
            MockReports.return_value = mock_rep
            mock_act = AsyncMock()
            mock_act.run.return_value = 5
            MockActors.return_value = mock_act

            await run_import(config)

            mock_ind.run.assert_called_once()
            mock_rep.run.assert_called_once()
            mock_act.run.assert_called_once()
        finally:
            os.unlink(config_path)

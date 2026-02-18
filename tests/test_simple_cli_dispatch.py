import unittest
from unittest.mock import patch

import oneseam as oe


class TestCliDispatch(unittest.TestCase):
    def setUp(self):
        self.prev_advanced = oe.CLI_ADVANCED_MODE
        self.prev_mode_override = oe.CLI_MODE_OVERRIDE

    def tearDown(self):
        oe.CLI_ADVANCED_MODE = self.prev_advanced
        oe.CLI_MODE_OVERRIDE = self.prev_mode_override

    def test_default_routes_to_simple_cli(self):
        oe.CLI_ADVANCED_MODE = False
        oe.CLI_MODE_OVERRIDE = ''
        with patch.object(oe, 'run_simple_cli_menu') as simple_menu, patch.object(oe, 'cli_menu_advanced') as advanced_menu:
            oe.cli_menu()
            simple_menu.assert_called_once()
            advanced_menu.assert_not_called()

    def test_advanced_flag_routes_to_advanced_cli(self):
        oe.CLI_ADVANCED_MODE = True
        oe.CLI_MODE_OVERRIDE = ''
        with patch.object(oe, 'run_simple_cli_menu') as simple_menu, patch.object(oe, 'cli_menu_advanced') as advanced_menu:
            oe.cli_menu()
            advanced_menu.assert_called_once()
            simple_menu.assert_not_called()

    def test_mode_override_routes_to_advanced_cli(self):
        oe.CLI_ADVANCED_MODE = False
        oe.CLI_MODE_OVERRIDE = 'advanced'
        with patch.object(oe, 'run_simple_cli_menu') as simple_menu, patch.object(oe, 'cli_menu_advanced') as advanced_menu:
            oe.cli_menu()
            advanced_menu.assert_called_once()
            simple_menu.assert_not_called()


if __name__ == '__main__':
    unittest.main()

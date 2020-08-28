import sys

import mock

from tests.mocks.ghidra_api import FlatProgramAPI

sys.modules['ghidra'] = mock.MagicMock()
sys.modules['ghidra.program'] = mock.MagicMock()
sys.modules['ghidra.program.model'] = mock.MagicMock()
sys.modules['ghidra.program.model.address'] = mock.MagicMock()
sys.modules['ghidra.program.flatapi'] = mock.MagicMock()
sys.modules['ghidra.program.flatapi'].FlatProgramAPI.return_value = FlatProgramAPI()
sys.modules['ghidra.program.model.util'] = mock.MagicMock()
sys.modules['ghidra.util'] = mock.MagicMock()
sys.modules['ghidra.util.task'] = mock.MagicMock()

imported = True

import unittest

from mocks.patch_ghidra import imported
print(imported)# need to use something from this import is not automatically culled by pycharm formatter/linter

from vxutility.common import get_is_big_endian


class VxWorksTestCase(unittest.TestCase):
    def test_getting_endianess(self):
        ret = get_is_big_endian()
        self.assertEqual(False, ret)


if __name__ == '__main__':
    unittest.main()

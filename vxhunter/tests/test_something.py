import unittest

from mocks.patch_ghidra import imported

print(imported)  # need to use something from this import is not automatically culled by pycharm formatter/linter

from vxutility.common import get_is_big_endian, get_image_base, is_offset_in_current_program


class VxWorksTestCase(unittest.TestCase):
    def test_getting_endianess(self):
        ret = get_is_big_endian()
        self.assertEqual(False, ret)

    def test_getting_image_base(self):
        ret = get_image_base()
        self.assertEqual(0, ret)

    def test_checking_address_in_offset(self):
        ret = is_offset_in_current_program(10)
        self.assertEqual(True, ret)

        ret = is_offset_in_current_program(0x100000)
        self.assertEqual(True, ret)

        ret = is_offset_in_current_program(0x100001)
        self.assertEqual(False, ret)

        ret = is_offset_in_current_program(0xFFFFFFFF)
        self.assertEqual(False, ret)


if __name__ == '__main__':
    unittest.main()

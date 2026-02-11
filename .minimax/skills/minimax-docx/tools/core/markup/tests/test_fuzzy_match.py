"""Tests for fuzzy_match module."""

import unittest
from ..fuzzy_match import _fix_duplicate_attributes, safe_parse_xml_string


class TestDuplicateAttributes(unittest.TestCase):

    def test_basic_duplicate(self):
        xml = '<w:comment w:id="0" w:id="1"/>'
        result = _fix_duplicate_attributes(xml)
        self.assertIn('w:id="0"', result)
        self.assertNotIn('w:id="1"', result)

    def test_no_duplicate(self):
        xml = '<w:comment w:id="0" w:author="Test"/>'
        result = _fix_duplicate_attributes(xml)
        self.assertEqual(result, xml)

    def test_complex_tag(self):
        xml = '<w:p w:rsidR="00A1" w:rsidR="00B2" w:rsidP="00C3"/>'
        result = _fix_duplicate_attributes(xml)
        self.assertEqual(result.count('w:rsidR'), 1)
        self.assertIn('w:rsidP="00C3"', result)


class TestSafeParseString(unittest.TestCase):

    def test_parse_simple(self):
        xml = '<root><child>text</child></root>'
        elem = safe_parse_xml_string(xml)
        self.assertEqual(elem.tag, 'root')

    def test_parse_with_bom(self):
        xml = '\ufeff<root/>'
        elem = safe_parse_xml_string(xml)
        self.assertEqual(elem.tag, 'root')


if __name__ == '__main__':
    unittest.main()

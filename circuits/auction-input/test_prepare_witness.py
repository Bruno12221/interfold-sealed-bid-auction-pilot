import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("auction_prepare", Path(__file__).with_name("prepare-witness.py"))
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)


class PublicStatementEncoding(unittest.TestCase):
    def fixture(self):
        values = {name: "1" for name in prepare.WORDS}
        values.update(chainId="11155111", paramsHash=prepare.PARAMS_HASH,
                      slot="31", maxTick="100", e3Id=str((1 << 255) + 7))
        return values

    def test_preserves_full_width_e3_identifier(self):
        self.assertEqual(prepare.checked_statement(self.fixture())[5], (1 << 255) + 7)

    def test_rejects_safe_field_alias(self):
        values = self.fixture()
        values["ciphertextCommitment"] = str(prepare.FIELD + 1)
        with self.assertRaises(ValueError):
            prepare.checked_statement(values)

    def test_rejects_address_high_bits(self):
        values = self.fixture()
        values["bidder"] = str((1 << 160) + 1)
        with self.assertRaises(ValueError):
            prepare.checked_statement(values)

    def test_rejects_floating_point_json_coefficients(self):
        with self.assertRaises(ValueError):
            prepare.integer(float(1 << 59))

    def test_preserves_coefficients_above_javascript_safe_integer(self):
        coefficient = (1 << 59) + 1
        self.assertEqual(prepare.integer(coefficient), coefficient)
        self.assertEqual(prepare.integer(str(coefficient)), coefficient)

    def test_rejects_unknown_statement_fields(self):
        values = self.fixture()
        values["uncheckedDigest"] = "1"
        with self.assertRaises(ValueError):
            prepare.checked_statement(values)

    def test_rejects_private_output_outside_ignored_pilot(self):
        with self.assertRaises(ValueError):
            prepare.checked_destination(prepare.REPO_DIR / "private-proof")

    def test_accepts_ignored_private_pilot_destination(self):
        expected = prepare.REPO_DIR / ".pilot" / "new-private-proof-test"
        self.assertEqual(prepare.checked_destination(expected), expected)


if __name__ == "__main__":
    unittest.main()

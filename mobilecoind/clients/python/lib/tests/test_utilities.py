from unittest import TestCase

import mobilecoin

class TestDisplayAsMOB(TestCase):
    def test_display_as_MOB(self):
        nMOB = 1e3
        μMOB = 1e6
        MOB = 1e12
        kMOB = 1e15
        MMOB = 1e18

        test_pairs = [
            # negative values
            (-9999.05 * kMOB, "-9999.05k"),
            (-1, "-0.001n"),
            # zero
            (0, "0.000"),
            # nano
            (0.001 * nMOB, "0.001n"),
            (0.012 * nMOB, "0.012n"),
            (0.123 * nMOB, "0.123n"),
            (0.500 * nMOB, "0.500n"),
            (0.999 * nMOB, "0.999n"),
            (0.9991  * nMOB, "0.999n"),
            (0.9995  * nMOB, "0.001μ"),
            # micro
            (0.001 * μMOB, "0.001μ"),
            (0.012 * μMOB, "0.012μ"),
            (0.123 * μMOB, "0.123μ"),
            (0.5 * μMOB, "0.500μ"),
            (0.999 * μMOB, "0.999μ"),
            (0.9991  * μMOB, "0.999μ"),
            (0.9995  * μMOB, "0.000001"),
            (1  * μMOB, "0.000001"),
            (12  * μMOB, "0.000012"),
            (123 * μMOB, "0.000123"),
            (500 * μMOB, "0.000500"),
            # base precision 6
            (0.000099 * MOB, "0.000099"),
            (0.000090 * MOB, "0.000090"),
            (0.0009991 * MOB, "0.000999"),
            (0.0009995 * MOB, "0.001"),
            # base precision 3
            (0.0009999 * MOB, "0.001"),
            (0.0015 * MOB, "0.002"),
            (0.0030005 * MOB , "0.003"),
            (0.999 * MOB, "0.999"),
            (0.9991  * MOB, "0.999"),
            (0.9995  * MOB, "1.000"),
            (1  * MOB, "1.000"),
            (12  * MOB, "12.000"),
            (123 * MOB, "123.000"),
            (0.012 * MOB, "0.012"),
            (0.1 * MOB, "0.100"),
            (0.25 * MOB, "0.250"),
            (0.22342 * MOB, "0.223"),
            (1.2349 * MOB, "1.235"),
            (34.5 * MOB, "34.500"),
            (1234.234323 * MOB, "1234.234"),
            (9999.999 * MOB, "9999.999"),
            (9999.9991 * MOB, "9999.999"),
            (9999.9995 * MOB, "10.00k"),
            # kilo
            (9.9999994 * kMOB, "9999.999"),
            (9.9999995 * kMOB, "10.00k"),
            (12  * kMOB, "12.00k"),
            (123.02 * kMOB, "123.02k"),
            (500 * kMOB, "500.00k"),
            (9999.05 * kMOB, "9999.05k"),
            (9999.994 * kMOB, "9999.99k"),
            (9999.995 * kMOB, "10.00M"),
            #mega
            (9.999994 * MMOB, "9999.99k"),
            (9.999995 * MMOB, "10.00M"),
            (10  * MMOB, "10.00M"),
            (123.02 * MMOB, "123.02M"),
            (200.01 * MMOB, "200.01M"),
            (250 * MMOB, "250.00M"),
            (250.000_000_000_001 * MMOB, "overflow"),
            ]

        for (picoMOB, expected_str) in test_pairs:
            str = mobilecoin.display_as_MOB(picoMOB)
            print(str, expected_str)
            self.assertTrue(str == expected_str)

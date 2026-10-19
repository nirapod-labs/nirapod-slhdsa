# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# ci/tests/test_inventory.py
# ==========================
#
# proofs/tools/inventory.py on a stand-in for EasyCrypt that prints a
# fixed output: the same memory restrictions printed with their members
# in two orders give the same inventory, byte for byte, while a change of
# member still shows. Braces that are not a restriction are left alone.

import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(HERE)), "proofs", "tools"))
import inventory  # noqa: E402

# Shaped like the print of the scratch theory: each marker operator, then
# what follows it. {R} is the restriction under test.
OUTPUT = """\
op inventory_axioms_follow : int = 0.

==================== Top.T ====================
axiom a_restricted (A <: T.Adv{R}): true.
* In [operators]:

op inventory_theorems_follow : int = 0.

(* T.adv_bound *)
lemma adv_bound:
  forall (A <: T.Adv{R}),
    (forall (O <: T.Oracle{-A}), islossless O.f) => true.
* In [operators]:

op inventory_definitions_follow : int = 0.

theory T.
  module R_Adv (A : T.Adv{R}) = {
    proc f() : unit = { }
  }.
end T.
"""

FAKE = "import sys\nsys.stdout.write(open(sys.argv[1]).read())\n"

ORDER_1 = "-T.O_Default, -T.M.x, -T.F(T.B, T.A), -T.A"
ORDER_2 = "-T.A, -T.F(T.B, T.A), -T.O_Default, -T.M.x"


class Inventory(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = tmp.name
        self.fake = os.path.join(self.dir, "fake_easycrypt.py")
        with open(self.fake, "w") as f:
            f.write(FAKE)

    def inventory(self, restriction):
        printed = os.path.join(self.dir, "printed.txt")
        with open(printed, "w") as f:
            f.write(OUTPUT.replace("{R}", "{" + restriction + "}"))
        target = os.path.join(self.dir, "inventory.txt")
        with redirect_stdout(StringIO()):
            rc = inventory.main(["--pair", "test/pair",
                                 "--easycrypt", "%s -I %s %s" % (sys.executable, self.fake, printed),
                                 "--flags", "", "--theorems", "T.adv_bound",
                                 "--write", target, "T.ec"])
        self.assertEqual(rc, 0)
        with open(target) as f:
            return f.read()

    def test_member_order_does_not_change_the_inventory(self):
        text = self.inventory(ORDER_1)
        self.assertEqual(text, self.inventory(ORDER_2))
        self.assertIn("T.Adv{-T.A, -T.F(T.B, T.A), -T.M.x, -T.O_Default}),", text)

    def test_member_change_still_shows(self):
        self.assertNotEqual(self.inventory(ORDER_1),
                            self.inventory(ORDER_1.replace("-T.A", "-T.C")))

    def test_other_braces_are_kept(self):
        for text in ("proc f() : unit = { }", "{ -1 }", "{-T.B, (}", "{T.B.f, T.A.g}"):
            self.assertEqual(inventory.canonical_restrictions(text), text)
        self.assertEqual(inventory.canonical_restrictions("X{+T.B, -T.A, +T.A}"),
                         "X{+T.A, +T.B, -T.A}")


if __name__ == "__main__":
    unittest.main()

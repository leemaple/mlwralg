"""A completed parameter scan must distinguish failed precision from success."""
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from precision_failure import parse_precision_failure

class PrecisionOutcome(unittest.TestCase):
    parameters={'depth':10,'precision_bits':20}
    def parse(self,text):return parse_precision_failure(text,self.parameters)
    def test_real_failure(self):
        result=self.parse('Correctness: fresh key trial 2/3\nExperiment failed: depth_square at level 11: decoded error 1.717266541285277e-06 exceeds target 9.5367431640625e-07\n')
        self.assertEqual(result['operation'],'depth_square');self.assertEqual(result['level'],11)
        self.assertGreater(result['reported_absolute_error'],result['configured_target'])
    def test_structural_and_budget_errors_are_not_precision(self):
        self.assertIsNone(self.parse('Experiment failed: Compact logical scale or public bound exceeds modulus budget'))
        self.assertIsNone(self.parse('Experiment failed: Compact individual key-switch noise bound failed'))
    def test_success_and_inconsistent_values_rejected(self):
        for error,target in [('1e-10','9.5367431640625e-07'),('1e-6','0'),('1e9999','9.5367431640625e-07'),('1..2','9.5367431640625e-07'),('1e-6','1e-8')]:
            self.assertIsNone(self.parse(f'Experiment failed: depth_square at level 11: decoded error {error} exceeds target {target}'))
    def test_level_and_operation_checked(self):
        for op,level in [('depth_square',12),('decrypt_fresh_a',1),('rotate_lowest_level',10),('unrecognized',11)]:
            self.assertIsNone(self.parse(f'Experiment failed: {op} at level {level}: decoded error 1e-6 exceeds target 9.5367431640625e-07'))
    def test_only_final_native_error_is_used(self):
        self.assertIsNone(self.parse('Experiment failed: depth_square at level 11: decoded error 1e-6 exceeds target 9.5367431640625e-07\nOther failure'))

if __name__=='__main__':unittest.main()

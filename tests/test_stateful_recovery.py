
import unittest
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.ghost_audit_v7 import GhostAuditV7

from analysis.steganalysis_metric import calculate_kl, get_char_dist, BASELINE_CHAR_DIST

class TestStatefulRecovery(unittest.TestCase):
    def setUp(self):
        self.db = "test_stateful.db"
        self.evolve = "test_stateful.evolve"
        for f in [self.db, self.evolve]:
            if os.path.exists(f): 
                os.remove(f)
        self.ga = GhostAuditV7(db_path=self.db, secret_key="test-key"*4, verbose=False)

    def tearDown(self):
        self.ga.close()
        # Ensure connection closed and file handle released
        if os.path.exists(self.db): os.remove(self.db)
        if os.path.exists(self.evolve): os.remove(self.evolve)

    def test_boundary_exact_flush(self):
        """Boundary: Buffer exakt voll, kein Padding nötig."""
        # 3 Bits per Bio, 3 Bits per Event (angenommen)
        self.ga.log_event("Event A") # 3 bits -> flush
        self.ga.log_event("Event B") # 3 bits -> flush
        self.ga.close()
        
        events = self.ga.recover_events()
        self.assertEqual(len(events), 2)
        # Hier darf der [:-0] Bug nicht zuschlagen
        self.assertEqual(events[0][1], "Event A")

    def test_partial_flush(self):
        """Buffer 1/3 voll -> 2 weitere -> Flush."""
        self.ga.log_event("Event A") # Buffer: 1/3
        self.ga.log_event("Event B") # Buffer: 2/3
        self.ga.log_event("Event C") # Buffer: 3/3 -> Flush
        self.ga.close()
        
        events = self.ga.recover_events()
        self.assertEqual(len(events), 3)
        self.assertEqual(events[0][1], "Event A")

    def test_close_padding(self):
        """Close -> Padding angewendet -> Recovery strippt korrekt."""
        self.ga.log_event("Event A") # 1/3
        self.ga.close()
        
        events = self.ga.recover_events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0][1], "Event A")

    def test_multi_rotation(self):
        """12 Events -> 4 Zyklen -> Alles korrekt."""
        for i in range(12):
            self.ga.log_event(f"Event {i}")
        
        events = self.ga.recover_events()
        # DEBUG: Ausgeben was recovered wurde
        print(f"\n[DEBUG] Recovered events: {events}")
        
        self.assertEqual(len(events), 12)
        for i in range(12):
            self.assertEqual(events[i][1], f"Event {i}")

if __name__ == "__main__":
    unittest.main()

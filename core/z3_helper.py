"""
Automotion Reverse Engineering - Z3 SMT Constraint Solver Helper
Solves algebraic, linear, bitwise, and byte-by-byte validation systems
commonly found in CTF reverse engineering crackmes.
"""

from typing import Any, Callable, Dict, List, Optional
import z3


class Z3Helper:
    """Automates common SMT / SAT constraint solving patterns in CTF reversing."""

    @staticmethod
    def solve_byte_array(
        length: int,
        constraints_callback: Callable[[List[z3.BitVecRef], z3.Solver], None],
        printable_only: bool = True,
        prefix: Optional[str] = None
    ) -> Optional[str]:
        """
        Solve for an unknown byte array of specified length subject to SMT constraints.
        """
        solver = z3.Solver()
        vars = [z3.BitVec(f"c_{i}", 8) for i in range(length)]

        # Character set constraints
        if printable_only:
            for v in vars:
                solver.add(z3.UGE(v, 32), z3.ULE(v, 126))

        # Known prefix constraints
        if prefix:
            for i, char in enumerate(prefix[:length]):
                solver.add(vars[i] == ord(char))

        # Add custom problem constraints
        try:
            constraints_callback(vars, solver)
        except Exception as e:
            return None

        if solver.check() == z3.sat:
            m = solver.model()
            res_chars = [chr(m[v].as_long()) if m[v] is not None else "?" for v in vars]
            return "".join(res_chars)
        return None

    @staticmethod
    def solve_linear_system(
        matrix: List[List[int]],
        targets: List[int],
        modulo: Optional[int] = None
    ) -> Optional[List[int]]:
        """Solve a linear matrix system A * X = B [mod N]."""
        n = len(targets)
        if len(matrix) != n or any(len(row) != n for row in matrix):
            return None

        solver = z3.Solver()
        vars = [z3.Int(f"x_{i}") for i in range(n)]

        for row, target in zip(matrix, targets):
            expr = z3.Sum([coeff * var for coeff, var in zip(row, vars)])
            if modulo:
                solver.add(expr % modulo == target % modulo)
            else:
                solver.add(expr == target)

        if solver.check() == z3.sat:
            m = solver.model()
            return [m[v].as_long() for v in vars]
        return None

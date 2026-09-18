import subprocess
import sys
from pathlib import Path


def test_benchmark_runs_from_repository_root():
    root=Path(__file__).parents[1]
    result=subprocess.run([sys.executable,"tools/benchmark_realistic.py"],cwd=root,text=True,capture_output=True,timeout=180)
    assert result.returncode==0,result.stdout+result.stderr
    assert '"cisco_asa/large"' in result.stdout and '"fortigate/large"' in result.stdout
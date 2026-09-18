import os,socket,subprocess,sys,tempfile,time
import pytest

pytest.importorskip("pytest_playwright")

@pytest.fixture(scope="session")
def live_server():
    sock=socket.socket(); sock.bind(("127.0.0.1",0)); port=sock.getsockname()[1]; sock.close(); url=f"http://127.0.0.1:{port}"
    root=tempfile.mkdtemp(prefix="convert-browser-"); env={**os.environ,"FCS_DATA_DIR":root,"FCS_WORKSPACE_DIR":root+"/workspace"}
    process=subprocess.Popen([sys.executable,"-m","uvicorn","app.main:app","--host","127.0.0.1","--port",str(port)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=env)
    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1",port),timeout=.1): break
        except OSError:
            if process.poll() is not None: pytest.fail("Browser test server exited during startup")
            time.sleep(.1)
    else: pytest.fail("Browser test server did not start")
    yield url; process.terminate(); process.wait(timeout=5)
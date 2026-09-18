from pathlib import Path
import pytest

pytestmark=pytest.mark.browser

def test_fortigate_offline_workflow(page,live_server):
    external=[]
    page.on("request",lambda request: external.append(request.url) if not request.url.startswith(live_server) else None)
    page.goto(live_server)
    if page.evaluate("() => typeof window.htmx") == "undefined": pytest.xfail("vendored HTMX does not initialize under the current CSP")
    page.locator('[name="source_vendor"]').select_option("fortigate"); page.locator('[name="source_version"]').select_option("7.4"); page.locator("#target-version").select_option("11.1")
    page.locator("#file").set_input_files(str(Path("examples/fortigate/basic.conf").resolve()))
    page.wait_for_function("() => document.querySelector('#source').value.length > 0")
    page.get_by_role("button",name="Analyze & Convert").click(); page.locator(".results").wait_for()
    assert "FortiGate" in page.locator(".results").inner_text(); page.get_by_role("tab",name="Migration").click()
    page.locator(".mapping-row").first.wait_for(); page.locator(".mapping-row input[name=target_interface]").evaluate_all("xs=>xs.forEach((x,i)=>x.value=`ethernet1/${i+1}`)")
    page.locator(".mapping-row input[name=target_zone]").evaluate_all("xs=>xs.forEach(x=>x.value=x.closest('.mapping-row').dataset.nameif)")
    page.locator(".mapping-row input[name=confirmed]").check(); page.locator("#migration-mappings button[type=submit]").click()
    page.locator("#migration-render").click(); page.locator("#migration-candidate").wait_for(); page.locator("#migration-validate").click()
    assert not external

def test_malformed_is_recoverable(page,live_server):
    page.goto(live_server); page.locator("#target-version").select_option("11.1"); page.locator("#source").fill("not a firewall configuration"); page.get_by_role("button",name="Analyze & Convert").click()
    page.wait_for_timeout(300); assert page.locator("#source").input_value()=="not a firewall configuration"
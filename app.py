"""FixBot SecOps demo UI.  Run with:  streamlit run app.py"""

import os
import threading
import time

import streamlit as st
from dotenv import load_dotenv

from agent import DEV_MODEL, EVAL_MODEL, render_markdown, run_agent
from scenarios import SCENARIOS
from simulator import health_check

load_dotenv()
st.set_page_config(page_title="FixBot SecOps", layout="wide")
st.title("FixBot SecOps")


def start_run(scenario, model):
    """Run the agent in a background thread; the page polls `run` for progress."""
    run = {"scenario": scenario.name, "model": model, "log": [], "system": scenario.build(),
           "pending": None, "report": None, "error": None, "done": False}

    def approve(name, args):
        pending = {"name": name, "args": args, "event": threading.Event(), "ok": False}
        run["pending"] = pending
        pending["event"].wait(timeout=600)  # no answer in 10 minutes means denied
        run["pending"] = None
        run["log"].append(f"operator {'APPROVED' if pending['ok'] else 'DENIED'} {name}")
        return pending["ok"]

    def work():
        try:
            run["report"] = run_agent(scenario, model, approve=approve, log=run["log"].append,
                                      on_start=lambda system: run.update(system=system))
        except Exception as e:  # shown in the UI instead of dying silently in the thread
            run["error"] = f"{type(e).__name__}: {e}"
        finally:
            run["done"] = True

    threading.Thread(target=work, daemon=True).start()
    return run


def service_cards(system):
    health = health_check(system)
    for col, (name, svc) in zip(st.columns(4), system.services.items()):
        h = health["services"][name]
        text = (f"**{name}**: {h['status']}\n\ncpu {svc.cpu}% · mem {svc.memory}% · "
                f"disk {svc.disk}% · err {svc.error_rate:.1%}")
        if h["issues"]:
            text += "\n\n" + "\n".join(f"- {i}" for i in h["issues"])
        with col:
            (st.success if h["status"] == "healthy" else st.error)(text)


run = st.session_state.get("run")
running = run is not None and not run["done"]

with st.sidebar:
    scenario_name = st.selectbox("Scenario", list(SCENARIOS), disabled=running)
    model = st.selectbox("Model", [DEV_MODEL, EVAL_MODEL], disabled=running)
    scenario = SCENARIOS[scenario_name]
    st.caption(f"{scenario.type} · faults: {', '.join(scenario.faults)}")
    # A finished run belongs to its scenario and model; picking others starts fresh.
    if run and not running and (run["scenario"], run["model"]) != (scenario_name, model):
        del st.session_state["run"]
        run = None
    if not os.environ.get("ANTHROPIC_API_KEY"):
        st.error("ANTHROPIC_API_KEY is not set in .env")
    if st.button("Run", type="primary", disabled=running, use_container_width=True):
        run = st.session_state["run"] = start_run(scenario, model)
        running = True

st.subheader("Services")
service_cards(run["system"] if run else scenario.build())

if run and run["pending"]:
    p = run["pending"]
    st.warning(f"**Approval needed:** `{p['name']}` on `{p['args']}`")
    approve_col, deny_col, _ = st.columns([1, 1, 6])
    if approve_col.button("Approve", type="primary"):
        p["ok"] = True
        p["event"].set()
        st.rerun()
    if deny_col.button("Deny"):
        p["event"].set()
        st.rerun()

if run:
    st.subheader(f"Agent log: {run['scenario']}" + (" (running...)" if running else ""))
    with st.container(height=380):
        for line in run["log"]:
            st.text(line)
    if run["error"]:
        st.error(run["error"])
    if run["report"]:
        st.subheader("Incident report")
        st.markdown(render_markdown(run["report"]))

if running:
    time.sleep(1)
    st.rerun()

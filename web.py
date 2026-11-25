"""Local-only HAR2BW review UI. No deployment or network calls."""
import json
import hashlib
import tempfile
from pathlib import Path
import streamlit as st
from har2bw import inventory, build, MAX_BYTES
from review_bundle import artifacts, archive
from nginx_review import compare

st.set_page_config(page_title="HAR2BW", layout="wide")
st.title("HAR2BW — Policy Review")
st.warning("Use authorized test traffic only. HARs may contain secrets. Policies are drafts; verify backend authorization.")
host=st.text_input("Target hostname", "flow.example.test").strip().lower()
uploads=st.file_uploader("HAR files", type=["har","json"], accept_multiple_files=True)
scope=(host, tuple(hashlib.sha256(u.getvalue()).hexdigest() for u in uploads))
if st.session_state.get('input_scope') != scope:
    for key in ('report','draft','review_id'):
        st.session_state.pop(key,None)
    st.session_state.input_scope=scope
if st.button("Clear review"):
    for key in list(st.session_state):
        if key != 'input_scope':
            del st.session_state[key]
    st.rerun()
if st.button("Analyze", disabled=not uploads):
    st.session_state.pop("report",None)
    try:
        if sum(x.size for x in uploads)>MAX_BYTES:
            raise ValueError("Combined upload exceeds 128 MiB")
        with tempfile.TemporaryDirectory() as tmp:
            paths=[]
            for i,upload in enumerate(uploads):
                p=Path(tmp)/str(i)
                p.write_bytes(upload.getvalue())
                paths.append(p)
            st.session_state.report=inventory(paths,host)
        st.session_state.review_id=__import__("uuid").uuid4().hex
    except (ValueError,OSError) as exc:
        st.error(str(exc))
report=st.session_state.get("report")
if report and report["host"]==host:
    st.metric("Requests",report["entries"])
    st.metric("Candidates",len(report["candidates"]))
    st.caption("Review scope: "+report["host"])
    st.download_button("Download inventory (may contain sensitive paths)",json.dumps(report,indent=2),"report.json")
    existing=st.file_uploader("Existing HTTP configuration (offline comparison)",type=['conf','txt'])
    if existing is not None:
        try:
            if existing.size > 2*1024*1024:
                raise ValueError('Configuration exceeds 2 MiB')
            comparison=compare(report,existing.getvalue().decode('utf-8'))
            st.warning(comparison['warning'])
            st.json(comparison)
            st.download_button('Download comparison',json.dumps(comparison,indent=2),'comparison.json')
        except (ValueError,UnicodeError) as exc:
            st.error(str(exc))
    selected=[]
    with st.form("review"):
        for row in report["candidates"]:
            label=f'{row["method"]} {row["path"]} | {row["review"]} | {row["statuses"]}'
            if st.checkbox(label,disabled=not row["eligible"],key=st.session_state.review_id+row["id"]):
                selected.append(row["id"])
            for warning in row["warnings"]:
                st.caption(warning)
        sensitive=st.checkbox("I reviewed sensitive endpoints and backend authorization")
        dynamic=st.checkbox("I reviewed generalized UUID paths")
        query=st.checkbox("I accept unrestricted query strings for the selected observed query endpoints")
        redirect=st.checkbox("I reviewed redirect-only candidates")
        networks=st.text_area("Trusted internal CIDRs (optional, one per line)")
        trusted_real_ip=st.checkbox("I verified trusted proxies and client IP spoofing protection for internal bypass")
        submitted=st.form_submit_button("Generate draft")
    if submitted:
        st.session_state.pop("draft",None)
        try:
            conf,guard=build(report,selected,networks.split(),dynamic,query,sensitive,redirect,trusted_real_ip)
            options={'internal':networks.split(),'trusted_real_ip':trusted_real_ip,'dynamic':dynamic,'sensitive':sensitive,
                     'unrestricted_query':query,'redirect_only':redirect}
            bundle=archive(artifacts(report,selected,conf,guard,options))
            st.session_state.draft=(st.session_state.review_id,conf,guard,bundle)
        except ValueError as exc:
            st.error(str(exc))
    draft=st.session_state.get("draft")
    if draft and draft[0]==st.session_state.review_id:
        st.code(draft[1],language="nginx")
        st.download_button("Global HTTP draft",draft[1],"har2bw-http.conf")
        st.download_button("Service SERVER_HTTP draft",draft[2],"har2bw-server-http.conf")

        st.download_button("Download review bundle",draft[3],"har2bw-review.zip",mime="application/zip")

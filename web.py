"""Local-only HAR2BW review UI. No deployment or network calls."""
import hashlib
import json
import os
import tempfile
import uuid
from pathlib import Path

import streamlit as st

import auth
import history
from har2bw import MAX_BYTES, build, inventory
from i18n import LANGUAGES, t
from nginx_review import compare
from policy_diff import compare as approval_compare
from reporting import comparison_csv, report_csv, report_pdf
from review_bundle import archive, artifacts

st.set_page_config(page_title="HAR2BW", layout="wide")
lang=st.sidebar.selectbox("Language / Dil",list(LANGUAGES),format_func=LANGUAGES.get,key="lang")
st.title(t("title",lang))
st.warning(t("warning",lang))
try:
    _password=auth.configured_password()
except ValueError as exc:
    st.error(str(exc))
    st.stop()
if _password and not st.session_state.get("authenticated"):
    with st.form("login"):
        supplied=st.text_input(t("login",lang),type="password")
        if st.form_submit_button(t("login_button",lang)):
            attempts=st.session_state.get("attempts",0)
            if attempts>=auth.MAX_ATTEMPTS:
                st.error(t("login_wait",lang))
            elif auth.check(_password,supplied):
                st.session_state.authenticated=True
                st.rerun()
            else:
                st.session_state.attempts=attempts+1
                st.error(t("login_bad",lang))
    st.stop()
host=st.text_input("Target hostname", "flow.example.test").strip().lower()
uploads=st.file_uploader("HAR files", type=["har","json"], accept_multiple_files=True)
workspace=os.environ.get("HAR2BW_WORKSPACE")
project=None
if workspace:
    with st.expander(t("project",lang)):
        names=history.list_projects(workspace)
        pick=st.selectbox(t("project",lang),[t("project_none",lang),*names])
        project=None if pick==t("project_none",lang) else pick
        created=st.text_input(t("project_new",lang),key="new_project")
        if st.button(t("project_create",lang)):
            try:
                history.project_root(workspace,created.strip())
                Path(workspace,created.strip(),"history").mkdir(mode=0o700,parents=True,exist_ok=True)
                st.rerun()
            except (ValueError,OSError) as exc:
                st.error(str(exc))
        if project:
            st.subheader(t("history_title",lang))
            versions=history.list_versions(history.project_root(workspace,project))
            st.dataframe(versions) if versions else st.caption(t("history_empty",lang))
numeric_ids=st.checkbox("Generalize 1-9 digit numeric path segments (<int>); requires an explicit gate below")
scope=(host, numeric_ids, tuple(hashlib.sha256(u.getvalue()).hexdigest() for u in uploads))
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
            st.session_state.report=inventory(paths,host,numeric_ids)
        st.session_state.review_id=uuid.uuid4().hex
    except (ValueError,OSError) as exc:
        st.error(str(exc))
report=st.session_state.get("report")
if report and report["host"]==host:
    st.metric("Requests",report["entries"])
    st.metric("Candidates",len(report["candidates"]))
    st.caption("Review scope: "+report["host"])
    st.download_button("Download inventory (may contain sensitive paths)",json.dumps(report,indent=2),"report.json")
    st.caption(t("report_sensitive",lang))
    st.download_button(t("download_csv",lang),report_csv(report),"report.csv","text/csv")
    st.download_button(t("download_pdf",lang),report_pdf(report,lang),"report.pdf","application/pdf")
    existing=st.file_uploader("Existing HTTP configuration (offline comparison)",type=['conf','txt'])
    if existing is not None:
        try:
            if existing.size > 2*1024*1024:
                raise ValueError('Configuration exceeds 2 MiB')
            comparison=compare(report,existing.getvalue().decode('utf-8'))
            st.warning(comparison['warning'])
            for key,label in (('possible_overlaps','overlaps'),('unobserved_rule_lines','unobserved'),
                              ('duplicate_rule_groups','duplicates'),('unknown_lines','unknown_lines')):
                if comparison[key]:
                    st.subheader(t(label,lang))
                    st.dataframe(comparison[key] if key=='possible_overlaps' else [{'lines':x} for x in comparison[key]])
            st.dataframe([{'status':o['status'],'method':o['method'],'path':o['path'],'lines':o['lines']} for o in comparison['observations']])
            st.download_button('Download comparison',json.dumps(comparison,indent=2),'comparison.json')
            st.download_button(t("download_csv",lang),comparison_csv(comparison),"comparison.csv","text/csv")
        except (ValueError,UnicodeError) as exc:
            st.error(str(exc))
    previous=st.file_uploader(t("prev_approval",lang),type=['json'])
    if previous is not None:
        try:
            if previous.size > 1024*1024:
                raise ValueError('Approval file exceeds 1 MiB')
            old=json.loads(previous.getvalue().decode('utf-8'))
            if not isinstance(old,dict) or old.get('host')!=report['host']:
                raise ValueError('Previous approval belongs to another host')
            st.json(approval_compare(report,old.get('approved_ids'),[]))
        except (ValueError,UnicodeError) as exc:
            st.error(str(exc))
    needle=st.text_input(t("filter_text",lang),key="filter_text").strip().lower()
    categories=sorted({r["category"] for r in report["candidates"]})
    chosen=st.selectbox(t("filter_category",lang),[t("filter_all",lang),*categories])
    st.caption(t("filter_selected_hidden",lang))
    with st.form("review"):
        for row in report["candidates"]:
            if needle and needle not in row["path"].lower():
                continue
            if chosen!=t("filter_all",lang) and row["category"]!=chosen:
                continue
            label=f'{row["method"]} {row["path"]} | {row["review"]} | {row["statuses"]}'
            st.checkbox(label,disabled=not row["eligible"],key=st.session_state.review_id+row["id"])
            for warning in row["warnings"]:
                st.caption(warning)
        selected=[r["id"] for r in report["candidates"]
                  if r["eligible"] and st.session_state.get(st.session_state.review_id+r["id"])]
        sensitive=st.checkbox("I reviewed sensitive endpoints and backend authorization")
        dynamic=st.checkbox("I reviewed generalized UUID paths")
        numeric=st.checkbox("I reviewed generalized numeric ID paths")
        query=st.checkbox("I accept unrestricted query strings for the selected observed query endpoints")
        redirect=st.checkbox("I reviewed redirect-only candidates")
        networks=st.text_area("Trusted internal CIDRs (optional, one per line)")
        trusted_real_ip=st.checkbox("I verified trusted proxies and client IP spoofing protection for internal bypass")
        submitted=st.form_submit_button("Generate draft")
    if submitted:
        st.session_state.pop("draft",None)
        try:
            conf,guard=build(report,selected,networks.split(),dynamic,query,sensitive,redirect,trusted_real_ip,numeric)
            options={'internal':networks.split(),'trusted_real_ip':trusted_real_ip,'dynamic':dynamic,'sensitive':sensitive,
                     'unrestricted_query':query,'redirect_only':redirect,'numeric':numeric}
            bundle=archive(artifacts(report,selected,conf,guard,options))
            st.session_state.draft=(st.session_state.review_id,conf,guard,bundle)
            st.session_state.draft_ids=list(selected)
            st.session_state.draft_options=options
        except ValueError as exc:
            st.error(str(exc))
    draft=st.session_state.get("draft")
    if draft and draft[0]==st.session_state.review_id:
        st.code(draft[1],language="nginx")
        st.download_button("Global HTTP draft",draft[1],"har2bw-http.conf")
        st.download_button("Service SERVER_HTTP draft",draft[2],"har2bw-server-http.conf")

        st.download_button("Download review bundle",draft[3],"har2bw-review.zip",mime="application/zip")
        if workspace and project:
            if st.button(t("save_history",lang)):
                try:
                    files=artifacts(report,st.session_state.draft_ids,draft[1],draft[2],st.session_state.draft_options)
                    st.success(t("saved_history",lang,version=history.save(history.project_root(workspace,project),files)))
                except (ValueError,OSError) as exc:
                    st.error(str(exc))

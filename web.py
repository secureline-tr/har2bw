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
from i18n import LANGUAGES, t, tx
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
    st.error(tx(str(exc),lang))
    st.stop()
if _password and not st.session_state.get("authenticated"):
    with st.form("login"):
        supplied=st.text_input(t("login",lang),type="password",key="login_password")
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
host=st.text_input(t("host",lang), "flow.example.test", key="host").strip().lower()
uploads=st.file_uploader(t("har_files",lang), type=["har","json"], accept_multiple_files=True, key="har_upload")
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
                st.error(tx(str(exc),lang))
        if project:
            st.subheader(t("history_title",lang))
            versions=history.list_versions(history.project_root(workspace,project))
            st.dataframe(versions) if versions else st.caption(t("history_empty",lang))
numeric_ids=st.checkbox(t("numeric_ids",lang), key="numeric_ids")
scope=(host, numeric_ids, tuple(hashlib.sha256(u.getvalue()).hexdigest() for u in uploads))
if st.session_state.get('input_scope') != scope:
    for key in ('report','draft','review_id'):
        st.session_state.pop(key,None)
    st.session_state.input_scope=scope
if st.button(t("clear",lang)):
    for key in list(st.session_state):
        if key != 'input_scope':
            del st.session_state[key]
    st.rerun()
if st.button(t("analyze",lang), disabled=not uploads):
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
        st.error(tx(str(exc),lang))
report=st.session_state.get("report")
if report and report["host"]==host:
    st.metric(t("requests",lang),report["entries"])
    st.metric(t("candidates",lang),len(report["candidates"]))
    st.caption(t("scope",lang,host=report["host"]))
    st.download_button(t("dl_inventory",lang),json.dumps(report,indent=2),"report.json")
    st.caption(t("report_sensitive",lang))
    st.download_button(t("download_csv",lang),report_csv(report),"report.csv","text/csv")
    st.download_button(t("download_pdf",lang),report_pdf(report,lang),"report.pdf","application/pdf")
    existing=st.file_uploader(t("existing_conf",lang),type=['conf','txt'],key="existing_conf")
    if existing is not None:
        try:
            if existing.size > 2*1024*1024:
                raise ValueError('Configuration exceeds 2 MiB')
            comparison=compare(report,existing.getvalue().decode('utf-8'))
            st.warning(tx(comparison['warning'],lang))
            for key,label in (('possible_overlaps','overlaps'),('unobserved_rule_lines','unobserved'),
                              ('duplicate_rule_groups','duplicates'),('unknown_lines','unknown_lines')):
                if comparison[key]:
                    st.subheader(t(label,lang))
                    if key=='possible_overlaps':
                        st.dataframe([{t('col_broad',lang):o['broad_line'],t('col_covered',lang):o['covered_lines']} for o in comparison[key]])
                    else:
                        st.dataframe([{t('col_lines',lang):x} for x in comparison[key]])
            st.dataframe([{t('col_status',lang):t('st_'+o['status'],lang),t('col_method',lang):o['method'],
                           t('col_path',lang):o['path'],t('col_lines',lang):o['lines']} for o in comparison['observations']])
            st.download_button(t('dl_comparison',lang),json.dumps(comparison,indent=2),'comparison.json')
            st.download_button(t("download_csv",lang),comparison_csv(comparison),"comparison.csv","text/csv")
        except (ValueError,UnicodeError) as exc:
            st.error(tx(str(exc),lang))
    previous=st.file_uploader(t("prev_approval",lang),type=['json'],key="prev_approval")
    if previous is not None:
        try:
            if previous.size > 1024*1024:
                raise ValueError('Approval file exceeds 1 MiB')
            old=json.loads(previous.getvalue().decode('utf-8'))
            if not isinstance(old,dict) or old.get('host')!=report['host']:
                raise ValueError('Previous approval belongs to another host')
            st.json(approval_compare(report,old.get('approved_ids'),[]))
        except (ValueError,UnicodeError) as exc:
            st.error(tx(str(exc),lang))
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
            label=f'{row["method"]} {row["path"]} | {t("review_"+row["review"],lang)} | {row["statuses"]}'
            st.checkbox(label,disabled=not row["eligible"],key=st.session_state.review_id+row["id"])
            for warning in row["warnings"]:
                st.caption(tx(warning,lang))
        selected=[r["id"] for r in report["candidates"]
                  if r["eligible"] and st.session_state.get(st.session_state.review_id+r["id"])]
        sensitive=st.checkbox(t("gate_sensitive",lang),key="gate_sensitive")
        dynamic=st.checkbox(t("gate_dynamic",lang),key="gate_dynamic")
        numeric=st.checkbox(t("gate_numeric",lang),key="gate_numeric")
        query=st.checkbox(t("gate_query",lang),key="gate_query")
        redirect=st.checkbox(t("gate_redirect",lang),key="gate_redirect")
        networks=st.text_area(t("cidrs",lang),key="cidrs")
        trusted_real_ip=st.checkbox(t("gate_real_ip",lang),key="gate_real_ip")
        submitted=st.form_submit_button(t("generate",lang))
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
            st.error(tx(str(exc),lang))
    draft=st.session_state.get("draft")
    if draft and draft[0]==st.session_state.review_id:
        st.code(draft[1],language="nginx")
        st.download_button(t("dl_http",lang),draft[1],"har2bw-http.conf")
        st.download_button(t("dl_server",lang),draft[2],"har2bw-server-http.conf")

        st.download_button(t("dl_bundle",lang),draft[3],"har2bw-review.zip",mime="application/zip")
        if workspace and project:
            if st.button(t("save_history",lang)):
                try:
                    files=artifacts(report,st.session_state.draft_ids,draft[1],draft[2],st.session_state.draft_options)
                    st.success(t("saved_history",lang,version=history.save(history.project_root(workspace,project),files)))
                except (ValueError,OSError) as exc:
                    st.error(tx(str(exc),lang))

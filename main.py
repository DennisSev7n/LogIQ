import os
import re
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import pandas as pd
import numpy as np
import streamlit as st
import requests
import altair as alt

# =============================================================
# App Config
# =============================================================
st.set_page_config(page_title="LogIQ Pro 🧠", layout="wide")
st.title(" LogIQ 🧠")
st.caption("Fast, schema-flexible, privacy-aware log insights. Built for security analysts.")

# ---------------- Sidebar ----------------
st.sidebar.header("⚙️ Configuration")
api_key = st.sidebar.text_input("Groq API Key", type="password")

SUPPORTED_MODELS = [
    "llama-3.3-70b-versatile",   # primary (recommended)
    "llama-3.1-8b-instant",      # fallback (faster, smaller)
]
model = st.sidebar.selectbox("Model", SUPPORTED_MODELS, index=0)

answer_style = st.sidebar.radio("Answer style", ["Short", "Detailed"], index=0, help="Controls how verbose the AI answer is.")

# Working hours + timezone
col_tz1, col_tz2 = st.sidebar.columns(2)
start_hour = col_tz1.number_input("Workday start", min_value=0, max_value=23, value=9)
end_hour = col_tz2.number_input("Workday end", min_value=0, max_value=23, value=17)

# Default to Africa/Lagos per Dennis's TZ
timezone = st.sidebar.text_input("Timezone (IANA)", value="Africa/Lagos")

# AI sampling & limits
max_rows_to_ai = st.sidebar.slider("Rows to send to AI", 50, 2000, 300, 50, help="We never send your full log; only a compact sample.")
max_chars_per_chunk = st.sidebar.slider("Max chars per chunk", 2000, 8000, 6000, 500, help="Protects against 413 errors.")

use_ai = st.sidebar.checkbox("Use AI fallback when rules don't match", value=True)
redact_pii = st.sidebar.checkbox("Redact PII (IPs, usernames) in AI prompt", value=False)

st.sidebar.markdown("---")
st.sidebar.markdown("**Privacy note**: Logs are processed locally first. Only compact samples + summaries are sent to Groq when AI is used.")

# ---------------- File upload ----------------
uploaded = st.file_uploader("Upload CSV/TSV/TXT log file", type=["csv", "tsv", "txt", "log"])  

# Helper: safe requests to Groq with fallback models
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

def _groq_chat(messages, api_key: str, model_name: str, max_tokens: int = 400, temperature: float = 0.2):
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {
        "model": model_name,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    resp = requests.post(GROQ_URL, headers=headers, json=payload, timeout=60)
    if resp.status_code != 200:
        raise RuntimeError(f"API Error {resp.status_code}: {resp.text}")
    return resp.json()["choices"][0]["message"]["content"].strip()


def groq_chat_with_fallback(messages, api_key: str, preferred_model: str, fallbacks: list[str]):
    tried = []
    for m in [preferred_model] + [x for x in fallbacks if x != preferred_model]:
        try:
            return _groq_chat(messages, api_key, m)
        except Exception as e:
            tried.append((m, str(e)))
    # If all failed, raise with details
    raise RuntimeError("; ".join([f"{m} -> {err}" for m, err in tried]))

# ---------------- Utilities ----------------
IPV4_REGEX = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
HTTP_VERBS = {"GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS"}

ROLE_ORDER = [
    "timestamp","user_name","ip_address","action","endpoint","status_code","section","country","threat_label","bytes","user_agent","domain","session_id"
]


def parse_any_datetime(series: pd.Series):
    try:
        return pd.to_datetime(series, errors="coerce", utc=False)
    except Exception:
        return pd.to_datetime(series.astype(str), errors="coerce", utc=False)


def guess_schema(df: pd.DataFrame) -> dict:
    """Heuristic role inference from headers + value patterns."""
    roles = {}
    cols = list(df.columns)
    sample = df.head(500)

    for c in cols:
        lc = str(c).lower()
        s = sample[c].astype(str).fillna("")

        # Timestamp
        if any(k in lc for k in ["time","date","timestamp","ts"]) or (
            s.str.contains(r"\d{4}-\d{2}-\d{2}").mean() > 0.4
        ):
            roles.setdefault("timestamp", c)
            continue

        # IP
        ip_ratio = s.str.match(IPV4_REGEX).mean()
        if "ip" in lc or ip_ratio > 0.5:
            roles.setdefault("ip_address", c)
            continue

        # User / account
        if any(k in lc for k in ["user","account","uname","username","actor","principal","caller"]):
            roles.setdefault("user_name", c)
            continue

        # Action / method
        if any(k in lc for k in ["action","method","verb","event"]) or (
            s.str.upper().isin(list(HTTP_VERBS)).mean() > 0.5
        ):
            roles.setdefault("action", c)
            continue

        # Endpoint / path / resource
        if any(k in lc for k in ["endpoint","path","uri","url","resource","route","section"]):
            roles.setdefault("endpoint", c)
            continue

        # Status code
        if any(k in lc for k in ["status","code","resp_code"]) or s.str.match(r"^[1-5]\\d{2}$").mean() > 0.5:
            roles.setdefault("status_code", c)
            continue

        # Country / geo
        if any(k in lc for k in ["country","geo","location"]):
            roles.setdefault("country", c)
            continue

        # Threat label
        if any(k in lc for k in ["threat","risk","label","malicious"]):
            roles.setdefault("threat_label", c)
            continue

        # Bytes
        if any(k in lc for k in ["bytes","size","length"]) and pd.to_numeric(sample[c], errors="coerce").notna().mean() > 0.5:
            roles.setdefault("bytes", c)
            continue

        # User agent
        if any(k in lc for k in ["agent","ua","useragent"]):
            roles.setdefault("user_agent", c)
            continue

        # Domain / host
        if any(k in lc for k in ["host","domain"]):
            roles.setdefault("domain", c)
            continue

        # Session
        if any(k in lc for k in ["session","sid","sess"]):
            roles.setdefault("session_id", c)
            continue

    # Coerce timestamp if detected
    if roles.get("timestamp") is not None:
        df[roles["timestamp"]] = parse_any_datetime(df[roles["timestamp"]])

    return roles


def redact_series(s: pd.Series) -> pd.Series:
    s = s.astype(str)
    s = s.str.replace(IPV4_REGEX, "***.***.***.***", regex=True)
    s = s.str.replace(r"([A-Za-z])[A-Za-z]+", r"\1***", regex=True)  # Dennis -> D***
    return s


def prepare_ai_payload(df: pd.DataFrame, mapping: dict, question: str, max_rows: int, redact: bool) -> str:
    cols = [c for c in mapping.values() if c in df.columns]
    slim = df[cols].head(max_rows).copy()

    if redact:
        if mapping.get("ip_address") in slim.columns:
            slim[mapping["ip_address"]] = redact_series(slim[mapping["ip_address"]])
        if mapping.get("user_name") in slim.columns:
            slim[mapping["user_name"]] = redact_series(slim[mapping["user_name"]])

    sample_json = slim.to_dict(orient="records")

    style = "Be terse." if st.session_state.get("answer_style","Short") == "Short" else "Be specific but brief."

    content = (
        "You are a cybersecurity log analyst. "
        "Infer the meaning of columns from the sample. "
        "Answer the question using ONLY the provided rows. "
        "Respond in <= 4 bullet points. "
        f"{style}\n\n"
        f"Column mapping (guessed): {mapping}\n"
        f"Question: {question}\n"
        f"Rows (sample): {sample_json}"
    )
    return content


def intent_detect(q: str) -> str:
    ql = q.lower()
    if any(k in ql for k in ["after hours","after working hours","off hours","out of hours"]):
        return "after_hours"
    if any(k in ql for k in ["top user","most active user","top users","most users","top account"]):
        return "top_user"
    if any(k in ql for k in ["top ip","most active ip","suspicious ip","ips with many errors"]):
        return "top_ip"
    if any(k in ql for k in ["failed login","unauthorized","401","403"]):
        return "failed_logins"
    if any(k in ql for k in ["endpoint hits","top endpoints","most requested path","top url"]):
        return "top_endpoints"
    if any(k in ql for k in ["courses","bns courses"]):
        return "courses_access"
    return "unknown"


# ---------------- Main UI ----------------
if uploaded is not None:
    with st.expander("📑 File Preview", expanded=True):
        # Try to parse with delimiter auto-detect
        try:
            # If user uploaded TSV, use tab; else let python engine sniff
            if uploaded.name.endswith(".tsv"):
                df = pd.read_csv(uploaded, sep="\t", engine="python", on_bad_lines="skip")
            else:
                df = pd.read_csv(uploaded, sep=None, engine="python", on_bad_lines="skip")
            st.dataframe(df.head(50), use_container_width=True)
        except Exception:
            uploaded.seek(0)
            raw = uploaded.read().decode(errors="ignore")
            st.text_area("Raw preview", raw[:4000], height=220)
            st.stop()

    st.markdown("---")

    # Schema detection + manual override
    st.subheader("🔎 Detected Schema (editable)")
    detected = guess_schema(df)

    cols_sel = st.columns(4)
    mapping = {}

    def sel(label, key, default_col=None):
        opts = ["<none>"] + list(df.columns)
        idx = opts.index(default_col) if (default_col in opts) else 0
        return cols_sel[key % 4].selectbox(label, opts, index=idx)

    # Build mapping UI in ROLE_ORDER
    for i, role in enumerate(ROLE_ORDER):
        default = detected.get(role)
        chosen = sel(f"{role}", i, default_col=default)
        if chosen != "<none>":
            mapping[role] = chosen

    st.caption("Tip: Correct any mis-detections above before running queries.")

    # Quick stats row
    with st.expander("📈 Quick Stats", expanded=False):
        st.write(f"Rows: {len(df):,} | Columns: {len(df.columns)}")
        if mapping.get("timestamp"):
            ts_col = mapping["timestamp"]
            if pd.api.types.is_datetime64_any_dtype(df[ts_col]) is False:
                df[ts_col] = parse_any_datetime(df[ts_col])
            st.write(f"Time span: {df[ts_col].min()} → {df[ts_col].max()}")
        if mapping.get("status_code"):
            vc = df[mapping["status_code"]].astype(str).value_counts().head(10)
            st.write("Top status codes:")
            st.write(vc)

    # Query input + suggestions
    st.subheader("💬 Ask a question")
    c1, c2, c3, c4 = st.columns(4)
    if c1.button("Top users"):
        st.session_state["_q"] = "Who are the top users?"
    if c2.button("After-hours logins"):
        st.session_state["_q"] = "Who accessed or logged in after working hours?"
    if c3.button("Top IPs"):
        st.session_state["_q"] = "Which IPs are most active or suspicious?"
    if c4.button("Failed logins"):
        st.session_state["_q"] = "Show failed or unauthorized logins."

    q_default = st.session_state.get("_q", "Who is the top user?")
    q = st.text_input("Question", q_default)
    st.session_state["answer_style"] = answer_style

    run = st.button("Run Query", type="primary", use_container_width=True)

    # ---------------- Query Execution ----------------
    if run:
        intent = intent_detect(q)
        tz = ZoneInfo(timezone)

        def after_hours_mask(ts_series: pd.Series):
            if pd.api.types.is_datetime64_any_dtype(ts_series) is False:
                ts = parse_any_datetime(ts_series)
            else:
                ts = ts_series
            local = ts.dt.tz_localize(None)
            hrs = local.dt.hour
            return (hrs < start_hour) | (hrs >= end_hour)

        summary_text = ""
        out_df = None

        # Local rule-based handlers for speed & precision
        try:
            if intent == "top_user" and mapping.get("user_name"):
                u = mapping["user_name"]
                counts = df[u].astype(str).value_counts().reset_index()
                counts.columns = ["user", "events"]
                out_df = counts
                top_row = counts.iloc[0]
                summary_text = f"Top user: **{top_row['user']}** ({int(top_row['events'])} events)."

            elif intent == "top_ip" and mapping.get("ip_address"):
                ip = mapping["ip_address"]
                counts = df[ip].astype(str).value_counts().reset_index()
                counts.columns = ["ip", "events"]
                out_df = counts
                top_row = counts.iloc[0]
                summary_text = f"Top IP: **{top_row['ip']}** ({int(top_row['events'])} events)."

            elif intent == "failed_logins":
                # Needs action/status + possibly endpoint
                mask = pd.Series(True, index=df.index)
                if mapping.get("action"):
                    mask &= df[mapping["action"]].astype(str).str.contains(r"fail|unauth|denied|invalid", case=False, regex=True)
                if mapping.get("status_code"):
                    mask |= df[mapping["status_code"]].astype(str).str.match(r"^(401|403|429)$")
                out_df = df[mask].copy()
                summary_text = f"Failed/unauthorized events: **{len(out_df):,}**." if len(out_df) else "No failed/unauthorized events found."

            elif intent == "after_hours" and mapping.get("timestamp"):
                ts = mapping["timestamp"]
                mask = after_hours_mask(df[ts])
                if mapping.get("action"):
                    # prioritize logins/access
                    mask &= df[mapping["action"]].astype(str).str.contains(r"login|log in|access", case=False, regex=True)
                out_df = df[mask].copy()
                # Optional: show yesterday after-hours subset if user implies yesterday
                summary_text = f"After-hours events: **{len(out_df):,}** between {start_hour}:00–{end_hour}:00 policy."

            elif intent == "top_endpoints" and mapping.get("endpoint"):
                ep = mapping["endpoint"]
                counts = df[ep].astype(str).value_counts().reset_index().head(50)
                counts.columns = ["endpoint", "hits"]
                out_df = counts
                top_row = counts.iloc[0]
                summary_text = f"Top endpoint: **{top_row['endpoint']}** ({int(top_row['hits'])} hits)."

            elif intent == "courses_access" and mapping.get("endpoint"):
                ep = mapping["endpoint"]
                mask = df[ep].astype(str).str.contains("courses", case=False, na=False)
                if mapping.get("action"):
                    mask &= df[mapping["action"]].astype(str).str.contains("access|GET|POST", case=False)
                out_df = df[mask].copy()
                users = mapping.get("user_name")
                if users and len(out_df):
                    names = ", ".join(sorted(out_df[users].astype(str).unique()))
                    summary_text = f"Users who accessed courses: {names}."
                else:
                    summary_text = f"Courses access events: **{len(out_df):,}**."

            else:
                summary_text = ""

        except Exception as e:
            st.error(f"Local analysis error: {e}")
            out_df = None

        handled_locally = out_df is not None and len(out_df) > 0

        # Display local results if any
        if handled_locally:
            st.success(summary_text)
            st.dataframe(out_df.head(500), use_container_width=True)

            # Small charts for common outputs
            try:
                if "events" in out_df.columns and "user" in out_df.columns:
                    chart = alt.Chart(out_df.head(20)).mark_bar().encode(
                        x=alt.X("events:Q"), y=alt.Y("user:N", sort='-x')
                    ).properties(height=300)
                    st.altair_chart(chart, use_container_width=True)
                if "events" in out_df.columns and "ip" in out_df.columns:
                    chart = alt.Chart(out_df.head(20)).mark_bar().encode(
                        x=alt.X("events:Q"), y=alt.Y("ip:N", sort='-x')
                    ).properties(height=300)
                    st.altair_chart(chart, use_container_width=True)
                if mapping.get("timestamp") and intent in {"after_hours","failed_logins"} and len(out_df):
                    ts = mapping["timestamp"]
                    if pd.api.types.is_datetime64_any_dtype(out_df[ts]) is False:
                        out_df[ts] = parse_any_datetime(out_df[ts])
                    by_hour = out_df.groupby(out_df[ts].dt.floor('H')).size().reset_index(name='events')
                    chart = alt.Chart(by_hour).mark_line(point=True).encode(
                        x=alt.X(f"{ts}:T", title="Hour"), y=alt.Y("events:Q")
                    ).properties(height=300)
                    st.altair_chart(chart, use_container_width=True)
            except Exception:
                pass

            # Download
            csv = out_df.to_csv(index=False).encode('utf-8')
            st.download_button("Download results CSV", data=csv, file_name="analysis_results.csv", mime="text/csv")

        # If not handled or user insists on AI, call Groq with compact sample
        elif use_ai:
            if not api_key:
                st.error("Enter your Groq API key or disable AI fallback.")
                st.stop()

            # Build compact prompt
            prompt = prepare_ai_payload(df, mapping, q, max_rows_to_ai, redact_pii)

            # Chunk to avoid 413
            chunks = [prompt[i:i+max_chars_per_chunk] for i in range(0, len(prompt), max_chars_per_chunk)]
            answers = []
            for idx, ch in enumerate(chunks, 1):
                with st.spinner(f"Asking AI (chunk {idx}/{len(chunks)})…"):
                    msgs = [
                        {"role": "system", "content": "Answer crisply. Use at most 4 bullets."},
                        {"role": "user", "content": ch}
                    ]
                    try:
                        resp = groq_chat_with_fallback(
                            msgs, api_key, preferred_model=model, fallbacks=SUPPORTED_MODELS
                        )
                        answers.append(resp)
                    except Exception as e:
                        st.error(str(e))
                        break

            if answers:
                # If multiple chunks, summarize them briefly
                final = "\n".join(answers)
                if len(answers) > 1 and api_key:
                    try:
                        msgs = [
                            {"role": "system", "content": "Summarize to <=4 bullets, direct answers only."},
                            {"role": "user", "content": final}
                        ]
                        final = groq_chat_with_fallback(msgs, api_key, preferred_model=model, fallbacks=SUPPORTED_MODELS)
                    except Exception:
                        pass

                st.success(final)
            else:
                st.info("No AI answer produced.")

        else:
            st.info("No matching rule for your question. Enable AI fallback or rephrase.")

else:
    st.info("Upload a file to get started.")

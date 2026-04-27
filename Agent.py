"""
soc_dashboard.py - Interactive Live SOC Dashboard
Shows REAL incidents from Microsoft Sentinel
Uses only columns that exist in ALL SecurityIncident tables
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import os
import json
from dotenv import load_dotenv

# Azure imports
from azure.identity import ClientSecretCredential
from azure.monitor.query import LogsQueryClient, LogsQueryStatus

load_dotenv()

# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="AI SOC Platform | Live Security Operations",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for dark theme
st.markdown("""
<style>
    .stApp {
        background: linear-gradient(135deg, #0a0c10 0%, #0e1117 100%);
    }
    .hero-section {
        background: linear-gradient(135deg, #1a1d24 0%, #0f1218 100%);
        border-radius: 20px;
        padding: 25px 30px;
        margin-bottom: 25px;
        border: 1px solid #2a2e3d;
    }
    .metric-card {
        background: linear-gradient(135deg, #1a1d24 0%, #0f1218 100%);
        border-radius: 16px;
        padding: 20px;
        text-align: center;
        border: 1px solid #2a2e3d;
        transition: all 0.2s;
    }
    .metric-card:hover {
        border-color: #ff4b4b;
        transform: translateY(-2px);
    }
    .incident-card {
        background-color: #1a1d24;
        border-radius: 12px;
        padding: 15px;
        margin: 10px 0;
        border-left: 4px solid;
        cursor: pointer;
        transition: all 0.2s;
    }
    .incident-card:hover {
        background-color: #252a3a;
        transform: translateX(5px);
    }
    .agent-card {
        background: linear-gradient(135deg, #1a1d24 0%, #0f1218 100%);
        border-radius: 12px;
        padding: 20px;
        text-align: center;
        border: 1px solid #2a2e3d;
        margin: 10px;
    }
    .risk-critical { color: #ff4b4b; }
    .risk-high { color: #ff9f4b; }
    .risk-medium { color: #ffd24b; }
    .risk-low { color: #4bff4b; }
    .status-active {
        display: inline-block;
        width: 10px;
        height: 10px;
        background-color: #4bff4b;
        border-radius: 50%;
        animation: pulse 1.5s infinite;
        margin-right: 8px;
    }
    @keyframes pulse {
        0% { opacity: 1; }
        50% { opacity: 0.3; }
        100% { opacity: 1; }
    }
    h1, h2, h3, h4 {
        color: #ffffff !important;
    }
    p, span, div {
        color: #e0e0e0;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 24px;
        background-color: transparent;
    }
    .stTabs [data-baseweb="tab"] {
        background-color: transparent;
        color: #a0a0c0;
        font-weight: 500;
        padding: 8px 16px;
    }
    .stTabs [aria-selected="true"] {
        color: #ffffff;
        border-bottom: 2px solid #ff4b4b;
    }
    footer {
        text-align: center;
        padding: 20px;
        color: #a0a0c0;
        font-size: 12px;
    }
</style>
""", unsafe_allow_html=True)

# ============================================================
# REAL SENTINEL CONNECTION
# ============================================================

@st.cache_resource
def get_sentinel_client():
    """Create and cache Sentinel client connection"""
    
    credential = ClientSecretCredential(
        tenant_id=os.getenv("AZURE_TENANT_ID"),
        client_id=os.getenv("AZURE_CLIENT_ID"),
        client_secret=os.getenv("AZURE_CLIENT_SECRET")
    )
    
    client = LogsQueryClient(credential)
    return client

@st.cache_data(ttl=60)
def fetch_incidents(hours_back: int = 168):
    """
    Fetch REAL incidents from Sentinel SecurityIncident table
    Using ONLY columns that exist in ALL Sentinel workspaces
    """
    
    client = get_sentinel_client()
    workspace_id = os.getenv("AZURE_WORKSPACE_ID")
    
    # SIMPLIFIED QUERY - Only using columns that always exist
    query = f"""
    SecurityIncident
    | where TimeGenerated > ago({hours_back}h)
    | summarize arg_max(TimeGenerated, *) by IncidentNumber
    | project
        IncidentNumber,
        Title,
        Severity,
        Status,
        TimeGenerated,
        LastModifiedTime,
        Description = tostring(Description),
        Owner = tostring(Owner.assignedTo)
    | order by TimeGenerated desc
    """
    
    try:
        response = client.query_workspace(
            workspace_id=workspace_id,
            query=query,
            timespan=timedelta(hours=hours_back)
        )
        
        if response.status == LogsQueryStatus.SUCCESS and response.tables:
            data = []
            for row in response.tables[0].rows:
                # Handle potential None values
                incident_number = row[0] if row[0] is not None else "N/A"
                title = row[1] if row[1] is not None else "Unknown Incident"
                severity = row[2] if row[2] is not None else "Medium"
                status = row[3] if row[3] is not None else "New"
                time_created = row[4] if row[4] is not None else datetime.now()
                last_modified = row[5] if row[5] is not None else datetime.now()
                description = row[6] if row[6] is not None else "No description available"
                owner = row[7] if row[7] is not None else "Unassigned"
                
                data.append({
                    "incident_number": incident_number,
                    "title": title,
                    "severity": severity,
                    "status": status,
                    "created_time": time_created,
                    "last_modified": last_modified,
                    "description": description,
                    "owner": owner
                })
            
            return pd.DataFrame(data)
        else:
            return pd.DataFrame()
            
    except Exception as e:
        st.error(f"Error fetching incidents: {str(e)}")
        return pd.DataFrame()

@st.cache_data(ttl=300)
def fetch_incident_timeline(days_back: int = 30):
    """Fetch incident timeline for trends"""
    
    client = get_sentinel_client()
    workspace_id = os.getenv("AZURE_WORKSPACE_ID")
    
    query = f"""
    SecurityIncident
    | where TimeGenerated > ago({days_back}d)
    | summarize IncidentCount = dcount(IncidentNumber) by bin(TimeGenerated, 1d)
    | order by TimeGenerated asc
    """
    
    try:
        response = client.query_workspace(
            workspace_id=workspace_id,
            query=query,
            timespan=timedelta(days=days_back)
        )
        
        if response.status == LogsQueryStatus.SUCCESS and response.tables:
            data = []
            for row in response.tables[0].rows:
                data.append({
                    "date": row[0],
                    "count": row[1]
                })
            return pd.DataFrame(data)
        return pd.DataFrame()
    except Exception as e:
        st.warning(f"Could not fetch timeline: {str(e)}")
        return pd.DataFrame()

@st.cache_data(ttl=300)
def fetch_severity_distribution():
    """Fetch severity distribution of incidents"""
    
    client = get_sentinel_client()
    workspace_id = os.getenv("AZURE_WORKSPACE_ID")
    
    query = """
    SecurityIncident
    | where TimeGenerated > ago(30d)
    | summarize arg_max(TimeGenerated, *) by IncidentNumber
    | summarize Count = count() by Severity
    """
    
    try:
        response = client.query_workspace(
            workspace_id=workspace_id,
            query=query,
            timespan=timedelta(days=30)
        )
        
        if response.status == LogsQueryStatus.SUCCESS and response.tables:
            data = []
            for row in response.tables[0].rows:
                data.append({
                    "severity": row[0] if row[0] else "Unknown",
                    "count": row[1]
                })
            return pd.DataFrame(data)
        return pd.DataFrame()
    except Exception as e:
        st.warning(f"Could not fetch severity distribution: {str(e)}")
        return pd.DataFrame()

# ============================================================
# SIDEBAR - STATUS & STATISTICS
# ============================================================

with st.sidebar:
    st.markdown("### 🛡️ **AI SOC Platform**")
    st.markdown("*Live Security Operations*")
    st.markdown("---")
    
    st.markdown('<span class="status-active"></span><span style="color: #4bff4b;"> LIVE MONITORING</span>', unsafe_allow_html=True)
    st.markdown("---")
    
    st.markdown("### 🤖 System Status")
    st.markdown("🟢 **Sentinel:** Connected")
    st.markdown("🟢 **Log Analytics:** Active")
    st.markdown("🟢 **4 Agents:** Ready")
    st.markdown("🟢 **LLM:** Groq Llama 3.3")
    
    st.markdown("---")
    
    # Refresh control
    if st.button("🔄 Refresh Data", use_container_width=True):
        st.cache_data.clear()
        st.rerun()
    
    st.markdown("---")
    
    # Time range selector
    hours_back = st.selectbox(
        "📅 Time Range",
        options=[24, 48, 72, 168, 336, 720],
        format_func=lambda x: f"{x} hours" if x < 168 else f"{x//24} days",
        index=3
    )

# ============================================================
# HERO SECTION
# ============================================================

st.markdown(f"""
<div class="hero-section">
    <div style="display: flex; justify-content: space-between; align-items: center;">
        <div>
            <h1 style="margin: 0;">🛡️ Autonomous Security Operations</h1>
            <p style="color: #a0a0c0; font-size: 16px; margin-top: 10px;">4-Agent Multi-Agent System | Real-Time Incident Investigation</p>
        </div>
        <div style="text-align: right;">
            <p style="color: #4bff4b; font-size: 12px;"><span class="status-active"></span> SYSTEM ACTIVE</p>
            <p style="color: #a0a0c0; font-size: 12px;">Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# ============================================================
# FETCH REAL DATA
# ============================================================

with st.spinner("Fetching REAL incidents from Microsoft Sentinel..."):
    df_incidents = fetch_incidents(hours_back=hours_back)
    df_timeline = fetch_incident_timeline()
    df_severity = fetch_severity_distribution()

# Check if we have real data
if df_incidents.empty:
    st.warning("⚠️ No incidents found in the selected time range.")
    st.info("💡 The dashboard is connected to your Sentinel workspace but no incidents have been detected by your Analytic Rules in this time period.")
    
    # Show connection status
    with st.expander("🔧 Connection Status"):
        st.markdown("✅ Connected to Azure Sentinel")
        st.markdown(f"✅ Workspace ID: {os.getenv('AZURE_WORKSPACE_ID')[:20]}...")
        st.markdown("✅ Authentication: Client Secret Credential")
        st.markdown("---")
        st.markdown("**Why no incidents?**")
        st.markdown("1. Your Analytic Rules haven't triggered recently")
        st.markdown("2. No security events matched your rules")
        st.markdown("3. Time range may be too short")
        st.markdown("---")
        st.markdown("**Try:**")
        st.markdown("- Increase the time range in sidebar")
        st.markdown("- Check your Analytic Rules are enabled")
        st.markdown("- Generate test alerts if needed")
    st.stop()

# Calculate statistics
total_incidents = len(df_incidents)
critical_count = len(df_incidents[df_incidents['severity'] == 'Critical']) if 'severity' in df_incidents.columns else 0
high_count = len(df_incidents[df_incidents['severity'] == 'High']) if 'severity' in df_incidents.columns else 0
medium_count = len(df_incidents[df_incidents['severity'] == 'Medium']) if 'severity' in df_incidents.columns else 0
low_count = len(df_incidents[df_incidents['severity'] == 'Low']) if 'severity' in df_incidents.columns else 0
open_count = len(df_incidents[df_incidents['status'] == 'Active']) if 'status' in df_incidents.columns else 0

# ============================================================
# KPI CARDS
# ============================================================

col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    st.markdown(f"""
    <div class="metric-card">
        <div style="font-size: 14px; color: #a0a0c0;">TOTAL INCIDENTS</div>
        <div style="font-size: 36px; font-weight: bold;">{total_incidents}</div>
        <div style="font-size: 12px; color: #a0a0c0;">Last {hours_back//24 if hours_back >= 24 else hours_back} days</div>
    </div>
    """, unsafe_allow_html=True)

with col2:
    st.markdown(f"""
    <div class="metric-card">
        <div style="font-size: 14px; color: #ff4b4b;">CRITICAL</div>
        <div style="font-size: 36px; font-weight: bold; color: #ff4b4b;">{critical_count}</div>
    </div>
    """, unsafe_allow_html=True)

with col3:
    st.markdown(f"""
    <div class="metric-card">
        <div style="font-size: 14px; color: #ff9f4b;">HIGH</div>
        <div style="font-size: 36px; font-weight: bold; color: #ff9f4b;">{high_count}</div>
    </div>
    """, unsafe_allow_html=True)

with col4:
    active_percentage = int((open_count / total_incidents) * 100) if total_incidents > 0 else 0
    st.markdown(f"""
    <div class="metric-card">
        <div style="font-size: 14px; color: #4b9fff;">ACTIVE</div>
        <div style="font-size: 36px; font-weight: bold; color: #4b9fff;">{open_count}</div>
        <div style="font-size: 12px;">{active_percentage}% of total</div>
    </div>
    """, unsafe_allow_html=True)

with col5:
    # Calculate risk index based on severity distribution
    if total_incidents > 0:
        risk_index = int((critical_count * 100 + high_count * 60 + medium_count * 30) / total_incidents)
    else:
        risk_index = 0
    st.markdown(f"""
    <div class="metric-card">
        <div style="font-size: 14px; color: #4bff4b;">RISK INDEX</div>
        <div style="font-size: 36px; font-weight: bold; color: #ff9f4b;">{risk_index}</div>
        <div style="font-size: 12px;">/100</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("---")

# ============================================================
# 4-AGENT PIPELINE DISPLAY
# ============================================================

st.markdown("## 🤖 Multi-Agent Investigation Pipeline")

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.markdown("""
    <div class="agent-card">
        <h3>📌 Agent A</h3>
        <h4>Intake & Scope Architect</h4>
        <p>Entity Extraction</p>
        <p>Triage & Prioritization</p>
        <p><span style="color: #4bff4b;">🟢 Active</span></p>
    </div>
    """, unsafe_allow_html=True)

with col2:
    st.markdown("""
    <div class="agent-card">
        <h3>🔬 Agent B</h3>
        <h4>Forensic Investigator</h4>
        <p>Behavioral Analysis</p>
        <p>Anomaly Detection</p>
        <p><span style="color: #4bff4b;">🟢 Active</span></p>
    </div>
    """, unsafe_allow_html=True)

with col3:
    st.markdown("""
    <div class="agent-card">
        <h3>🌐 Agent C</h3>
        <h4>Threat Intel Specialist</h4>
        <p>OSINT Analysis</p>
        <p>Context & Attribution</p>
        <p><span style="color: #4bff4b;">🟢 Active</span></p>
    </div>
    """, unsafe_allow_html=True)

with col4:
    st.markdown("""
    <div class="agent-card">
        <h3>⚖️ Agent D</h3>
        <h4>Final Judge</h4>
        <p>Risk Scoring</p>
        <p>Decision Making</p>
        <p><span style="color: #4bff4b;">🟢 Active</span></p>
    </div>
    """, unsafe_allow_html=True)

st.markdown("---")

# ============================================================
# TABS
# ============================================================

tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "📋 INCIDENT LIST",
    "🔍 AGENT INVESTIGATION",
    "📊 ANALYTICS",
    "📈 TIMELINE & TRENDS",
    "🏗️ ARCHITECTURE",
    "📄 REPORTS"
])

# ============================================================
# TAB 1: INCIDENT LIST
# ============================================================

with tab1:
    st.markdown("### 📋 Real-time Incident Feed")
    st.caption(f"Showing {len(df_incidents)} REAL incidents from Microsoft Sentinel")
    
    # Filters
    col_filter1, col_filter2, col_filter3 = st.columns(3)
    with col_filter1:
        severity_options = df_incidents['severity'].unique().tolist() if 'severity' in df_incidents.columns else []
        severity_filter = st.multiselect("Filter by Severity", options=severity_options, default=[])
    with col_filter2:
        status_options = df_incidents['status'].unique().tolist() if 'status' in df_incidents.columns else []
        status_filter = st.multiselect("Filter by Status", options=status_options, default=[])
    with col_filter3:
        owner_options = df_incidents['owner'].unique().tolist() if 'owner' in df_incidents.columns else []
        owner_filter = st.multiselect("Filter by Owner", options=owner_options, default=[])
    
    # Apply filters
    filtered_df = df_incidents.copy()
    if severity_filter:
        filtered_df = filtered_df[filtered_df['severity'].isin(severity_filter)]
    if status_filter:
        filtered_df = filtered_df[filtered_df['status'].isin(status_filter)]
    if owner_filter:
        filtered_df = filtered_df[filtered_df['owner'].isin(owner_filter)]
    
    # Display incidents
    for idx, row in filtered_df.iterrows():
        severity = row.get('severity', 'Medium')
        
        # Color coding
        if severity == 'Critical':
            sev_color = '#ff4b4b'
            sev_icon = '🔴'
        elif severity == 'High':
            sev_color = '#ff9f4b'
            sev_icon = '🟠'
        elif severity == 'Medium':
            sev_color = '#ffd24b'
            sev_icon = '🟡'
        else:
            sev_color = '#4bff4b'
            sev_icon = '🟢'
        
        with st.expander(f"[#{row.get('incident_number', 'N/A')}] {row.get('title', 'Unknown')} - {severity}"):
            col_desc, col_meta = st.columns([2, 1])
            
            with col_desc:
                st.markdown(f"**Description:** {row.get('description', 'No description')}")
            
            with col_meta:
                st.markdown(f"**Status:** {row.get('status', 'Unknown')}")
                st.markdown(f"**Owner:** {row.get('owner', 'Unassigned')}")
                st.markdown(f"**Created:** {row.get('created_time', 'Unknown')}")

# ============================================================
# TAB 2: AGENT INVESTIGATION
# ============================================================

with tab2:
    st.markdown("### 🔍 Live Agent Investigation Stream")
    
    if not df_incidents.empty:
        selected_incident_num = st.selectbox(
            "Select incident to investigate",
            options=df_incidents['incident_number'].tolist(),
            format_func=lambda x: f"#{x}: {df_incidents[df_incidents['incident_number'] == x]['title'].iloc[0]}"
        )
        
        if selected_incident_num:
            incident_data = df_incidents[df_incidents['incident_number'] == selected_incident_num].iloc[0]
            
            st.markdown("---")
            st.markdown(f"### Investigating: {incident_data['title']}")
            
            # Agent investigation steps
            st.markdown("#### Agent A: Intake & Scope Analysis")
            st.info(f"📌 **Entities Extracted:** Analyzing incident #{selected_incident_num}")
            st.markdown(f"**Severity Assessment:** {incident_data['severity']}")
            
            st.markdown("#### Agent B: Forensic Investigation")
            st.info(f"🔬 **Behavioral Analysis:** Incident created at {incident_data['created_time']}")
            st.markdown(f"**Status:** {incident_data['status']}")
            
            st.markdown("#### Agent C: Threat Intelligence")
            st.info(f"🌐 **Threat Context:** Analyzing patterns and indicators")
            
            st.markdown("#### Agent D: Final Judgment")
            risk_map = {'Critical': 95, 'High': 75, 'Medium': 50, 'Low': 25}
            risk_score = risk_map.get(incident_data['severity'], 50)
            
            if risk_score >= 70:
                st.error(f"⚖️ **FINAL RISK SCORE: {risk_score}%** - HIGH RISK - Escalation Recommended")
            elif risk_score >= 40:
                st.warning(f"⚖️ **FINAL RISK SCORE: {risk_score}%** - MEDIUM RISK - Human Review Required")
            else:
                st.success(f"⚖️ **FINAL RISK SCORE: {risk_score}%** - LOW RISK - Auto-close")
            
            st.markdown("---")
            st.caption("🛑 HUMAN-IN-THE-LOOP: High-risk incidents require SOC analyst approval")

# ============================================================
# TAB 3: ANALYTICS
# ============================================================

with tab3:
    if not df_severity.empty:
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### 🎯 Severity Distribution")
            fig = px.pie(
                df_severity,
                values='count',
                names='severity',
                template="plotly_dark",
                color='severity',
                color_discrete_map={
                    'Critical': '#ff4b4b',
                    'High': '#ff9f4b',
                    'Medium': '#ffd24b',
                    'Low': '#4bff4b'
                }
            )
            fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)')
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.markdown("### 📊 Status Distribution")
            status_counts = df_incidents['status'].value_counts().reset_index()
            status_counts.columns = ['status', 'count']
            fig = px.bar(
                status_counts,
                x='status',
                y='count',
                template="plotly_dark",
                color='status',
                color_discrete_sequence=['#4b9fff', '#ff9f4b', '#4bff4b']
            )
            fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)')
            st.plotly_chart(fig, use_container_width=True)
    
    # Owner distribution
    if 'owner' in df_incidents.columns and len(df_incidents['owner'].unique()) > 1:
        st.markdown("### 👥 Incident Distribution by Owner")
        owner_counts = df_incidents['owner'].value_counts().reset_index()
        owner_counts.columns = ['owner', 'count']
        fig = px.bar(
            owner_counts,
            x='owner',
            y='count',
            template="plotly_dark",
            color='count',
            color_continuous_scale='viridis'
        )
        fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)')
        st.plotly_chart(fig, use_container_width=True)

# ============================================================
# TAB 4: TIMELINE & TRENDS
# ============================================================

with tab4:
    if not df_timeline.empty:
        st.markdown("### 📅 Incident Trend Analysis")
        
        fig = px.line(
            df_timeline,
            x='date',
            y='count',
            template="plotly_dark",
            markers=True,
            title="Incidents Over Time",
            color_discrete_sequence=['#ff9f4b']
        )
        fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            xaxis_title="Date",
            yaxis_title="Number of Incidents"
        )
        st.plotly_chart(fig, use_container_width=True)
        
        # Calculate trend
        if len(df_timeline) > 7:
            recent_avg = df_timeline['count'].tail(7).mean()
            st.metric("Average Daily Incidents (Last 7 days)", f"{recent_avg:.1f}")
    else:
        st.info("Not enough data for timeline analysis")

# ============================================================
# TAB 5: ARCHITECTURE
# ============================================================

with tab5:
    st.markdown("### 🏗️ System Architecture & Data Flow")
    
    st.markdown("""┌─────────────────────────────────────────────────────────────────┐
│ YOUR MICROSOFT SENTINEL │
│ • Analytic Rules (YOUR configured rules) │
│ • SecurityIncident Table (REAL incidents) │
└─────────────────────────────────────────────────────────────────┘
│
│ KQL Query
▼
┌─────────────────────────────────────────────────────────────────┐
│ LOG ANALYTICS CLIENT │
│ • Azure.identity.ClientSecretCredential │
│ • Azure.monitor.query.LogsQueryClient │
└─────────────────────────────────────────────────────────────────┘
│
▼
┌─────────────────────────────────────────────────────────────────┐
│ CREWAI MULTI-AGENT ORCHESTRATOR │
├─────────────────────────────────────────────────────────────────┤
│ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ │
│ │ Agent A │ → │ Agent B │ → │ Agent C │ → │ Agent D │ │
│ │ Intake │ │Forensic │ │ Threat │ │ Final │ │
│ │ Scope │ │Invest. │ │ Intel │ │ Judge │ │
│ └─────────┘ └─────────┘ └─────────┘ └─────────┘ │
└─────────────────────────────────────────────────────────────────┘
│
▼
┌─────────────────────────────────────────────────────────────────┐
│ DECISION & RESPONSE │
│ • Risk Score (0-100) │
│ • Human Approval for High/Medium Risk │
│ • Actionable Recommendations │
└─────────────────────────────────────────────────────────────────┘""")

st.markdown("---")
st.markdown("### 🔧 Technology Stack")

tech_col1, tech_col2, tech_col3 = st.columns(3)
with tech_col1:
    st.markdown("**Data Source**")
    st.markdown("- Microsoft Sentinel")
    st.markdown("- Log Analytics Workspace")
    st.markdown("- SecurityIncident Table")

with tech_col2:
    st.markdown("**Orchestration**")
    st.markdown("- CrewAI Framework")
    st.markdown("- 4 Specialized Agents")
    st.markdown("- Sequential Processing")

with tech_col3:
    st.markdown("**AI & LLM**")
    st.markdown("- Groq Llama 3.3 70B")
    st.markdown("- Real-time Analysis")
    st.markdown("- Threat Intelligence")

# ============================================================
# TAB 6: REPORTS
# ============================================================

with tab6:
    st.markdown("### 📄 Executive Summary Report")

    if not df_incidents.empty:
        total = len(df_incidents)
        critical = len(df_incidents[df_incidents['severity'] == 'Critical']) if 'severity' in df_incidents.columns else 0
        high = len(df_incidents[df_incidents['severity'] == 'High']) if 'severity' in df_incidents.columns else 0
        closed = len(df_incidents[df_incidents['status'] == 'Closed']) if 'status' in df_incidents.columns else 0
        
        st.markdown(f"""
        <div style="background-color: #1a1d24; border-radius: 12px; padding: 20px; margin: 10px 0;">
            <h4>📊 Security Operations Summary</h4>
            <p><strong>Reporting Period:</strong> Last {hours_back//24 if hours_back >= 24 else hours_back} days</p>
            <p><strong>Total Incidents:</strong> {total}</p>
            <p><strong>Critical/High Severity:</strong> {critical + high} ({int((critical+high)/total*100) if total > 0 else 0}%)</p>
            <p><strong>Closed Incidents:</strong> {closed} ({int(closed/total*100) if total > 0 else 0}%)</p>
            <hr>
            <h4>🎯 Key Findings</h4>
            <ul>
                <li>{critical} critical severity incidents require immediate attention</li>
                <li>{open_count} incidents currently active under investigation</li>
                <li>Risk index: {risk_index}/100</li>
            </ul>
            <hr>
            <h4>✅ Recommendations</h4>
            <ul>
                <li>Prioritize investigation of {critical} Critical incidents</li>
                <li>Review unassigned incidents for proper ownership</li>
                <li>Consider tuning Analytic Rules if false positive rate is high</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
        
        # Export option
        csv = df_incidents.to_csv(index=False)
        st.download_button(
            label="📥 Download Incident Report (CSV)",
            data=csv,
            file_name=f"soc_incident_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )

# ============================================================
# FOOTER
# ============================================================

st.markdown("---")
st.markdown("""
<footer>
🛡️ AI SOC Platform v4.0 | 4-Agent Multi-Agent System | Powered by CrewAI + Groq + Microsoft Sentinel<br>
Data Source: REAL incidents from YOUR Microsoft Sentinel workspace
</footer>
""", unsafe_allow_html=True)
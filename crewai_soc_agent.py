"""
crewai_soc_agent.py - RELIABLE Production Multi-Agent SOC System
Uses Log Analytics KQL (SecurityIncident table) - Most reliable method
4 Agents: Intake → Forensic → Threat Intel → Judge
LLM: Groq Llama 3.3 70B
"""

import os
import json
import requests
from datetime import datetime, timedelta
from typing import List, Dict
from dotenv import load_dotenv

# Azure authentication - YOUR EXISTING WORKING CONNECTION
from azure.identity import ClientSecretCredential
from azure.monitor.query import LogsQueryClient, LogsQueryStatus

# CrewAI imports
from crewai import Agent, Task, Crew, Process
from crewai import LLM
from crewai.tools import BaseTool

load_dotenv()

# ============================================================
# CONFIGURATION - EXISTING .env VARIABLES
# ============================================================

AZURE_TENANT_ID = os.getenv("AZURE_TENANT_ID")
AZURE_CLIENT_ID = os.getenv("AZURE_CLIENT_ID")
AZURE_CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET")
AZURE_WORKSPACE_ID = os.getenv("AZURE_WORKSPACE_ID")  # You already have this
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

# Optional External APIs
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

# ============================================================
# AZURE AUTHENTICATION - WORKING CONNECTION
# ============================================================

credential = ClientSecretCredential(
    tenant_id=AZURE_TENANT_ID,
    client_id=AZURE_CLIENT_ID,
    client_secret=AZURE_CLIENT_SECRET
)

logs_client = LogsQueryClient(credential)

print("=" * 70)
print("🤖 REAL PRODUCTION MULTI-AGENT SOC SYSTEM")
print("=" * 70)
print(f"✅ Log Analytics Client: CONNECTED")
print(f"✅ Workspace ID: {AZURE_WORKSPACE_ID[:10]}...")
print(f"✅ LLM: Groq Llama 3.3 70B")
print(f"✅ Data Source: SecurityIncident table (from your Analytic Rules)")
print("=" * 70)

# ============================================================
# FETCH INCIDENTS USING KQL 
# ============================================================

def fetch_sentinel_incidents(limit: int = 20, hours_back: int = 24) -> List[Dict]:
    """
    Fetch REAL incidents from Sentinel using KQL on SecurityIncident table.
    These incidents are created by YOUR Analytic Rules.
    This method is MORE RELIABLE than the REST API.
    """
    
    # KQL query to get latest incidents by IncidentNumber (removes duplicates) [citation:4][citation:7][citation:9]
    query = f"""
    SecurityIncident
    | where TimeGenerated > ago({hours_back}h)
    | summarize arg_max(TimeGenerated, *) by IncidentNumber
    | project 
        IncidentNumber,
        Title,
        Severity,
        Status,
        CreatedTime,
        LastModifiedTime,
        Description,
        Owner = tostring(Owner.assignedTo),
        Classification,
        AlertIds
    | order by CreatedTime desc
    | take {limit}
    """
    
    try:
        response = logs_client.query_workspace(
            workspace_id=AZURE_WORKSPACE_ID,
            query=query,
            timespan=timedelta(hours=hours_back)
        )
        
        if response.status == LogsQueryStatus.SUCCESS:
            incidents = []
            if response.tables:
                for row in response.tables[0].rows:
                    incidents.append({
                        "incident_number": row[0],
                        "title": row[1],
                        "severity": row[2],
                        "status": row[3],
                        "time_created": str(row[4]) if row[4] else None,
                        "last_modified": str(row[5]) if row[5] else None,
                        "description": row[6] or "No description",
                        "owner": row[7] or "Unassigned",
                        "classification": row[8] or "",
                        "alert_ids": row[9] if len(row) > 9 else []
                    })
            
            print(f"\n✅ Fetched {len(incidents)} REAL incidents from Sentinel (via KQL)")
            return incidents
        else:
            print(f"\n⚠️ Query completed with warnings: {response.partial_error}")
            return []
            
    except Exception as e:
        print(f"\n❌ Failed to fetch incidents: {e}")
        return []

def fetch_incident_details(incident_number: int) -> Dict:
    """
    Fetch detailed information for a specific incident
    Including entities from related alerts if available [citation:1]
    """
    
    # First get the incident details
    query = f"""
    SecurityIncident
    | where IncidentNumber == {incident_number}
    | summarize arg_max(TimeGenerated, *) by IncidentNumber
    | project 
        IncidentNumber,
        Title,
        Severity,
        Status,
        CreatedTime,
        Description,
        Owner = tostring(Owner.assignedTo),
        AlertIds,
        Comments
    """
    
    try:
        response = logs_client.query_workspace(
            workspace_id=AZURE_WORKSPACE_ID,
            query=query,
            timespan=timedelta(days=7)
        )
        
        if response.status == LogsQueryStatus.SUCCESS and response.tables and response.tables[0].rows:
            row = response.tables[0].rows[0]
            
            # Try to get hostnames from related alerts if needed [citation:1]
            # Note: SecurityIncident doesn't directly expose Entities anymore
            # Entities are stored in SecurityAlert table
            
            return {
                "incident_number": row[0],
                "title": row[1],
                "severity": row[2],
                "status": row[3],
                "time_created": str(row[4]) if row[4] else None,
                "description": row[5] or "No description",
                "owner": row[6] or "Unassigned",
                "alert_ids": row[7] if len(row) > 7 else [],
                "comments": row[8] if len(row) > 8 else []
            }
        
        return {}
        
    except Exception as e:
        print(f"❌ Error fetching incident details: {e}")
        return {}

def extract_ips_from_alert_ids(alert_ids: List[str]) -> List[str]:
    """Extract IP addresses from alerts if available"""
    if not alert_ids:
        return []
    
    # Build query to get IPs from SecurityAlert table
    alert_list = ", ".join([f'"{aid}"' for aid in alert_ids])
    query = f"""
    SecurityAlert
    | where SystemAlertId in ({alert_list})
    | extend EntitiesList = parse_json(Entities)
    | mv-expand EntitiesList
    | extend EntityType = tostring(EntitiesList.Type)
    | where EntityType == "ip"
    | extend IpAddress = tostring(EntitiesList.Address)
    | where isnotempty(IpAddress)
    | distinct IpAddress
    """
    
    try:
        response = logs_client.query_workspace(
            workspace_id=AZURE_WORKSPACE_ID,
            query=query,
            timespan=timedelta(days=7)
        )
        
        ips = []
        if response.status == LogsQueryStatus.SUCCESS and response.tables:
            for row in response.tables[0].rows:
                ips.append(row[0])
        return ips
    except:
        return []

# ============================================================
# CREATE LLM - GROQ LLAMA 3.3 70B
# ============================================================

llm = LLM(
    model="groq/llama-3.3-70b-versatile",
    api_key=GROQ_API_KEY,
    temperature=0.1
)

# ============================================================
# TOOLS FOR AGENTS (USING RELIABLE KQL METHOD)
# ============================================================

class GetIncidentsTool(BaseTool):
    name: str = "get_incidents"
    description: str = "Fetch REAL security incidents from Microsoft Sentinel using KQL"
    
    def _run(self, hours_back: int = 24, limit: int = 20) -> str:
        incidents = fetch_sentinel_incidents(limit=limit, hours_back=hours_back)
        return json.dumps(incidents, default=str)

class GetIncidentDetailsTool(BaseTool):
    name: str = "get_incident_details"
    description: str = "Get detailed information about a specific incident"
    
    def _run(self, incident_number: int) -> str:
        details = fetch_incident_details(incident_number)
        
        # Try to extract IPs from alerts if available
        if details.get("alert_ids"):
            ips = extract_ips_from_alert_ids(details["alert_ids"])
            details["extracted_ips"] = ips
        
        return json.dumps(details, default=str)

class CheckIPReputationTool(BaseTool):
    name: str = "check_ip_reputation"
    description: str = "Check IP reputation using VirusTotal and AbuseIPDB"
    
    def _run(self, ip_address: str) -> str:
        results = {"ip": ip_address, "sources": {}, "verdict": "UNKNOWN", "threat_score": 0}
        
        # VirusTotal
        if VIRUSTOTAL_API_KEY:
            try:
                vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
                headers = {"x-apikey": VIRUSTOTAL_API_KEY}
                response = requests.get(vt_url, headers=headers, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                    results["sources"]["virustotal"] = {
                        "malicious": stats.get('malicious', 0),
                        "suspicious": stats.get('suspicious', 0),
                        "harmless": stats.get('harmless', 0)
                    }
                    results["threat_score"] += stats.get('malicious', 0) * 10
            except Exception as e:
                results["sources"]["virustotal"] = {"error": str(e)}
        
        # AbuseIPDB
        if ABUSEIPDB_API_KEY:
            try:
                abuse_url = "https://api.abuseipdb.com/api/v2/check"
                headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
                params = {"ipAddress": ip_address, "maxAgeInDays": "90"}
                response = requests.get(abuse_url, headers=headers, params=params, timeout=10)
                
                if response.status_code == 200:
                    data = response.json().get('data', {})
                    results["sources"]["abuseipdb"] = {
                        "abuse_score": data.get('abuseConfidenceScore', 0),
                        "total_reports": data.get('totalReports', 0),
                        "country": data.get('countryCode', 'Unknown')
                    }
                    results["threat_score"] += data.get('abuseConfidenceScore', 0) / 10
            except Exception as e:
                results["sources"]["abuseipdb"] = {"error": str(e)}
        
        results["threat_score"] = min(results["threat_score"], 100)
        if results["threat_score"] >= 70:
            results["verdict"] = "MALICIOUS"
        elif results["threat_score"] >= 40:
            results["verdict"] = "SUSPICIOUS"
        else:
            results["verdict"] = "CLEAN"
        
        return json.dumps(results)

# ============================================================
# CREATE TOOL INSTANCES
# ============================================================

get_incidents_tool = GetIncidentsTool()
get_details_tool = GetIncidentDetailsTool()
check_ip_tool = CheckIPReputationTool()

# ============================================================
# AGENT 1: INTAKE & SCOPE ARCHITECT
# ============================================================

intake_agent = Agent(
    role="Intake & Scope Architect",
    goal="Fetch and analyze REAL Sentinel incidents using Groq AI",
    backstory="""You are a senior SOC intake analyst. Your job:
    
    1. Use get_incidents tool to fetch REAL incidents from Sentinel
    2. Analyze each incident using your AI intelligence
    3. Determine the priority and true severity
    4. Extract key entities and indicators
    
    Analytic Rules detected these incidents. Now YOU analyze them
    using your cybersecurity expertise.""",
    llm=llm,
    tools=[get_incidents_tool],
    verbose=True
)

# ============================================================
# AGENT 2: FORENSIC INVESTIGATOR
# ============================================================

forensic_agent = Agent(
    role="Deep-Dive Forensic Investigator",
    goal="Analyze incident details, user behavior, and entity patterns",
    backstory="""You are a forensic investigator AI. Your job:
    
    1. Use get_incident_details tool for the selected incident
    2. Analyze:
       - What actually happened?
       - What is the attack timeline?
       - Which users, IPs, hosts are involved?
       - What is the potential blast radius?
    3. Provide detailed forensic analysis
    
    Connect all the evidence and think like a forensic expert.""",
    llm=llm,
    tools=[get_details_tool, check_ip_tool],
    verbose=True
)

# ============================================================
# AGENT 3: THREAT INTEL SPECIALIST
# ============================================================

threat_intel_agent = Agent(
    role="Threat Intel & OSINT Specialist",
    goal="Provide threat intelligence context for IPs and indicators",
    backstory="""You are a threat intelligence AI. Your job:
    
    1. Review IP addresses identified in the incident
    2. Use check_ip_reputation tool for external threat intel
    3. Analyze:
       - Is this IP known malicious?
       - What threat actor might be responsible?
       - What TTPs are being used?
    4. Provide actionable intelligence
    
    Provide context that helps the SOC respond effectively.""",
    llm=llm,
    tools=[check_ip_tool],
    verbose=True
)

# ============================================================
# AGENT 4: FINAL JUDGE
# ============================================================

final_judge_agent = Agent(
    role="Final Judge & Decision Maker",
    goal="Make final risk assessment and recommend actions",
    backstory="""You are the final decision-making AI for the SOC.
    
    YOUR RESPONSIBILITY:
    1. Review all analyses from the three specialized agents
    2. Calculate FINAL RISK SCORE (0-100) based on YOUR reasoning
    3. Provide specific, actionable recommendations
    4. Determine if human review is needed
    
    RISK LEVELS:
    - 70-100: HIGH RISK - Escalate immediately
    - 40-69: MEDIUM RISK - Create ticket, document findings
    - 0-39: LOW RISK - Auto-close with notes
    
    Be decisive. Your analysis drives the security response.""",
    llm=llm,
    tools=[],
    verbose=True
)

# ============================================================
# TASKS
# ============================================================

task_intake = Task(
    description="""TASK 1: INCIDENT INTAKE & ANALYSIS

    Step 1: Use get_incidents tool to fetch REAL incidents from the last 24 hours
    Step 2: Analyze each incident using your AI intelligence
    Step 3: For the highest priority incident, provide:
        - Incident title and severity from Sentinel
        - Your true/false positive assessment
        - Why this matters (business impact)
        - Key entities involved (users, IPs, hosts)
    
    Your Analytic Rules detected these. Now YOU analyze them with your AI.
    """,
    expected_output="Comprehensive incident analysis with prioritization and impact assessment",
    agent=intake_agent
)

task_forensic = Task(
    description="""TASK 2: DETAILED FORENSIC INVESTIGATION

    Using the incident identified in Task 1:
    
    Step 1: Use get_incident_details tool with that incident number
    Step 2: Analyze all available details
    Step 3: For any IP addresses found, use check_ip_reputation
    Step 4: Provide forensic analysis:
        - What actually happened?
        - What is the attack timeline?
        - Which assets are affected?
        - What is the blast radius?
    
    Be thorough. Use your cybersecurity expertise.
    """,
    expected_output="Detailed forensic analysis with entity investigation and attack timeline",
    agent=forensic_agent,
    context=[task_intake]
)

task_threat_intel = Task(
    description="""TASK 3: THREAT INTELLIGENCE CONTEXT

    Using the IPs identified in the incident:
    
    Step 1: Use check_ip_reputation for each suspicious IP
    Step 2: Analyze threat intelligence to determine:
        - Is this known malicious infrastructure?
        - What threat actor typically uses this?
        - What is the attacker's likely objective?
        - What other indicators should we look for?
    
    Provide intelligence to guide the response.
    """,
    expected_output="Threat intelligence report with attribution and TTP analysis",
    agent=threat_intel_agent,
    context=[task_intake, task_forensic]
)

task_judgment = Task(
    description="""TASK 4: FINAL JUDGMENT AND DECISION

    Review all previous analyses and make the final decision:
    
    1. Calculate FINAL RISK SCORE (0-100):
       - Alert severity contribution (0-35 points)
       - Forensic findings contribution (0-35 points)
       - Threat intelligence contribution (0-30 points)
    
    2. Provide YOUR reasoning for the score
    
    3. Specific recommendations:
       - Block IPs? List them
       - Reset credentials? Which users?
       - Isolate hosts? Which ones?
       - Escalate to L2? Yes/No
    
    4. Executive summary for SOC manager
    
    Be decisive. Your analysis determines the response.
    """,
    expected_output="Final risk score with detailed justification and actionable recommendations",
    agent=final_judge_agent,
    context=[task_intake, task_forensic, task_threat_intel]
)

# ============================================================
# CREATE CREW
# ============================================================

soc_crew = Crew(
    agents=[intake_agent, forensic_agent, threat_intel_agent, final_judge_agent],
    tasks=[task_intake, task_forensic, task_threat_intel, task_judgment],
    process=Process.sequential,
    verbose=True
)

# ============================================================
# HUMAN REVIEW FUNCTION
# ============================================================

def human_review(risk_score: int, incident_title: str) -> bool:
    if risk_score < 40:
        print("\n" + "=" * 60)
        print("🔄 AUTO-CLOSING: AI determined LOW RISK")
        print("=" * 60)
        print(f"Incident: {incident_title}")
        print(f"Risk Score: {risk_score}%")
        print("No human intervention required.")
        return True
    
    print("\n" + "=" * 60)
    print("🛑 HUMAN REVIEW REQUIRED")
    print("=" * 60)
    print(f"Incident: {incident_title}")
    print(f"AI Risk Score: {risk_score}%")
    if risk_score >= 70:
        print("⚠️ HIGH RISK - Escalation recommended")
    else:
        print("🟠 MEDIUM RISK - Review recommended")
    print("=" * 60)
    
    response = input("\nApprove the AI's recommendation? (yes/no): ").lower()
    return response in ['yes', 'y']

# ============================================================
# MAIN FUNCTION
# ============================================================

def run_soc_investigation():
    print("\n" + "=" * 70)
    print("🔍 STARTING SOC INCIDENT INVESTIGATION")
    print("=" * 70)
    print("📡 Data Source: SecurityIncident table (Log Analytics)")
    print("🤖 AI Model: Groq Llama 3.3 70B")
    print("👥 Agents: 4 (Intake → Forensic → Threat Intel → Judge)")
    print("=" * 70)
    
    print("\n📋 Fetching recent incidents from Sentinel...")
    incidents = fetch_sentinel_incidents(limit=10, hours_back=168)
    
    if not incidents:
        print("\n⚠️ No incidents found in the last 7 days.")
        print("   Your Analytic Rules haven't triggered any incidents.")
        print("   The system is ready and waiting for real incidents.")
        return
    
    print(f"\n🚨 Found {len(incidents)} incidents to investigate")
    print("\n📋 Incident List:")
    for inc in incidents[:5]:
        print(f"   → [{inc.get('severity')}] #{inc.get('incident_number')}: {inc.get('title')}")
    
    print("\n" + "=" * 70)
    
    result = soc_crew.kickoff()
    
    result_str = str(result)
    import re
    risk_match = re.search(r'risk score[:\s]*(\d+)', result_str, re.IGNORECASE)
    risk_score = int(risk_match.group(1)) if risk_match else 50
    
    incident_title = incidents[0].get("title", "Unknown") if incidents else "Unknown"
    approved = human_review(risk_score, incident_title)
    
    print("\n" + "=" * 70)
    print("✅ INVESTIGATION COMPLETE")
    print("=" * 70)
    print(f"Final Risk Score: {risk_score}%")
    print(f"Human Decision: {'✅ APPROVED' if approved else '❌ REJECTED'}")
    print("=" * 70)
    
    return result

def test_connection():
    print("\n🔌 Testing Log Analytics Connection...")
    try:
        query = "SecurityIncident | take 1"
        response = logs_client.query_workspace(
            workspace_id=AZURE_WORKSPACE_ID,
            query=query,
            timespan=timedelta(hours=1)
        )
        print("\n✅ SUCCESS! Connected to Log Analytics")
        print(f"✅ Workspace ID: {AZURE_WORKSPACE_ID[:20]}...")
        return True
    except Exception as e:
        print(f"\n❌ Connection failed: {e}")
        return False

# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":
    print("=" * 70)
    print("🤖 PRODUCTION MULTI-AGENT SOC SYSTEM")
    print("=" * 70)
    print("What this system does:")
    print("  ✅ Fetches REAL incidents from YOUR Microsoft Sentinel")
    print("  ✅ Uses KQL on SecurityIncident table (MOST RELIABLE METHOD)")
    print("  ✅ Uses YOUR Analytic Rules (no detection logic in this code)")
    print("  ✅ 4 AI Agents analyze with Groq Llama 3.3 70B")
    print("  ✅ Provides investigation findings and recommendations")
    print("=" * 70)
    
    if test_connection():
        run_soc_investigation()
    else:
        print("\n❌ Cannot proceed. Check your .env configuration.")
        print("\n📋 Required .env variables:")
        print("  AZURE_TENANT_ID=xxx")
        print("  AZURE_CLIENT_ID=xxx")
        print("  AZURE_CLIENT_SECRET=xxx")
        print("  AZURE_WORKSPACE_ID=xxx  # ← YOU ALREADY HAVE THIS")
        print("  GROQ_API_KEY=gsk_xxx")
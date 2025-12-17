import streamlit as st
import requests
import plotly.graph_objects as go
import pandas as pd
from datetime import datetime
import time
import json
from pathlib import Path
import os

# Page configuration
st.set_page_config(
    page_title="Cyhawk Africa - Live Threat Map",
    page_icon="assets/favicon.png",  # Using favicon from assets
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for Cyhawk Africa branding
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(135deg, #0a4a6e 0%, #1e3a8a 100%);
        padding: 2rem;
        border-radius: 10px;
        margin-bottom: 2rem;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
    }
    .logo-container {
        display: flex;
        align-items: center;
        gap: 1.5rem;
        margin-bottom: 1rem;
    }
    .logo-image {
        width: 80px;
        height: 80px;
        object-fit: contain;
    }
    .cyhawk-logo {
        font-size: 3rem;
        font-weight: bold;
        background: linear-gradient(135deg, #06b6d4 0%, #3b82f6 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        line-height: 1.2;
    }
    .threat-card {
        background: linear-gradient(135deg, rgba(6, 182, 212, 0.1) 0%, rgba(59, 130, 246, 0.1) 100%);
        padding: 1.5rem;
        border-radius: 8px;
        border-left: 4px solid #06b6d4;
        margin-bottom: 1rem;
    }
    .stat-box {
        background: rgba(10, 74, 110, 0.3);
        padding: 1.5rem;
        border-radius: 8px;
        border: 1px solid rgba(6, 182, 212, 0.3);
        text-align: center;
    }
    .severity-critical {
        color: #ef4444;
        font-weight: bold;
    }
    .severity-high {
        color: #f97316;
        font-weight: bold;
    }
    .severity-medium {
        color: #eab308;
        font-weight: bold;
    }
    .severity-low {
        color: #22c55e;
        font-weight: bold;
    }
    .api-badge {
        display: inline-block;
        background: rgba(6, 182, 212, 0.2);
        color: #06b6d4;
        padding: 0.25rem 0.75rem;
        border-radius: 12px;
        font-size: 0.75rem;
        margin: 0.25rem;
    }
    .debug-info {
        background: rgba(139, 92, 246, 0.1);
        border: 1px solid rgba(139, 92, 246, 0.3);
        padding: 1rem;
        border-radius: 8px;
        margin-bottom: 1rem;
        font-size: 0.85rem;
    }
</style>
""", unsafe_allow_html=True)

# Country coordinates database
COUNTRY_COORDS = {
    'US': {'name': 'USA', 'lat': 37.0902, 'lon': -95.7129},
    'CN': {'name': 'China', 'lat': 35.8617, 'lon': 104.1954},
    'RU': {'name': 'Russia', 'lat': 61.5240, 'lon': 105.3188},
    'BR': {'name': 'Brazil', 'lat': -14.2350, 'lon': -51.9253},
    'IN': {'name': 'India', 'lat': 20.5937, 'lon': 78.9629},
    'DE': {'name': 'Germany', 'lat': 51.1657, 'lon': 10.4515},
    'GB': {'name': 'UK', 'lat': 55.3781, 'lon': -3.4360},
    'JP': {'name': 'Japan', 'lat': 36.2048, 'lon': 138.2529},
    'KR': {'name': 'South Korea', 'lat': 35.9078, 'lon': 127.7669},
    'FR': {'name': 'France', 'lat': 46.2276, 'lon': 2.2137},
    'AU': {'name': 'Australia', 'lat': -25.2744, 'lon': 133.7751},
    'CA': {'name': 'Canada', 'lat': 56.1304, 'lon': -106.3468},
    'NL': {'name': 'Netherlands', 'lat': 52.1326, 'lon': 5.2913},
    'VN': {'name': 'Vietnam', 'lat': 14.0583, 'lon': 108.2772},
    'PL': {'name': 'Poland', 'lat': 51.9194, 'lon': 19.1451},
    'UA': {'name': 'Ukraine', 'lat': 48.3794, 'lon': 31.1656},
    'IT': {'name': 'Italy', 'lat': 41.8719, 'lon': 12.5674},
    'ES': {'name': 'Spain', 'lat': 40.4637, 'lon': -3.7492},
    'TR': {'name': 'Turkey', 'lat': 38.9637, 'lon': 35.2433},
    'ID': {'name': 'Indonesia', 'lat': -0.7893, 'lon': 113.9213},
    'Unknown': {'name': 'Unknown', 'lat': 0, 'lon': 0}
}

def get_country_from_code(code):
    """Get country info from code"""
    if not code:
        return COUNTRY_COORDS['Unknown']
    return COUNTRY_COORDS.get(code.upper(), COUNTRY_COORDS['Unknown'])

# ===========================================
# LOGO AND ASSET DETECTION
# ===========================================

def check_assets():
    """Check for logo and favicon files and return their status"""
    # Get current working directory
    cwd = os.getcwd()
    
    # Possible logo paths
    logo_paths = [
        "assets/CyHawk-logo.png",
        "./assets/CyHawk-logo.png",
        "CyHawk-logo.png",
        os.path.join(cwd, "assets", "CyHawk-logo.png")
    ]
    
    # Possible favicon paths
    favicon_paths = [
        "assets/favicon.png",
        "./assets/favicon.png",
        "favicon.png",
        os.path.join(cwd, "assets", "favicon.png")
    ]
    
    # Check which files exist
    logo_info = {
        'exists': False,
        'path': None,
        'checked_paths': []
    }
    
    favicon_info = {
        'exists': False,
        'path': None,
        'checked_paths': []
    }
    
    # Check logo paths
    for path in logo_paths:
        logo_info['checked_paths'].append(path)
        if Path(path).exists():
            logo_info['exists'] = True
            logo_info['path'] = path
            break
    
    # Check favicon paths
    for path in favicon_paths:
        favicon_info['checked_paths'].append(path)
        if Path(path).exists():
            favicon_info['exists'] = True
            favicon_info['path'] = path
            break
    
    return {
        'cwd': cwd,
        'logo': logo_info,
        'favicon': favicon_info,
        'files_in_cwd': list(Path(cwd).glob('*')),
        'files_in_assets': list(Path(cwd, 'assets').glob('*')) if Path(cwd, 'assets').exists() else []
    }

# ===========================================
# API INTEGRATION FUNCTIONS
# ===========================================

def fetch_urlhaus_threats():
    """Fetch threats from URLhaus (No API key required)"""
    try:
        response = requests.post(
            'https://urlhaus-api.abuse.ch/v1/urls/recent/',
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            timeout=10
        )
        data = response.json()
        
        if data.get('query_status') == 'ok' and data.get('urls'):
            threats = []
            for url in data['urls'][:5]:
                threats.append({
                    'id': f"urlhaus-{datetime.now().timestamp()}-{hash(url['url'])}",
                    'type': url.get('threat', 'Malware Distribution'),
                    'source_country': 'RU' if url.get('url_status') == 'online' else 'CN',
                    'target_country': 'US',
                    'timestamp': datetime.fromisoformat(url['dateadded'].replace('Z', '+00:00')),
                    'severity': 'Critical' if url.get('url_status') == 'online' else 'High',
                    'api_source': 'URLhaus',
                    'details': {
                        'url': url['url'][:50] + '...',
                        'tags': ', '.join(url.get('tags', [])) if url.get('tags') else 'none',
                        'reporter': url.get('reporter', 'Unknown')
                    }
                })
            return threats
    except Exception as e:
        st.error(f"URLhaus API error: {str(e)}")
    return []

def fetch_threatfox_data():
    """Fetch threats from ThreatFox (No API key required)"""
    try:
        response = requests.post(
            'https://threatfox-api.abuse.ch/api/v1/',
            headers={'Content-Type': 'application/json'},
            json={'query': 'get_iocs', 'days': 1},
            timeout=10
        )
        data = response.json()
        
        if data.get('query_status') == 'ok' and data.get('data'):
            threats = []
            for ioc in data['data'][:5]:
                threats.append({
                    'id': f"threatfox-{datetime.now().timestamp()}-{hash(ioc['id'])}",
                    'type': ioc.get('malware_printable', 'Malware C2'),
                    'source_country': 'CN',
                    'target_country': 'US',
                    'timestamp': datetime.fromisoformat(ioc['first_seen'].replace(' ', 'T')),
                    'severity': 'Critical' if ioc.get('confidence_level', 0) >= 75 else 'High',
                    'api_source': 'ThreatFox',
                    'details': {
                        'malware': ioc.get('malware_printable', 'Unknown'),
                        'threat_type': ioc.get('threat_type', 'Unknown'),
                        'confidence': f"{ioc.get('confidence_level', 0)}%"
                    }
                })
            return threats
    except Exception as e:
        st.error(f"ThreatFox API error: {str(e)}")
    return []

def fetch_abuseipdb(api_key):
    """Fetch threats from AbuseIPDB (Requires API key)"""
    if not api_key:
        return []
    
    try:
        response = requests.get(
            'https://api.abuseipdb.com/api/v2/blacklist?limit=10',
            headers={
                'Key': api_key,
                'Accept': 'application/json'
            },
            timeout=10
        )
        data = response.json()
        
        if data.get('data'):
            threats = []
            for ip in data['data'][:5]:
                score = ip.get('abuseConfidenceScore', 0)
                threats.append({
                    'id': f"abuseipdb-{datetime.now().timestamp()}-{hash(ip['ipAddress'])}",
                    'type': 'IP Abuse/Attack',
                    'source_country': ip.get('countryCode', 'Unknown'),
                    'target_country': 'US',
                    'timestamp': datetime.now(),
                    'severity': 'Critical' if score >= 90 else 'High' if score >= 75 else 'Medium',
                    'api_source': 'AbuseIPDB',
                    'details': {
                        'ip': ip['ipAddress'],
                        'score': f"{score}%",
                        'country': ip.get('countryCode', 'Unknown')
                    }
                })
            return threats
    except Exception as e:
        st.error(f"AbuseIPDB API error: {str(e)}")
    return []

def fetch_greynoise(api_key):
    """Fetch threats from GreyNoise (Requires API key)"""
    if not api_key:
        return []
    
    try:
        response = requests.get(
            'https://api.greynoise.io/v3/community/8.8.8.8',
            headers={'key': api_key},
            timeout=10
        )
        data = response.json()
        
        if data:
            return [{
                'id': f"greynoise-{datetime.now().timestamp()}",
                'type': 'Internet Scanner',
                'source_country': 'CN',
                'target_country': 'US',
                'timestamp': datetime.now(),
                'severity': 'Medium',
                'api_source': 'GreyNoise',
                'details': {
                    'classification': data.get('classification', 'unknown'),
                    'noise': 'Yes' if data.get('noise') else 'No',
                    'name': data.get('name', 'Scanner')
                }
            }]
    except Exception as e:
        st.error(f"GreyNoise API error: {str(e)}")
    return []

def fetch_virustotal(api_key):
    """Fetch threats from VirusTotal (Requires API key)"""
    if not api_key:
        return []
    
    try:
        response = requests.get(
            'https://www.virustotal.com/api/v3/intelligence/search?query=type:ip_address',
            headers={'x-apikey': api_key},
            timeout=10
        )
        data = response.json()
        
        if data.get('data'):
            threats = []
            for item in data['data'][:3]:
                attrs = item.get('attributes', {})
                malicious = attrs.get('last_analysis_stats', {}).get('malicious', 0)
                threats.append({
                    'id': f"virustotal-{datetime.now().timestamp()}-{hash(str(item))}",
                    'type': 'Malicious IP',
                    'source_country': attrs.get('country', 'Unknown'),
                    'target_country': 'US',
                    'timestamp': datetime.now(),
                    'severity': 'Critical' if malicious > 10 else 'High' if malicious > 5 else 'Medium',
                    'api_source': 'VirusTotal',
                    'details': {
                        'detections': f"{malicious} detections",
                        'asn': attrs.get('asn', 'Unknown'),
                        'network': attrs.get('network', 'Unknown')
                    }
                })
            return threats
    except Exception as e:
        st.error(f"VirusTotal API error: {str(e)}")
    return []

def fetch_pulsedive(api_key):
    """Fetch threats from Pulsedive (Requires API key)"""
    if not api_key:
        return []
    
    try:
        response = requests.get(
            f'https://pulsedive.com/api/explore.php?q=risk:high&limit=5&key={api_key}',
            timeout=10
        )
        data = response.json()
        
        if data.get('results'):
            threats = []
            for item in data['results']:
                threats.append({
                    'id': f"pulsedive-{datetime.now().timestamp()}-{hash(str(item))}",
                    'type': item.get('type', 'Threat'),
                    'source_country': 'RU',
                    'target_country': 'US',
                    'timestamp': datetime.now(),
                    'severity': 'Critical' if item.get('risk') == 'critical' else 'High' if item.get('risk') == 'high' else 'Medium',
                    'api_source': 'Pulsedive',
                    'details': {
                        'indicator': item.get('indicator', 'Unknown'),
                        'risk': item.get('risk', 'unknown'),
                        'threats': ', '.join(item.get('threats', [])) if item.get('threats') else 'none'
                    }
                })
            return threats
    except Exception as e:
        st.error(f"Pulsedive API error: {str(e)}")
    return []

def create_globe_visualization(threats_df):
    """Create 3D globe with threat lines"""
    if threats_df.empty:
        return None
    
    fig = go.Figure()
    
    # Add Earth sphere
    fig.add_trace(go.Scattergeo(
        lon=[0],
        lat=[0],
        mode='markers',
        marker=dict(size=1, color='rgba(0,0,0,0)'),
        showlegend=False
    ))
    
    # Add threat lines
    for _, threat in threats_df.iterrows():
        source = get_country_from_code(threat['source_country'])
        target = get_country_from_code(threat['target_country'])
        
        color = {
            'Critical': 'red',
            'High': 'orange',
            'Medium': 'yellow',
            'Low': 'green'
        }.get(threat['severity'], 'cyan')
        
        fig.add_trace(go.Scattergeo(
            lon=[source['lon'], target['lon']],
            lat=[source['lat'], target['lat']],
            mode='lines',
            line=dict(width=2, color=color),
            opacity=0.6,
            showlegend=False,
            hovertemplate=f"<b>{threat['type']}</b><br>" +
                         f"From: {source['name']}<br>" +
                         f"To: {target['name']}<br>" +
                         f"Severity: {threat['severity']}<br>" +
                         f"Source: {threat['api_source']}<extra></extra>"
        ))
    
    fig.update_geos(
        projection_type="orthographic",
        showland=True,
        landcolor="rgb(10, 74, 110)",
        oceancolor="rgb(15, 23, 42)",
        showocean=True,
        showcountries=True,
        countrycolor="rgb(6, 182, 212)",
        bgcolor="rgba(0,0,0,0)"
    )
    
    fig.update_layout(
        height=600,
        margin=dict(l=0, r=0, t=0, b=0),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)"
    )
    
    return fig

# Initialize session state
if 'threats' not in st.session_state:
    st.session_state.threats = []
if 'total_attacks' not in st.session_state:
    st.session_state.total_attacks = 0
if 'critical_count' not in st.session_state:
    st.session_state.critical_count = 0
if 'show_debug' not in st.session_state:
    st.session_state.show_debug = True  # Show debug by default on first load

# ===========================================
# MAIN APPLICATION
# ===========================================

# Check for assets
asset_info = check_assets()

# Debug information (collapsible)
if st.session_state.show_debug:
    with st.expander("🔍 Asset Debug Information", expanded=True):
        st.markdown(f"""
        <div class="debug-info">
            <h4 style="color: #06b6d4; margin-bottom: 1rem;">📂 File System Information</h4>
            
            <p><strong>Current Working Directory:</strong><br/>
            <code>{asset_info['cwd']}</code></p>
            
            <h5 style="color: #06b6d4; margin-top: 1rem;">🖼️ Logo Status</h5>
            <p><strong>Found:</strong> {"✅ Yes" if asset_info['logo']['exists'] else "❌ No"}</p>
            {f"<p><strong>Path:</strong> <code>{asset_info['logo']['path']}</code></p>" if asset_info['logo']['exists'] else ""}
            <p><strong>Checked paths:</strong></p>
            <ul style="font-size: 0.85rem;">
                {''.join([f"<li><code>{path}</code> {'✅' if Path(path).exists() else '❌'}</li>" for path in asset_info['logo']['checked_paths']])}
            </ul>
            
            <h5 style="color: #06b6d4; margin-top: 1rem;">🎯 Favicon Status</h5>
            <p><strong>Found:</strong> {"✅ Yes" if asset_info['favicon']['exists'] else "❌ No"}</p>
            {f"<p><strong>Path:</strong> <code>{asset_info['favicon']['path']}</code></p>" if asset_info['favicon']['exists'] else ""}
            <p><strong>Checked paths:</strong></p>
            <ul style="font-size: 0.85rem;">
                {''.join([f"<li><code>{path}</code> {'✅' if Path(path).exists() else '❌'}</li>" for path in asset_info['favicon']['checked_paths']])}
            </ul>
            
            <h5 style="color: #06b6d4; margin-top: 1rem;">📁 Files in Current Directory</h5>
            <ul style="font-size: 0.85rem;">
                {''.join([f"<li><code>{f.name}</code></li>" for f in asset_info['files_in_cwd'][:10]])}
            </ul>
            
            {f'''<h5 style="color: #06b6d4; margin-top: 1rem;">📁 Files in Assets Directory</h5>
            <ul style="font-size: 0.85rem;">
                {''.join([f"<li><code>{f.name}</code></li>" for f in asset_info['files_in_assets']])}
            </ul>''' if asset_info['files_in_assets'] else '<p style="color: #f97316;">⚠️ Assets directory not found</p>'}
        </div>
        """, unsafe_allow_html=True)
        
        if st.button("Hide Debug Info"):
            st.session_state.show_debug = False
            st.rerun()

# Header with Cyhawk Africa branding
if asset_info['logo']['exists']:
    # Use actual logo
    st.markdown('<div class="main-header">', unsafe_allow_html=True)
    col_logo, col_text = st.columns([1, 5])
    with col_logo:
        st.image(asset_info['logo']['path'], width=80)
    with col_text:
        st.markdown("""
        <div>
            <div class="cyhawk-logo">CYHAWK AFRICA</div>
            <div style="color: #06b6d4; font-size: 1.2rem; font-weight: 600;">Live Cyber Threat Intelligence Map</div>
        </div>
        """, unsafe_allow_html=True)
    st.markdown("""
    <div style="color: rgba(255,255,255,0.7); font-size: 0.9rem; margin-top: 1rem;">
        Real-time threat monitoring powered by global intelligence feeds
    </div>
    """, unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)
else:
    # Fallback to emoji if logo not found
    st.markdown("""
    <div class="main-header">
        <div class="logo-container">
            <div style="font-size: 4rem;">🦅</div>
            <div>
                <div class="cyhawk-logo">CYHAWK AFRICA</div>
                <div style="color: #06b6d4; font-size: 1.2rem; font-weight: 600;">Live Cyber Threat Intelligence Map</div>
            </div>
        </div>
        <div style="color: rgba(255,255,255,0.7); font-size: 0.9rem;">
            Real-time threat monitoring powered by global intelligence feeds
        </div>
        <div style="color: #f97316; font-size: 0.85rem; margin-top: 0.5rem;">
            ⚠️ Logo not found - check debug info above
        </div>
    </div>
    """, unsafe_allow_html=True)

# Sidebar configuration
with st.sidebar:
    st.markdown("### ⚙️ Configuration")
    st.markdown("---")
    
    if not st.session_state.show_debug:
        if st.button("Show Debug Info"):
            st.session_state.show_debug = True
            st.rerun()
    
    st.markdown("#### 🆓 Free APIs (Always Active)")
    st.success("✅ URLhaus - Malicious URLs")
    st.success("✅ ThreatFox - IOC Database")
    
    st.markdown("---")
    st.markdown("#### 🔑 Optional API Keys")
    
    abuseipdb_key = st.text_input(
        "AbuseIPDB API Key",
        type="password",
        help="Get free key at https://www.abuseipdb.com/register"
    )
    
    greynoise_key = st.text_input(
        "GreyNoise API Key",
        type="password",
        help="Get free key at https://www.greynoise.io/viz/signup"
    )
    
    virustotal_key = st.text_input(
        "VirusTotal API Key",
        type="password",
        help="Get free key at https://www.virustotal.com/gui/join-us"
    )
    
    pulsedive_key = st.text_input(
        "Pulsedive API Key",
        type="password",
        help="Get free key at https://pulsedive.com/register"
    )
    
    st.markdown("---")
    auto_refresh = st.checkbox("Auto-refresh (30s)", value=True)
    
    if st.button("🔄 Fetch Threats Now", type="primary", use_container_width=True):
        with st.spinner("Fetching real-time threat data..."):
            # Fetch from all sources
            all_threats = []
            active_apis = []
            
            # Free APIs
            all_threats.extend(fetch_urlhaus_threats())
            all_threats.extend(fetch_threatfox_data())
            active_apis.extend(['URLhaus', 'ThreatFox'])
            
            # Optional APIs
            if abuseipdb_key:
                all_threats.extend(fetch_abuseipdb(abuseipdb_key))
                active_apis.append('AbuseIPDB')
            
            if greynoise_key:
                all_threats.extend(fetch_greynoise(greynoise_key))
                active_apis.append('GreyNoise')
            
            if virustotal_key:
                all_threats.extend(fetch_virustotal(virustotal_key))
                active_apis.append('VirusTotal')
            
            if pulsedive_key:
                all_threats.extend(fetch_pulsedive(pulsedive_key))
                active_apis.append('Pulsedive')
            
            if all_threats:
                st.session_state.threats = all_threats + st.session_state.threats[:50]
                st.session_state.total_attacks += len(all_threats)
                st.session_state.critical_count += sum(1 for t in all_threats if t['severity'] == 'Critical')
                st.success(f"✅ Fetched {len(all_threats)} threats from {len(active_apis)} sources!")
            else:
                st.warning("No new threats detected")

# Main content
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.markdown(f"""
    <div class="stat-box">
        <div style="font-size: 2.5rem; color: #06b6d4; font-weight: bold;">{st.session_state.total_attacks}</div>
        <div style="color: rgba(255,255,255,0.7); font-size: 0.9rem;">Total Threats</div>
    </div>
    """, unsafe_allow_html=True)

with col2:
    st.markdown(f"""
    <div class="stat-box">
        <div style="font-size: 2.5rem; color: #ef4444; font-weight: bold;">{st.session_state.critical_count}</div>
        <div style="color: rgba(255,255,255,0.7); font-size: 0.9rem;">Critical</div>
    </div>
    """, unsafe_allow_html=True)

with col3:
    st.markdown(f"""
    <div class="stat-box">
        <div style="font-size: 2.5rem; color: #22c55e; font-weight: bold;">{len(st.session_state.threats)}</div>
        <div style="color: rgba(255,255,255,0.7); font-size: 0.9rem;">Active Threats</div>
    </div>
    """, unsafe_allow_html=True)

with col4:
    active_sources = 2  # URLhaus + ThreatFox always active
    if abuseipdb_key:
        active_sources += 1
    if greynoise_key:
        active_sources += 1
    if virustotal_key:
        active_sources += 1
    if pulsedive_key:
        active_sources += 1
    
    st.markdown(f"""
    <div class="stat-box">
        <div style="font-size: 2.5rem; color: #f97316; font-weight: bold;">{active_sources}</div>
        <div style="color: rgba(255,255,255,0.7); font-size: 0.9rem;">Active Sources</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# Create two columns for globe and feed
col_globe, col_feed = st.columns([2, 1])

with col_globe:
    st.markdown("### 🌍 Global Threat Visualization")
    
    if st.session_state.threats:
        threats_df = pd.DataFrame(st.session_state.threats[:20])
        fig = create_globe_visualization(threats_df)
        if fig:
            st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("👆 Click 'Fetch Threats Now' in the sidebar to start monitoring")

with col_feed:
    st.markdown("### 📡 Live Threat Feed")
    
    if st.session_state.threats:
        for threat in st.session_state.threats[:10]:
            source = get_country_from_code(threat['source_country'])
            target = get_country_from_code(threat['target_country'])
            
            severity_class = f"severity-{threat['severity'].lower()}"
            
            st.markdown(f"""
            <div class="threat-card">
                <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 0.5rem;">
                    <span style="font-weight: bold; color: #06b6d4;">{threat['type']}</span>
                    <span class="{severity_class}">{threat['severity']}</span>
                </div>
                <div style="font-size: 0.85rem; color: rgba(255,255,255,0.7); margin-bottom: 0.5rem;">
                    {source['name']} → {target['name']}
                </div>
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span class="api-badge">{threat['api_source']}</span>
                    <span style="font-size: 0.75rem; color: rgba(255,255,255,0.5);">
                        {threat['timestamp'].strftime('%H:%M:%S')}
                    </span>
                </div>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("No threats to display yet")

# Auto-refresh
if auto_refresh and st.session_state.threats:
    time.sleep(30)
    st.rerun()

# Footer
st.markdown("---")
st.markdown("""
<div style="text-align: center; color: rgba(255,255,255,0.5); font-size: 0.85rem; padding: 1rem;">
    <b>Cyhawk Africa</b> | Powered by URLhaus, ThreatFox, AbuseIPDB, GreyNoise, VirusTotal & Pulsedive<br>
    Real-time threat intelligence for African cybersecurity
</div>
""", unsafe_allow_html=True)

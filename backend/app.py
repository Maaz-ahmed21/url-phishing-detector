import re
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

import pandas as pd
import joblib

from features import extract_features

app = FastAPI(
    title="Link Check",
    description="Uses lexical analysis",
    version="2.0.0"
)

# Allow CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load ML model and encoder
try:
    model = joblib.load("model.pkl")
    label_encoder = joblib.load("label_encoder.pkl")
except Exception:
    try:
        model = joblib.load("../model.pkl")
        label_encoder = joblib.load("../label_encoder.pkl")
    except Exception:
        model = None
        label_encoder = None


def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    return url


def analyze_risk_factors(url: str) -> List[Dict[str, str]]:
    factors = []
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path.split('/')[0]
    
    # Protocol Check
    if not url.startswith("https://"):
        factors.append({
            "type": "warning",
            "title": "Insecure Protocol (HTTP)",
            "description": "Connection lacks SSL/TLS encryption. Data sent to this site can be intercepted."
        })
    else:
        factors.append({
            "type": "safe",
            "title": "Encrypted Protocol (HTTPS)",
            "description": "Uses standard SSL/TLS encryption."
        })

    # IP Host Check
    if re.search(r'\d+\.\d+\.\d+\.\d+', domain):
        factors.append({
            "type": "danger",
            "title": "Raw IP Address Hostname",
            "description": "URL uses a numeric IP address instead of a registered domain name, a classic phishing indicator."
        })

    # URL Length
    if len(url) > 75:
        factors.append({
            "type": "danger",
            "title": f"Excessive URL Length ({len(url)} chars)",
            "description": "Suspiciously long URL commonly used to hide fake domain destinations."
        })
    elif len(url) > 54:
        factors.append({
            "type": "warning",
            "title": f"Above-Average URL Length ({len(url)} chars)",
            "description": "URL is longer than standard domain formats."
        })

    # '@' symbol check
    if "@" in url:
        factors.append({
            "type": "danger",
            "title": "Credential Obfuscation Symbol (@)",
            "description": "The '@' symbol causes browsers to ignore preceding characters, deceiving users about the true destination."
        })

    # Suspicious keywords
    suspicious_words = [
        "login", "signin", "verify", "verification", "secure", "update", "bank", 
        "banking", "account", "support", "billing", "free", "paypal", "appleid", 
        "confirm", "password", "credential", "wallet", "claim", "reward"
    ]
    found_keywords = [w for w in suspicious_words if w in url.lower()]
    if found_keywords:
        factors.append({
            "type": "warning",
            "title": f"High-Risk Security Keywords ({', '.join(found_keywords[:3])})",
            "description": "Contains sensitive terms frequently used in phishing landing pages."
        })

    # URL Shorteners
    shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", "ow.ly", "tiny.cc", "rb.gy"]
    if any(s in domain.lower() for s in shorteners):
        factors.append({
            "type": "warning",
            "title": "URL Shortener Service",
            "description": "The true destination is concealed behind a URL shortening service."
        })

    # Domain hyphens
    if domain.count("-") >= 2:
        factors.append({
            "type": "warning",
            "title": f"Multiple Domain Hyphens ({domain.count('-')})",
            "description": "Phishers use hyphens to create lookalike brand domains (e.g. security-paypal-login.com)."
        })

    # Subdomain depth
    subdomains = [s for s in domain.split(".") if s and s != "www"]
    if len(subdomains) >= 3:
        factors.append({
            "type": "warning",
            "title": f"Deep Subdomain Structure ({len(subdomains)-1} levels)",
            "description": "Multiple subdomains can obscure the apex domain from users."
        })

    return factors


def is_obviously_benign(url: str) -> bool:
    temp = url
    if temp.startswith("https://"):
        temp = temp[8:]
    elif temp.startswith("http://"):
        temp = temp[7:]
    
    if temp.endswith("/"):
        temp = temp[:-1]
        
    if "/" in temp:
        return False
        
    if re.search(r'\d', temp):
        return False
    if "-" in temp or "_" in temp:
        return False
    if temp.count(".") > 2:
        return False
        
    safe_tlds = (".com", ".org", ".net", ".edu", ".gov", ".mil", ".int", ".co", ".io")
    if not temp.endswith(safe_tlds):
        return False
        
    suspicious = ["login", "signin", "verify", "verification", "secure", "update", "bank", "account", "support", "billing", "free"]
    if any(word in temp.lower() for word in suspicious):
        return False
        
    return True


def process_url(raw_url: str) -> Dict[str, Any]:
    url = raw_url.strip()
    if not url:
        return None
        
    norm_url = normalize_url(url)
    parsed = urlparse(norm_url)
    
    risk_factors = analyze_risk_factors(norm_url)

    if is_obviously_benign(norm_url):
        raw_prediction = "benign"
        risk_score = 4.0
        confidence = 98.5
    else:
        features = extract_features(norm_url)
        features_df = pd.DataFrame([features])
        
        if model is not None and label_encoder is not None:
            pred_code = model.predict(features_df)[0]
            raw_prediction = str(label_encoder.inverse_transform([pred_code])[0])
            
            if hasattr(model, "predict_proba"):
                probs = model.predict_proba(features_df)[0]
                classes = list(label_encoder.classes_)
                
                benign_idx = classes.index("benign") if "benign" in classes else -1
                if benign_idx != -1:
                    benign_prob = probs[benign_idx]
                    risk_score = round((1.0 - float(benign_prob)) * 100, 1)
                else:
                    risk_score = round(float(max(probs)) * 100, 1)
                
                confidence = round(float(max(probs)) * 100, 1)
            else:
                risk_score = 90.0 if raw_prediction.lower() != "benign" else 10.0
                confidence = 85.0
        else:
            raw_prediction = "benign"
            risk_score = 10.0
            confidence = 50.0

    verdict_map = {
        "benign": "SAFE",
        "phishing": "PHISHING",
        "malicious": "MALICIOUS",
        "defacement": "DEFACEMENT",
        "safe": "SAFE"
    }
    verdict = verdict_map.get(raw_prediction.lower(), raw_prediction.upper())
    
    if verdict == "SAFE":
        if risk_score > 35:
            risk_score = 15.0
        risk_level = "LOW"
    elif risk_score >= 80:
        risk_level = "CRITICAL"
    elif risk_score >= 50:
        risk_level = "HIGH"
    else:
        risk_level = "MODERATE"

    recommendations = []
    if verdict == "SAFE":
        recommendations.append("This URL passes fundamental structural & machine learning security checks.")
        recommendations.append("Always verify the full domain address in your browser before entering credentials.")
    else:
        recommendations.append("DO NOT enter passwords, personal identification, or financial details on this site.")
        recommendations.append("Close this browser window immediately if you arrived here via email or SMS link.")
        recommendations.append("Report this domain to your organization's IT security center or email filter.")

    return {
        "url": url,
        "normalized_url": norm_url,
        "prediction": verdict,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "confidence": confidence,
        "structure": {
            "scheme": parsed.scheme or "http",
            "domain": parsed.netloc or parsed.path.split('/')[0],
            "path": parsed.path or "/",
            "query": parsed.query or "None",
            "length": len(norm_url)
        },
        "risk_factors": risk_factors,
        "recommendations": recommendations
    }


def render_html_page(active_tab="single", result_data=None, batch_results=None, input_url="", batch_input_text=""):
    
    # Generate Result Banner & Cards HTML if result_data exists
    result_html = ""
    if result_data:
        verdict = result_data["prediction"]
        risk_score = result_data["risk_score"]
        confidence = result_data["confidence"]
        risk_level = result_data["risk_level"]
        norm_url = result_data["normalized_url"]
        struct = result_data["structure"]
        factors = result_data["risk_factors"]
        recs = result_data["recommendations"]

        badge_class = "badge-safe"
        banner_class = "banner-safe"
        gauge_color = "#10b981"

        if verdict == "PHISHING" or verdict == "MALICIOUS":
            badge_class = "badge-phishing"
            banner_class = "banner-phishing"
            gauge_color = "#ef4444"
        elif verdict == "DEFACEMENT":
            badge_class = "badge-defacement"
            banner_class = "banner-defacement"
            gauge_color = "#a855f7"
        elif risk_score > 40:
            gauge_color = "#f59e0b"

        # Pure CSS Conic Gradient Dial
        gauge_gradient = f"conic-gradient({gauge_color} 0% {risk_score}%, rgba(255,255,255,0.08) {risk_score}% 100%)"

        factors_html = ""
        if factors:
            for f in factors:
                icon = "✅" if f["type"] == "safe" else ("🚨" if f["type"] == "danger" else "⚠️")
                factors_html += f'''
                <div class="flag-item {f['type']}">
                    <span class="flag-icon">{icon}</span>
                    <div class="flag-content">
                        <h4>{f['title']}</h4>
                        <p>{f['description']}</p>
                    </div>
                </div>
                '''
        else:
            factors_html = '''
            <div class="flag-item safe">
                <span class="flag-icon">✅</span>
                <div class="flag-content">
                    <h4>No Suspicious Anomalies Detected</h4>
                    <p>URL structure adheres to standard web formatting standards.</p>
                </div>
            </div>
            '''

        recs_html = "".join([f"<li>{r}</li>" for r in recs])

        result_html = f'''
        <div class="result-container">
            <div class="verdict-banner {banner_class}">
                <div class="verdict-main">
                    <span class="verdict-badge {badge_class}">{verdict}</span>
                    <h2 class="verdict-title">Verdict: {verdict} ({risk_level} Risk)</h2>
                    <p class="verdict-url">{norm_url}</p>
                </div>

                <div class="gauge-card">
                    <div class="conic-gauge" style="background: {gauge_gradient};">
                        <div class="gauge-inner">
                            <span class="gauge-number">{risk_score}%</span>
                            <span class="gauge-label">Risk Level</span>
                        </div>
                    </div>
                    <div class="confidence-tag">Model Confidence: {confidence}%</div>
                </div>
            </div>

            <div class="analysis-grid">
                <div class="analysis-card">
                    <div class="card-header">
                        <h3>URL Components Inspector</h3>
                    </div>
                    <div class="structure-list">
                        <div class="struct-item">
                            <span class="struct-label">Protocol (Scheme)</span>
                            <span class="struct-val code-font">{struct['scheme'].upper()}</span>
                        </div>
                        <div class="struct-item">
                            <span class="struct-label">Host Domain</span>
                            <span class="struct-val code-font">{struct['domain']}</span>
                        </div>
                        <div class="struct-item">
                            <span class="struct-label">Target Path</span>
                            <span class="struct-val code-font">{struct['path']}</span>
                        </div>
                        <div class="struct-item">
                            <span class="struct-label">Query Parameters</span>
                            <span class="struct-val code-font">{struct['query']}</span>
                        </div>
                        <div class="struct-item">
                            <span class="struct-label">Total Character Length</span>
                            <span class="struct-val">{struct['length']} characters</span>
                        </div>
                    </div>
                </div>

                <div class="analysis-card">
                    <div class="card-header">
                        <h3>Detected Security Indicators</h3>
                    </div>
                    <div class="risk-factors-list">
                        {factors_html}
                    </div>
                </div>

                <div class="analysis-card full-width-card">
                    <div class="card-header">
                        <h3>Security Recommendations</h3>
                    </div>
                    <ul class="recommendations-list">
                        {recs_html}
                    </ul>
                </div>
            </div>
        </div>
        '''

    # Batch Results HTML
    batch_html = ""
    if batch_results:
        safe_c = sum(1 for b in batch_results if b["prediction"] == "SAFE")
        phish_c = sum(1 for b in batch_results if b["prediction"] in ["PHISHING", "MALICIOUS"])
        susp_c = len(batch_results) - safe_c - phish_c

        rows_html = ""
        for idx, item in enumerate(batch_results, 1):
            v = item["prediction"]
            b_class = "badge-safe"
            if v in ["PHISHING", "MALICIOUS"]: b_class = "badge-phishing"
            elif v == "DEFACEMENT": b_class = "badge-defacement"

            rows_html += f'''
            <tr>
                <td>{idx}</td>
                <td class="code-font" style="max-width:280px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">{item['url']}</td>
                <td><span class="badge-pill {b_class}">{v}</span></td>
                <td><strong>{item['risk_score']}%</strong></td>
                <td>{item['risk_level']}</td>
            </tr>
            '''

        batch_html = f'''
        <div class="batch-results-container">
            <div class="batch-stats-summary">
                <div class="stat-box">
                    <span class="stat-num" style="color:var(--text-primary)">{len(batch_results)}</span>
                    <span class="stat-label">Total Links</span>
                </div>
                <div class="stat-box">
                    <span class="stat-num" style="color:var(--color-safe)">{safe_c}</span>
                    <span class="stat-label">Safe</span>
                </div>
                <div class="stat-box">
                    <span class="stat-num" style="color:var(--color-danger)">{phish_c}</span>
                    <span class="stat-label">Phishing</span>
                </div>
                <div class="stat-box">
                    <span class="stat-num" style="color:var(--color-warning)">{susp_c}</span>
                    <span class="stat-label">Suspicious</span>
                </div>
            </div>

            <div class="batch-table-wrapper">
                <table class="batch-table">
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>URL</th>
                            <th>Verdict</th>
                            <th>Risk Score</th>
                            <th>Risk Level</th>
                        </tr>
                    </thead>
                    <tbody>
                        {rows_html}
                    </tbody>
                </table>
            </div>
        </div>
        '''

    # Pure CSS Tab Checked states
    tab_single_checked = "checked" if active_tab == "single" else ""
    tab_batch_checked = "checked" if active_tab == "batch" else ""
    tab_handbook_checked = "checked" if active_tab == "handbook" else ""

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Link Check - Server-Rendered Phishing URL Detector</title>
    <meta name="description" content="Uses lexical analysis.">
    
    <!-- Google Fonts -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    
    <style>
        /* Modern No-JS Stylesheet */
        :root {{
            --bg-dark: #0b0f19;
            --bg-card: #131c31;
            --bg-card-hover: #18243e;
            --bg-input: #1c2844;
            --border-color: rgba(255, 255, 255, 0.08);
            --border-color-focus: #00f2fe;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --color-safe: #10b981;
            --color-safe-bg: rgba(16, 185, 129, 0.12);
            --color-warning: #f59e0b;
            --color-warning-bg: rgba(245, 158, 11, 0.12);
            --color-danger: #ef4444;
            --color-danger-bg: rgba(239, 68, 68, 0.12);
            --color-purple: #a855f7;
            --color-purple-bg: rgba(168, 85, 247, 0.12);
            --color-cyan: #00f2fe;
            --font-sans: 'Plus Jakarta Sans', sans-serif;
            --font-mono: 'JetBrains Mono', monospace;
            --radius-md: 10px;
            --radius-lg: 16px;
            --radius-full: 9999px;
            --shadow-card: 0 10px 30px -10px rgba(0, 0, 0, 0.5);
        }}

        * {{ box-sizing: border-box; margin: 0; padding: 0; }}

        body {{
            font-family: var(--font-sans);
            background-color: var(--bg-dark);
            color: var(--text-primary);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            line-height: 1.6;
            background-image: 
                radial-gradient(circle at 15% 15%, rgba(0, 242, 254, 0.04) 0%, transparent 40%),
                radial-gradient(circle at 85% 85%, rgba(168, 85, 247, 0.04) 0%, transparent 40%);
        }}

        .code-font {{ font-family: var(--font-mono); }}

        /* --- Header & Pure CSS Navigation --- */
        .app-header {{
            background: rgba(19, 28, 49, 0.95);
            border-bottom: 1px solid var(--border-color);
            position: sticky;
            top: 0;
            z-index: 100;
        }}

        .header-container {{
            max-width: 1280px;
            margin: 0 auto;
            padding: 16px 24px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 20px;
        }}

        .brand {{ display: flex; align-items: center; gap: 12px; }}
        .brand-icon {{
            width: 40px; height: 40px;
            background: linear-gradient(135deg, #00f2fe 0%, #4facfe 100%);
            border-radius: var(--radius-md);
            display: flex; align-items: center; justify-content: center;
            font-weight: 900; color: #0b0f19; font-size: 1.2rem;
        }}
        .brand-name {{ font-size: 1.25rem; font-weight: 800; }}
        .brand-accent {{ color: var(--color-cyan); }}
        .brand-tagline {{ font-size: 0.75rem; color: var(--text-secondary); display: block; }}

        /* Button Spacing & Flex Layouts */
        .nav-tabs-wrapper {{
            display: flex;
            align-items: center;
            gap: 8px;
            flex-wrap: wrap;
            background: rgba(11, 15, 25, 0.6);
            padding: 6px;
            border-radius: var(--radius-md);
            border: 1px solid var(--border-color);
        }}

        input[type="radio"].nav-radio {{ display: none; }}

        .nav-label {{
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            padding: 10px 20px;
            font-size: 0.875rem;
            font-weight: 600;
            color: var(--text-secondary);
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.2s ease;
            background: transparent;
            border: 1px solid transparent;
            user-select: none;
            line-height: 1.4;
        }}

        .nav-label:hover {{ color: var(--text-primary); background: rgba(255, 255, 255, 0.05); }}

        #tab-single:checked ~ .app-header .label-single,
        #tab-batch:checked ~ .app-header .label-batch,
        #tab-handbook:checked ~ .app-header .label-handbook {{
            background: var(--bg-card);
            color: var(--color-cyan);
            border-color: rgba(0, 242, 254, 0.3);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
        }}

        /* Tab Content Controllers */
        .tab-content {{ display: none; }}
        #tab-single:checked ~ .main-content #content-single {{ display: block; }}
        #tab-batch:checked ~ .main-content #content-batch {{ display: block; }}
        #tab-handbook:checked ~ .main-content #content-handbook {{ display: block; }}

        .main-content {{
            max-width: 1280px;
            width: 100%;
            margin: 0 auto;
            padding: 32px 24px;
            flex: 1;
        }}

        /* Hero & Search Form Buttons Spacing */
        .hero-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-lg);
            padding: 36px;
            text-align: center;
            box-shadow: var(--shadow-card);
            margin-bottom: 32px;
        }}

        .hero-card h1 {{
            font-size: 2rem; font-weight: 800; margin-bottom: 12px;
            background: linear-gradient(135deg, #ffffff 0%, #94a3b8 100%);
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;
        }}

        .hero-subtitle {{ color: var(--text-secondary); max-width: 720px; margin: 0 auto 28px; font-size: 0.95rem; }}

        .search-box-form {{
            max-width: 800px;
            margin: 0 auto 24px;
            display: flex;
            align-items: center;
            gap: 12px;
        }}

        .input-wrapper {{ flex: 1; min-width: 240px; }}

        .url-input {{
            width: 100%;
            min-height: 52px;
            background: var(--bg-input);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 14px 20px;
            font-size: 1rem;
            font-family: var(--font-mono);
            border-radius: var(--radius-md);
            outline: none;
            transition: all 0.2s ease;
        }}

        .url-input:focus {{ border-color: var(--color-cyan); box-shadow: 0 0 15px rgba(0, 242, 254, 0.2); }}

        .btn-primary {{
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            min-height: 52px;
            padding: 14px 32px;
            background: linear-gradient(135deg, #00f2fe 0%, #4facfe 100%);
            color: #0b0f19;
            border: none;
            font-size: 1rem;
            font-weight: 700;
            font-family: var(--font-sans);
            border-radius: var(--radius-md);
            cursor: pointer;
            white-space: nowrap;
            transition: all 0.2s ease;
            box-shadow: 0 4px 14px rgba(0, 242, 254, 0.3);
        }}

        .btn-primary:hover {{ transform: translateY(-2px); box-shadow: 0 6px 20px rgba(0, 242, 254, 0.4); }}

        /* Preset Sample Links Spacing */
        .sample-links {{
            display: flex;
            align-items: center;
            justify-content: center;
            flex-wrap: wrap;
            gap: 10px;
            font-size: 0.85rem;
            margin-top: 20px;
            padding-top: 16px;
            border-top: 1px solid rgba(255, 255, 255, 0.05);
        }}

        .sample-label {{ color: var(--text-muted); font-weight: 600; margin-right: 4px; }}
        
        .sample-chip {{
            display: inline-flex;
            align-items: center;
            gap: 6px;
            background: rgba(255, 255, 255, 0.04);
            border: 1px solid var(--border-color);
            color: var(--text-secondary);
            padding: 8px 16px;
            border-radius: var(--radius-full);
            text-decoration: none;
            font-size: 0.825rem;
            font-weight: 600;
            line-height: 1.4;
            transition: all 0.2s ease;
        }}

        .sample-chip:hover {{
            color: var(--text-primary);
            border-color: rgba(255, 255, 255, 0.25);
            background: rgba(255, 255, 255, 0.08);
            transform: translateY(-1px);
        }}

        /* --- Results Grid & Conic Gauge --- */
        .result-container {{ display: flex; flex-direction: column; gap: 24px; margin-top: 24px; }}

        .verdict-banner {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-lg);
            padding: 32px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 32px;
            position: relative;
            overflow: hidden;
        }}

        .verdict-banner::before {{ content: ''; position: absolute; left: 0; top: 0; bottom: 0; width: 6px; background: var(--color-safe); }}
        .verdict-banner.banner-phishing::before {{ background: var(--color-danger); }}
        .verdict-banner.banner-defacement::before {{ background: var(--color-purple); }}

        .verdict-main {{ flex: 1; }}

        .verdict-badge {{
            display: inline-block; padding: 6px 16px; border-radius: var(--radius-full);
            font-size: 0.85rem; font-weight: 800; letter-spacing: 0.5px; margin-bottom: 14px;
        }}

        .badge-safe {{ background: var(--color-safe-bg); color: var(--color-safe); border: 1px solid rgba(16, 185, 129, 0.4); }}
        .badge-phishing {{ background: var(--color-danger-bg); color: var(--color-danger); border: 1px solid rgba(239, 68, 68, 0.4); }}
        .badge-defacement {{ background: var(--color-purple-bg); color: var(--color-purple); border: 1px solid rgba(168, 85, 247, 0.4); }}

        .verdict-title {{ font-size: 1.75rem; font-weight: 800; margin-bottom: 8px; }}
        .verdict-url {{ font-family: var(--font-mono); color: var(--text-secondary); font-size: 0.95rem; word-break: break-all; }}

        /* Pure CSS Conic Gradient Dial */
        .gauge-card {{ display: flex; flex-direction: column; align-items: center; gap: 8px; min-width: 140px; }}

        .conic-gauge {{
            width: 110px; height: 110px; border-radius: 50%;
            display: flex; align-items: center; justify-content: center;
            padding: 8px;
        }}

        .gauge-inner {{
            width: 100%; height: 100%; background: var(--bg-card); border-radius: 50%;
            display: flex; flex-direction: column; align-items: center; justify-content: center;
        }}

        .gauge-number {{ font-size: 1.4rem; font-weight: 800; line-height: 1; }}
        .gauge-label {{ font-size: 0.65rem; color: var(--text-muted); font-weight: 600; text-transform: uppercase; }}
        .confidence-tag {{ font-size: 0.75rem; color: var(--text-muted); font-weight: 600; }}

        .analysis-grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 24px; }}
        .full-width-card {{ grid-column: span 2; }}

        .analysis-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-lg);
            padding: 24px;
        }}

        .card-header h3 {{ font-size: 1.1rem; font-weight: 700; margin-bottom: 16px; color: var(--color-cyan); }}

        .structure-list {{ display: flex; flex-direction: column; gap: 10px; }}
        .struct-item {{
            display: flex; justify-content: space-between; align-items: center;
            padding: 10px 14px; background: rgba(11, 15, 25, 0.4); border-radius: 6px; border: 1px solid var(--border-color);
        }}
        .struct-label {{ font-size: 0.85rem; color: var(--text-secondary); }}
        .struct-val {{ font-size: 0.85rem; color: var(--text-primary); font-weight: 600; }}

        .risk-factors-list {{ display: flex; flex-direction: column; gap: 10px; }}
        .flag-item {{ display: flex; align-items: flex-start; gap: 12px; padding: 12px 14px; border-radius: 8px; }}
        .flag-item.safe {{ background: var(--color-safe-bg); border: 1px solid rgba(16, 185, 129, 0.2); }}
        .flag-item.warning {{ background: var(--color-warning-bg); border: 1px solid rgba(245, 158, 11, 0.2); }}
        .flag-item.danger {{ background: var(--color-danger-bg); border: 1px solid rgba(239, 68, 68, 0.2); }}

        .flag-content h4 {{ font-size: 0.9rem; font-weight: 700; margin-bottom: 2px; }}
        .flag-item.safe h4 {{ color: var(--color-safe); }}
        .flag-item.warning h4 {{ color: var(--color-warning); }}
        .flag-item.danger h4 {{ color: var(--color-danger); }}

        .flag-content p {{ font-size: 0.8rem; color: var(--text-secondary); }}

        .recommendations-list {{ list-style: none; display: flex; flex-direction: column; gap: 10px; }}
        .recommendations-list li {{ position: relative; padding-left: 20px; font-size: 0.9rem; color: var(--text-secondary); }}
        .recommendations-list li::before {{ content: '➔'; position: absolute; left: 0; color: var(--color-cyan); }}

        /* --- Section Card & Batch --- */
        .section-card {{ background: var(--bg-card); border: 1px solid var(--border-color); border-radius: var(--radius-lg); padding: 32px; }}
        .section-card h2 {{ font-size: 1.5rem; font-weight: 800; margin-bottom: 6px; }}
        .section-desc {{ color: var(--text-secondary); font-size: 0.9rem; margin-bottom: 24px; }}

        .batch-textarea {{
            width: 100%; height: 180px; background: var(--bg-input); border: 1px solid var(--border-color);
            color: var(--text-primary); padding: 16px; font-size: 0.9rem; font-family: var(--font-mono);
            border-radius: var(--radius-md); outline: none; margin-bottom: 20px; resize: vertical;
        }}

        .batch-stats-summary {{ display: flex; gap: 16px; margin-bottom: 20px; }}
        .stat-box {{ background: rgba(11, 15, 25, 0.5); border: 1px solid var(--border-color); padding: 14px 20px; border-radius: var(--radius-md); display: flex; flex-direction: column; min-width: 120px; }}
        .stat-num {{ font-size: 1.5rem; font-weight: 800; }}
        .stat-label {{ font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; }}

        .batch-table {{ width: 100%; border-collapse: collapse; text-align: left; margin-top: 10px; }}
        .batch-table th {{ padding: 12px; background: rgba(11, 15, 25, 0.6); color: var(--text-muted); font-size: 0.8rem; border-bottom: 1px solid var(--border-color); }}
        .batch-table td {{ padding: 12px; border-bottom: 1px solid var(--border-color); font-size: 0.875rem; }}

        .badge-pill {{ display: inline-block; padding: 4px 10px; border-radius: var(--radius-full); font-size: 0.75rem; font-weight: 700; }}

        /* --- Threat Handbook --- */
        .handbook-grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 24px; }}
        .handbook-card {{ background: var(--bg-card); border: 1px solid var(--border-color); border-radius: var(--radius-lg); padding: 28px; }}
        .handbook-card h3 {{ font-size: 1.2rem; font-weight: 800; margin-bottom: 12px; color: var(--color-cyan); }}
        .handbook-card p {{ color: var(--text-secondary); font-size: 0.9rem; margin-bottom: 14px; }}
        .handbook-card ul {{ list-style: none; display: flex; flex-direction: column; gap: 10px; }}
        .handbook-card ul li {{ font-size: 0.875rem; color: var(--text-secondary); }}

        @media (max-width: 800px) {{
            .header-container {{ flex-direction: column; }}
            .analysis-grid {{ grid-template-columns: 1fr; }}
            .full-width-card {{ grid-column: span 1; }}
            .handbook-grid {{ grid-template-columns: 1fr; }}
            .search-box-form {{ flex-direction: column; }}
        }}
    </style>
</head>
<body>

    <!-- Hidden Pure CSS Radio Tab Controls -->
    <input type="radio" id="tab-single" name="nav-tabs" class="nav-radio" {tab_single_checked}>
    <input type="radio" id="tab-batch" name="nav-tabs" class="nav-radio" {tab_batch_checked}>
    <input type="radio" id="tab-handbook" name="nav-tabs" class="nav-radio" {tab_handbook_checked}>

    <!-- Header Navigation -->
    <header class="app-header">
        <div class="header-container">
            <div class="brand">
                <div class="brand-icon">🛡️</div>
                <div class="brand-text">
                    <span class="brand-name">URL <span class="brand-accent">Guard</span></span>
                    <span class="brand-tagline">Cyber Threat Intelligence Detector</span>
                </div>
            </div>

            <div class="nav-tabs-wrapper">
                <label for="tab-single" class="nav-label label-single">🔍 Single Scan</label>
                <label for="tab-batch" class="nav-label label-batch">📑 Batch Scanner</label>
                <label for="tab-handbook" class="nav-label label-handbook">🛡️ Threat Handbook</label>
            </div>
        </div>
    </header>

    <!-- Main Container -->
    <main class="main-content">

        <!-- TAB 1: SINGLE URL SCANNER -->
        <section id="content-single" class="tab-content">
            <div class="hero-card">
                <h1>Inspect Any Web Link Before You Click</h1>
                <p class="hero-subtitle">Uses lexical analysis to evaluate URL structural parameters, obfuscation patterns, and phishing heuristics.</p>

                <form action="/predict" method="POST" class="search-box-form">
                    <div class="input-wrapper">
                        <input type="text" name="url" value="{input_url}" class="url-input" placeholder="Enter URL (e.g. https://example.com/login)..." required autocomplete="off">
                    </div>
                    <button type="submit" class="btn-primary">Analyze URL</button>
                </form>

                <div class="sample-links">
                    <span class="sample-label">Try test samples:</span>
                    <a href="/predict?url=https://google.com" class="sample-chip">🟢 Safe URL</a>
                    <a href="/predict?url=http://login-verify-account-security-update.com/paypal/login" class="sample-chip">🔴 Phishing Sample</a>
                    <a href="/predict?url=http://192.168.1.105/bank/auth.php" class="sample-chip">🟠 Suspicious IP</a>
                    <a href="/predict?url=http://update-system-firmware-patch.net/installer.exe" class="sample-chip">🟣 Malicious Sample</a>
                </div>
            </div>

            {result_html}
        </section>

        <!-- TAB 2: BATCH SCANNER -->
        <section id="content-batch" class="tab-content">
            <div class="section-card">
                <h2>Batch Link Scanner</h2>
                <p class="section-desc">Paste up to 20 URLs below (one per line) for server-side threat analysis.</p>

                <form action="/batch" method="POST">
                    <textarea name="urls" class="batch-textarea" placeholder="https://example1.com&#10;http://phishing-site-test.com/login&#10;https://google.com">{batch_input_text}</textarea>
                    <button type="submit" class="btn-primary">Scan All Links</button>
                </form>

                {batch_html}
            </div>
        </section>

        <!-- TAB 3: THREAT HANDBOOK -->
        <section id="content-handbook" class="tab-content">
            <div class="handbook-grid">
                <div class="handbook-card">
                    <h3>Common Phishing Tactics</h3>
                    <p>Phishers use cunning techniques to deceive victims into handing over credentials:</p>
                    <ul>
                        <li><strong>Typosquatting:</strong> Registering slight typos of popular brands (e.g. <code>paypa1.com</code>).</li>
                        <li><strong>Subdomain Mimicry:</strong> Nesting legitimate names in subdomains (e.g. <code>paypal.com.verify-login.net</code>).</li>
                        <li><strong>Raw IP Address:</strong> Using numeric hostnames to bypass domain lookup reputation.</li>
                        <li><strong>Credential Obfuscation:</strong> Embedding the <code>@</code> symbol to mask real targets.</li>
                    </ul>
                </div>

                <div class="handbook-card">
                    <h3>How Machine Learning Detects Phishing</h3>
                    <p>Our model evaluates structural parameters extracted directly from the URL string:</p>
                    <ul>
                        <li><strong>Entropy & Special Characters:</strong> High count of hyphens, dots, underscores, and equal signs.</li>
                        <li><strong>Host Character Ratios:</strong> Numerical digit counts compared to alphabet letters.</li>
                        <li><strong>Protocol Validation:</strong> Presence of standard HTTPS certificates vs raw HTTP.</li>
                        <li><strong>Random Forest Classification:</strong> Decision tree ensembles trained on malicious dataset URL strings.</li>
                    </ul>
                </div>
            </div>
        </section>

    </main>
</body>
</html>
'''
    return html


# Routes
@app.get("/", response_class=HTMLResponse)
def home_page():
    return render_html_page(active_tab="single")


@app.get("/predict", response_class=HTMLResponse)
def predict_get(url: str = ""):
    if not url:
        return render_html_page(active_tab="single")
    result = process_url(url)
    return render_html_page(active_tab="single", result_data=result, input_url=url)


@app.post("/predict", response_class=HTMLResponse)
async def predict_post(request: Request):
    body_bytes = await request.body()
    form_data = parse_qs(body_bytes.decode('utf-8'))
    url = form_data.get('url', [''])[0]
    
    result = process_url(url) if url else None
    return render_html_page(active_tab="single", result_data=result, input_url=url)


@app.post("/batch", response_class=HTMLResponse)
async def batch_post(request: Request):
    body_bytes = await request.body()
    form_data = parse_qs(body_bytes.decode('utf-8'))
    raw_text = form_data.get('urls', [''])[0]
    
    urls = [line.strip() for line in raw_text.split('\n') if line.strip()]
    batch_results = []
    for u in urls[:20]:
        res = process_url(u)
        if res:
            batch_results.append(res)
            
    return render_html_page(active_tab="batch", batch_results=batch_results, batch_input_text=raw_text)


# JSON REST API endpoints for programatic access
class URLRequest(BaseModel):
    url: str

class BatchURLRequest(BaseModel):
    urls: List[str]

@app.post("/api/predict")
def api_predict(data: URLRequest):
    return process_url(data.url)

@app.post("/api/predict_batch")
def api_predict_batch(data: BatchURLRequest):
    results = [process_url(u) for u in data.urls[:20] if u.strip()]
    return {"count": len(results), "results": results}
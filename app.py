from flask import Flask, request, jsonify, render_template
import pickle
import feature  # The 'feature.py' from the original project
import visual_analysis  # The 'visual_analysis.py' we created
import traceback
from urllib.parse import urlparse
from config import BRAND_DATABASE
import Levenshtein 
import re
import concurrent.futures 
import time # Used for cache busting the screenshot image

# --- SUPPRESS WARNINGS ---
import warnings
warnings.filterwarnings("ignore", category=UserWarning, module='sklearn')

app = Flask(__name__)

# --- CACHE ---
RESULTS_CACHE = {}

# --- EXPLANATIONS ---
EXPLANATIONS = {
    'ip_address': {'title': 'URL Contains IP Address', 'details': 'Legitimate websites use domain names. IP addresses are suspicious.'},
    'ssl_cert': {'title': 'HTTPS (SSL) Certificate', 'details': 'Checks if the site uses a valid SSL certificate. HTTP is insecure.'},
    'long_url': {'title': 'URL Length', 'details': 'Unusually long URLs are often used to hide the real domain.'},
    'at_symbol': {'title': 'URL Contains "@" Symbol', 'details': 'The "@" symbol redirects the browser to a different domain.'},
    'domain_reg_len': {'title': 'Domain Registration Length', 'details': 'Short registration periods (e.g., 1 year) are suspicious.'},
    'domain_impersonation': {'title': 'Suspected Brand Impersonation', 'details': 'Detects typosquatting (e.g., paypa1.com) or keyword stuffing.'},
    'visual_analysis': {'title': 'Visual Identity Check', 'details': 'Compares the website layout against known brands to detect visual clones.'}
}

# --- HELPER FUNCTIONS ---
def has_ip_address(url):
    try:
        domain = urlparse(url).netloc
        if ':' in domain: domain = domain.split(':')[0]
        if re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", domain): return True
    except: pass
    return False

def check_impersonation(url):
    try:
        domain = urlparse(url).netloc.lower() 
        domain_parts = domain.split('.')
        if len(domain_parts) > 1: main_domain = ".".join(domain_parts[-2:]); domain_name_part = domain_parts[-2]
        else: main_domain = domain; domain_name_part = domain.split('.')[0]

        for keyword, data in BRAND_DATABASE.items():
            if main_domain == data['domain']: return {'is_impersonation': False} 
            if keyword in domain: return {'is_impersonation': True, 'brand': keyword, 'domain': domain}
            if 0 < Levenshtein.distance(domain_name_part, keyword) <= 2: return {'is_impersonation': True, 'brand': keyword, 'domain': domain}
    except: pass
    return {'is_impersonation': False}

# --- ANALYSIS ENGINE ---
def get_features_wrapper(url):
    return feature.FeatureExtraction(url).getFeaturesList()

def run_analysis(url):
    model = pickle.load(open('newmodel.pkl', 'rb'))
    risk_score = 0
    breakdown_data = [] 

    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_features = executor.submit(get_features_wrapper, url)
        future_visual = executor.submit(visual_analysis.get_visual_analysis, url)
        features_list = future_features.result()
        visual_report = future_visual.result()
    
    # 1. IP Check
    if features_list[0] == -1 or has_ip_address(url):
        breakdown_data.append({'id': 'ip_address', 'message': '❌ URL contains a suspicious IP address.', 'status': 'bad'}); risk_score += 15
    else: breakdown_data.append({'id': 'ip_address', 'message': '✔️ URL does not contain an IP address.', 'status': 'good'})

    # 2. SSL Check
    if not url.startswith('https://'):
        breakdown_data.append({'id': 'ssl_cert', 'message': '❌ Site does not use HTTPS (Not Secure).', 'status': 'bad'}); risk_score += 15 
    elif features_list[4] == -1:
        breakdown_data.append({'id': 'ssl_cert', 'message': '❌ Site uses an untrusted HTTPS certificate.', 'status': 'bad'}); risk_score += 15
    else: breakdown_data.append({'id': 'ssl_cert', 'message': '✔️ Site uses a trusted HTTPS certificate.', 'status': 'good'})
        
    # 3. URL Length
    if features_list[1] == -1: breakdown_data.append({'id': 'long_url', 'message': '❌ URL is unusually long.', 'status': 'bad'}); risk_score += 10
    else: breakdown_data.append({'id': 'long_url', 'message': '✔️ URL length is normal.', 'status': 'good'})

    # 4. At Symbol
    if features_list[3] == -1: breakdown_data.append({'id': 'at_symbol', 'message': '❌ URL contains a suspicious "@" symbol.', 'status': 'bad'}); risk_score += 40 

    # 5. Domain Reg Length
    if features_list[5] == -1: breakdown_data.append({'id': 'domain_reg_len', 'message': '❌ Domain is registered for a very short period.', 'status': 'bad'}); risk_score += 20
    else: breakdown_data.append({'id': 'domain_reg_len', 'message': '✔️ Domain is registered for a reputable length of time.', 'status': 'good'})
    
    # 6. Impersonation
    imp_check = check_impersonation(url)
    if imp_check['is_impersonation']:
        breakdown_data.append({'id': 'domain_impersonation', 'message': f"❌ CRITICAL: Domain impersonating '{imp_check['brand']}'.", 'status': 'bad'}); risk_score += 40 
    else: breakdown_data.append({'id': 'domain_impersonation', 'message': '✔️ No obvious brand impersonation detected.', 'status': 'good'})
    
    # 7. ML Prediction
    prediction = model.predict([features_list])
    prob = model.predict_proba([features_list])[0][0] 
    if prediction[0] == -1: risk_score += 20 
    risk_score += int(prob * 0.10)
    
    # 8. Visual Analysis
    v_status = 'good'
    if visual_report['risk_added'] > 0: v_status = 'bad'
    elif "⚠️" in visual_report['message']: v_status = 'warn'
    breakdown_data.append({'id': 'visual_analysis', 'message': visual_report['message'], 'status': v_status})
    risk_score += visual_report['risk_added']
    
    # Verdict Logic
    risk_score = min(risk_score, 100)
    if risk_score > 40: verdict = "Phishing"; verdict_class = "banner-phishing"
    else: verdict = "Safe"; verdict_class = "banner-safe"
        
    if imp_check['is_impersonation'] and verdict == "Safe": verdict = "Phishing"; verdict_class = "banner-phishing"
    if not url.startswith('https://') and verdict == "Safe": verdict = "Safe (Not Secure)"; verdict_class = "banner-safe" 

    # Generate a random string to force the browser to reload the screenshot image
    cache_buster = int(time.time())

    return {
        'url': url,
        'verdict': verdict,
        'verdict_class': verdict_class,
        'risk_score': int(risk_score), 
        'breakdown_data': breakdown_data,
        'cache_buster': cache_buster # NEW: Passed to template
    }

# --- ROUTES ---
@app.route('/')
def home(): return render_template('index.html')

@app.route('/usecases')
def usecases(): return render_template('usecases.html')

@app.route('/predict', methods=['POST'])
def predict():
    try:
        url = request.form['url']
        results = run_analysis(url)
        RESULTS_CACHE[url] = results
        return render_template('result.html', **results)
    except Exception as e:
        print(f"Predict Error: {e}"); traceback.print_exc()
        return f"Error: {e}", 500

@app.route('/report')
def report():
    try:
        url = request.args.get('url')
        if not url: return "Error: No URL.", 400
        results = RESULTS_CACHE.get(url) or run_analysis(url)
        return render_template('report.html', **results, explanations=EXPLANATIONS)
    except Exception as e: return f"Report Error: {e}", 500

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)
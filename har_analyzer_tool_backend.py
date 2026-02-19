"""
HAR Privacy Analyzer - Backend
Filename: har_analyzer_tool_backend.py
Flask application for analyzing HAR files for personal information and tracking
"""

from flask import Flask, request, jsonify, send_from_directory
import json
import re
from urllib.parse import urlparse, parse_qs, unquote
from collections import defaultdict
import os

app = Flask(__name__, static_folder='static')

# UUID/GUID pattern (with or without hyphens)
UUID_PATTERN = re.compile(r'\b[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}\b')

# Patterns to detect personal information (without Credit Card - handled separately)
# Removed Phone, ZIP Code, and IP Address patterns to reduce false positives
PII_PATTERNS = {
    'Email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
    'SSN': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
}

# Credit card pattern
CREDIT_CARD_PATTERN = re.compile(r'\b(\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4})\b')

# Known analytics/monitoring domains - for domain-based classification
ANALYTICS_DOMAINS = [
    'datadoghq.com', 'browser-intake-datadoghq.com',
    'google-analytics.com', 'googletagmanager.com', 'analytics.google.com',
    'mixpanel.com', 'api.mixpanel.com',
    'segment.com', 'api.segment.io', 'cdn.segment.com',
    'amplitude.com', 'api.amplitude.com', 'api2.amplitude.com',
    'newrelic.com', 'bam.nr-data.net', 'js-agent.newrelic.com',
    'hotjar.com', 'static.hotjar.com', 'api.hotjar.io',
    'optimizely.com', 'logx.optimizely.com',
    'fullstory.com', 'rs.fullstory.com',
    'logrocket.com', 'r.lr-ingest.io',
    'sentry.io', 'browser.sentry-cdn.com',
    'bugsnag.com', 'notify.bugsnag.com',
    'launchdarkly.com', 'events.launchdarkly.com',
]

def is_analytics_domain(domain):
    """Check if a domain is a known analytics/monitoring service"""
    domain_lower = domain.lower()
    for analytics_domain in ANALYTICS_DOMAINS:
        if analytics_domain in domain_lower:
            return True
    return False
MAJOR_THIRD_PARTY_PROVIDERS = {
    'Facebook': ['facebook.com', 'fbcdn.net', 'fb.com', 'facebook.net', 'fbsbx.com'],
    'Google': ['google.com', 'googleapis.com', 'google-analytics.com', 'googletagmanager.com', 'doubleclick.net', 'googlesyndication.com', 'gstatic.com'],
    'Google AdSense': ['googlesyndication.com', 'googleadservices.com', 'adservice.google.com'],
    'Stack Adapt': ['stackadapt.com', 'srv.stackadapt.com', 'srvtrck.com'],
    'Bing': ['bing.com', 'bingapis.com', 'bat.bing.com', 'clarity.ms'],
    'LinkedIn Ads': ['linkedin.com', 'licdn.com', 'ads.linkedin.com', 'px.ads.linkedin.com', 'bizographics.com'],
    'HubSpot': ['hubspot.com', 'hs-analytics.net', 'hsforms.com', 'hubspotusercontent-na1.net', 'hs-banner.com', 'hsadspixel.net'],
    'Twitter/X': ['twitter.com', 'twimg.com', 'x.com', 't.co'],
    'TikTok': ['tiktok.com', 'tiktokcdn.com', 'byteoversea.com'],
    'Amazon': ['amazon-adsystem.com', 'amazon.com', 'amazonpay.com'],
    'Microsoft': ['microsoft.com', 'live.com', 'msn.com', 'office.com'],
    'Adobe': ['adobe.com', 'omtrdc.net', 'demdex.net'],
    'Salesforce': ['salesforce.com', 'force.com', 'salesforceliveagent.com'],
    'Cloudflare': ['cloudflare.com', 'cloudflareinsights.com'],
    'New Relic': ['newrelic.com', 'nr-data.net'],
    'Hotjar': ['hotjar.com', 'hotjar.io'],
    'Segment': ['segment.com', 'segment.io'],
    'Mixpanel': ['mixpanel.com'],
    'Amplitude': ['amplitude.com'],
    'Criteo': ['criteo.com', 'criteo.net'],
    'Pinterest': ['pinterest.com', 'pinimg.com'],
    'Snapchat': ['snapchat.com', 'sc-static.net'],
    'Reddit': ['reddit.com', 'redd.it', 'redditstatic.com'],
    'Taboola': ['taboola.com', 'trc.taboola.com'],
    'Outbrain': ['outbrain.com', 'outbrainimg.com'],
}

# Common parameter names that might contain PII
# Separated into TRUE PII vs TRACKING/ANALYTICS
TRUE_PII_PARAM_NAMES = [
    'email', 'e-mail', 'mail', 'user_email', 'useremail',
    'name', 'firstname', 'lastname', 'fullname', 'first_name', 'last_name',
    'address', 'street', 'city', 'state', 'street_address',
    'ssn', 'social_security',
    'dob', 'dateofbirth', 'birthdate', 'date_of_birth',
    'password', 'passwd', 'pwd',
    'credit_card', 'creditcard', 'card_number', 'cardnumber',
]

# Analytics/Tracking parameters - lower priority
TRACKING_PARAM_NAMES = [
    'username', 'user_name', 'userid', 'user_id',
    'session', 'sessionid', 'session_id',
    'anonymous_id', 'anon_id',
    'visitor_id', 'visitorid',
    'client_id', 'clientid',
    'device_id', 'deviceid',
    'usr', 'user',  # Generic user identifiers
]

def extract_uuids_from_text(text):
    """Extract all UUIDs from text"""
    return UUID_PATTERN.findall(str(text))

def luhn_check(card_number):
    """
    Validate credit card number using Luhn algorithm (mod 10 check)
    Returns True if valid, False otherwise
    """
    # Remove spaces and hyphens
    card_number = card_number.replace(' ', '').replace('-', '')
    
    # Must be all digits and 13-19 characters (standard card lengths)
    if not card_number.isdigit() or len(card_number) < 13 or len(card_number) > 19:
        return False
    
    # Luhn algorithm
    def digits_of(n):
        return [int(d) for d in str(n)]
    
    digits = digits_of(card_number)
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    
    checksum = sum(odd_digits)
    for d in even_digits:
        checksum += sum(digits_of(d * 2))
    
    return checksum % 10 == 0

def is_likely_credit_card(number_str):
    """
    Check if a number is likely a real credit card
    Filters out common false positives
    """
    clean_number = number_str.replace(' ', '').replace('-', '')
    
    # Filter out obviously fake patterns
    # All same digit (1111-1111-1111-1111)
    if len(set(clean_number)) == 1:
        return False
    
    # Sequential digits (1234-5678-9012-3456)
    if clean_number in '01234567890123456789':
        return False
    
    # Common test cards
    test_cards = [
        '4111111111111111',  # Visa test
        '5555555555554444',  # Mastercard test
        '378282246310005',   # Amex test
        '6011111111111117',  # Discover test
        '3530111333300000',  # JCB test
    ]
    if clean_number in test_cards:
        return False
    
    # Must pass Luhn check
    return luhn_check(number_str)

def detect_pii_in_text(text):
    """Detect personal information patterns in text"""
    findings = []
    
    # Check standard PII patterns
    for pii_type, pattern in PII_PATTERNS.items():
        matches = pattern.findall(str(text))
        for match in matches:
            if isinstance(match, tuple):
                match = ''.join(match)
            findings.append({'type': pii_type, 'value': match})
    
    # Check credit cards separately with validation
    cc_matches = CREDIT_CARD_PATTERN.findall(str(text))
    for match in cc_matches:
        if is_likely_credit_card(match):
            findings.append({'type': 'Credit Card', 'value': match})
    
    return findings

def check_param_names(params):
    """Check if parameter names suggest personal information"""
    findings = []
    for key, value in params.items():
        key_lower = key.lower()
        value_str = str(value)[:2000]  # Increased from 500 to 2000 for large analytics batches
        
        # Check for TRUE PII first (higher priority)
        is_true_pii = False
        for pii_param in TRUE_PII_PARAM_NAMES:
            if pii_param in key_lower and value:
                # Additional validation: check if value looks like analytics/telemetry
                if is_analytics_payload(value_str):
                    # Skip - this is analytics data, not actual PII
                    continue
                
                findings.append({
                    'type': f'PII Parameter: {key}',
                    'value': str(value)[:100],  # Limit length
                    'category': 'true_pii'
                })
                is_true_pii = True
                break
        
        if not is_true_pii:
            # If not TRUE PII, check for tracking identifiers
            for tracking_param in TRACKING_PARAM_NAMES:
                if tracking_param in key_lower and value:
                    # Check if it's analytics telemetry (should be lower priority)
                    if is_analytics_payload(value_str):
                        findings.append({
                            'type': f'Analytics Telemetry: {key}',
                            'value': str(value)[:100],
                            'category': 'analytics'
                        })
                    else:
                        findings.append({
                            'type': f'Tracking Parameter: {key}',
                            'value': str(value)[:100],
                            'category': 'tracking'
                        })
                    break
    return findings

def is_analytics_payload(value_str):
    """
    Detect if a value is analytics/telemetry data rather than actual personal info
    Returns True if it looks like analytics data
    """
    # Convert to string and check for analytics indicators
    value_lower = value_str.lower()
    
    # Check for common analytics/telemetry patterns
    analytics_indicators = [
        '"kind":', '"seq":', '"when":', '"evts":',  # Event tracking structure
        '"args":', '"timestamp":', '"event_type":',
        'optimizely', 'mixpanel', 'segment', 'amplitude',
        'google-analytics', 'gtag', 'ga(',
        '"experiments":', '"variants":', '"test_id":',
        'telemetry', 'metrics', 'performance',
        '"long_task":', '"timing":', '"navigation":',
        'datadog', '"_dd":', '"rum":', '"apm":',
        '"viewport":', '"screen":', '"device":',
        '"browser":', '"platform":', '"os":',
        '"session":{', '"user":{', '"context":{',  # Structured analytics objects
        '"properties":{', '"traits":{',
    ]
    
    # Count how many indicators are present
    indicator_count = sum(1 for indicator in analytics_indicators if indicator in value_lower)
    
    # If multiple analytics indicators, it's likely analytics data
    if indicator_count >= 2:
        return True
    
    # Check for JSON structure with event/tracking fields
    try:
        # Try to parse as JSON
        import json
        data = json.loads(value_str)
        
        # Check if it has analytics-like structure
        if isinstance(data, dict):
            keys_lower = [k.lower() for k in data.keys()]
            analytics_keys = ['kind', 'seq', 'when', 'evts', 'events', 'type', 
                            'timestamp', 'properties', 'context', 'experiments',
                            'session', 'anonymous_id', 'user_id']
            
            # If it has multiple analytics-like keys, it's analytics
            analytics_key_count = sum(1 for k in analytics_keys if k in keys_lower)
            if analytics_key_count >= 2:
                return True
    except:
        pass
    
    return False

def identify_third_party_provider(domain):
    """Identify which major third party provider a domain belongs to"""
    # Check if domain contains any provider domain strings
    for provider, provider_domains in MAJOR_THIRD_PARTY_PROVIDERS.items():
        for provider_domain in provider_domains:
            # Use 'in' to check if provider_domain is contained in the full domain string
            if provider_domain in domain:
                return provider
    return 'Other'

def is_meta_tracking_request(url, domain, post_data_text=''):
    """
    Detect if a request is to Meta/Facebook/Instagram/WhatsApp tracking endpoints
    Returns dict with detection details or None
    
    Detects:
    - Facebook Pixel
    - Instagram tracking
    - WhatsApp Business tracking
    - Meta Conversions API
    - Meta Analytics
    """
    # Meta tracking endpoints across all Meta properties
    meta_tracking_endpoints = [
        # Facebook Pixel
        'facebook.com/tr',
        'facebook.com/tr/',
        'connect.facebook.net',
        'facebook.net/tr',
        
        # Instagram tracking
        'instagram.com/logging',
        'instagram.com/api/v1/web/activity',
        'instagram.com/graphql/query',
        'i.instagram.com/api',
        
        # WhatsApp Business API
        'whatsapp.com/v1/messages',
        'graph.facebook.com/v',  # Used for WhatsApp Business API
        
        # Meta Conversions API
        'graph.facebook.com',
        
        # Meta Analytics
        'analytics.facebook.com',
    ]
    
    # Check if URL matches Meta tracking endpoints
    url_lower = url.lower()
    is_tracking_endpoint = any(endpoint in url_lower for endpoint in meta_tracking_endpoints)
    
    # Check if it's a Meta domain
    meta_domains = ['facebook.com', 'facebook.net', 'fbcdn.net', 'instagram.com', 'whatsapp.com', 'fb.com']
    is_meta_domain = domain and any(meta_domain in domain.lower() for meta_domain in meta_domains)
    
    # Check for tracking-specific parameters in POST data
    has_tracking_params = False
    tracking_type = 'Unknown'
    
    if post_data_text:
        post_lower = post_data_text.lower()
        
        # Facebook Pixel indicators
        facebook_pixel_indicators = ['ev=', 'fbp=', 'fbc=', 'external_id=', 'fb_', '"event":', '"fbq"']
        if any(indicator in post_lower for indicator in facebook_pixel_indicators):
            has_tracking_params = True
            tracking_type = 'Facebook Pixel'
        
        # Instagram tracking indicators
        instagram_indicators = ['instagram', 'ig_', '"activity_type":', '"ig_user_id"']
        if any(indicator in post_lower for indicator in instagram_indicators) and 'instagram.com' in domain.lower():
            has_tracking_params = True
            tracking_type = 'Instagram Tracking'
        
        # WhatsApp indicators
        whatsapp_indicators = ['whatsapp', 'wa_', '"messaging_product":"whatsapp"']
        if any(indicator in post_lower for indicator in whatsapp_indicators):
            has_tracking_params = True
            tracking_type = 'WhatsApp Business Tracking'
        
        # Meta Conversions API indicators
        conversions_api_indicators = ['"data":[', '"event_name":', '"user_data":', '"custom_data":', 'conversions']
        if any(indicator in post_lower for indicator in conversions_api_indicators) and 'graph.facebook.com' in url_lower:
            has_tracking_params = True
            tracking_type = 'Meta Conversions API'
    
    # Determine if this is a tracking request
    if is_tracking_endpoint or (is_meta_domain and has_tracking_params):
        # If we couldn't determine specific type, default based on domain
        if tracking_type == 'Unknown':
            if 'facebook.com' in domain.lower():
                tracking_type = 'Facebook Pixel'
            elif 'instagram.com' in domain.lower():
                tracking_type = 'Instagram Tracking'
            elif 'whatsapp.com' in domain.lower():
                tracking_type = 'WhatsApp Tracking'
            else:
                tracking_type = 'Meta Tracking'
        
        return {
            'is_meta_tracking': True,
            'tracking_type': tracking_type,
            'url': url,
            'domain': domain,
            'detection_method': 'endpoint' if is_tracking_endpoint else 'parameters'
        }
    
    return None

def is_tiktok_tracking_request(url, domain, post_data_text=''):
    """
    Detect if a request is to TikTok/ByteDance tracking endpoints
    Returns dict with detection details or None
    
    Detects:
    - TikTok Pixel
    - TikTok Events API
    - TikTok Analytics
    - ByteDance tracking
    """
    # TikTok tracking endpoints
    tiktok_tracking_endpoints = [
        # TikTok Pixel
        'analytics.tiktok.com',
        'analytics-sg.tiktok.com',
        'analytics.tiktokv.com',
        
        # TikTok Events API
        'business-api.tiktok.com',
        'ads.tiktok.com/api',
        
        # TikTok tracking scripts
        'analytics-cdn.tiktokv.com',
        'analytics-cdn.tiktok.com',
        
        # Legacy tracking
        'log.tiktok.com',
        'mon.tiktokv.com',
        'mssdk-sg.tiktok.com',
    ]
    
    # Check if URL matches TikTok tracking endpoints
    url_lower = url.lower()
    is_tracking_endpoint = any(endpoint in url_lower for endpoint in tiktok_tracking_endpoints)
    
    # Check if it's a TikTok/ByteDance domain
    tiktok_domains = ['tiktok.com', 'tiktokv.com', 'bytedance.com', 'musical.ly']
    is_tiktok_domain = domain and any(tiktok_domain in domain.lower() for tiktok_domain in tiktok_domains)
    
    # Check for tracking-specific parameters in POST data
    has_tracking_params = False
    tracking_type = 'Unknown'
    
    if post_data_text:
        post_lower = post_data_text.lower()
        
        # TikTok Pixel indicators
        tiktok_pixel_indicators = [
            'ttclid',  # TikTok Click ID
            'ttp',     # TikTok tracking parameter
            '"event":', 
            '"event_id":',
            'pixelcode',
            '"pixel_code"',
            'tt_pixel',
            '"context":{"pixel"',
            '"properties":',
            '"page":{"url"',
        ]
        if any(indicator in post_lower for indicator in tiktok_pixel_indicators):
            has_tracking_params = True
            tracking_type = 'TikTok Pixel'
        
        # TikTok Events API indicators
        events_api_indicators = [
            '"event_source_id"',
            '"test_event_code"',
            '"data":[',
            'business-api.tiktok.com',
            '"user":{"external_id"',
        ]
        if any(indicator in post_lower for indicator in events_api_indicators):
            has_tracking_params = True
            tracking_type = 'TikTok Events API'
        
        # Advanced Matching indicators (captures data before consent)
        advanced_matching_indicators = [
            '"email":', 
            '"phone_number":',
            '"external_id":',
            '"auto_advanced_matching":true',
        ]
        if any(indicator in post_lower for indicator in advanced_matching_indicators) and 'tiktok' in url_lower:
            has_tracking_params = True
            if tracking_type == 'Unknown':
                tracking_type = 'TikTok Pixel (Advanced Matching)'
    
    # Determine if this is a tracking request
    if is_tracking_endpoint or (is_tiktok_domain and has_tracking_params):
        # Default to TikTok Pixel if type unknown
        if tracking_type == 'Unknown':
            tracking_type = 'TikTok Pixel'
        
        return {
            'is_tiktok_tracking': True,
            'tracking_type': tracking_type,
            'url': url,
            'domain': domain,
            'detection_method': 'endpoint' if is_tracking_endpoint else 'parameters'
        }
    
    return None

def is_linkedin_tracking_request(url, domain, post_data_text=''):
    """
    Detect if a request is to LinkedIn Insight Tag/tracking endpoints
    Returns dict with detection details or None
    
    Detects:
    - LinkedIn Insight Tag
    - LinkedIn Conversion Tracking
    - LinkedIn Ads tracking
    - LinkedIn Analytics
    """
    # LinkedIn tracking endpoints
    linkedin_tracking_endpoints = [
        # LinkedIn Insight Tag
        'px.ads.linkedin.com',
        'www.linkedin.com/px/',
        
        # LinkedIn Analytics
        'analytics.pointdrive.linkedin.com',
        
        # LinkedIn Ads
        'ads.linkedin.com/collect',
        'www.linkedin.com/li/track',
        
        # LinkedIn Conversion Tracking
        'snap.licdn.com',
    ]
    
    # Check if URL matches LinkedIn tracking endpoints
    url_lower = url.lower()
    is_tracking_endpoint = any(endpoint in url_lower for endpoint in linkedin_tracking_endpoints)
    
    # Check if it's a LinkedIn domain
    linkedin_domains = ['linkedin.com', 'licdn.com']
    is_linkedin_domain = domain and any(linkedin_domain in domain.lower() for linkedin_domain in linkedin_domains)
    
    # Check for tracking-specific parameters in POST data
    has_tracking_params = False
    tracking_type = 'Unknown'
    
    if post_data_text:
        post_lower = post_data_text.lower()
        
        # LinkedIn Insight Tag indicators
        insight_tag_indicators = [
            '"conversion_id"',
            '"user_id"',
            'li_fat_id',
            '"event_type"',
            '"event_name"',
            'linkedin',
            '"first_party_tracking"',
            '"page_url"',
            '"timestamp"',
        ]
        if any(indicator in post_lower for indicator in insight_tag_indicators):
            has_tracking_params = True
            tracking_type = 'LinkedIn Insight Tag'
        
        # LinkedIn Conversion indicators
        conversion_indicators = [
            '"conversion"',
            'conversionid',
            '"revenue"',
            '"currency"',
        ]
        if any(indicator in post_lower for indicator in conversion_indicators) and 'linkedin' in url_lower:
            has_tracking_params = True
            if tracking_type == 'Unknown':
                tracking_type = 'LinkedIn Conversion Tracking'
        
        # Enhanced Matching indicators (hashed email collection)
        enhanced_matching_indicators = [
            '"email"',
            '"hashed_email"',
            '"sha256_email"',
            '"first_name"',
            '"last_name"',
            '"company"',
            '"job_title"',
        ]
        if any(indicator in post_lower for indicator in enhanced_matching_indicators) and is_linkedin_domain:
            has_tracking_params = True
            if tracking_type == 'Unknown' or tracking_type == 'LinkedIn Insight Tag':
                tracking_type = 'LinkedIn Insight Tag (Enhanced Matching)'
    
    # Determine if this is a tracking request
    if is_tracking_endpoint or (is_linkedin_domain and has_tracking_params):
        # Default to LinkedIn Insight Tag if type unknown
        if tracking_type == 'Unknown':
            tracking_type = 'LinkedIn Insight Tag'
        
        return {
            'is_linkedin_tracking': True,
            'tracking_type': tracking_type,
            'url': url,
            'domain': domain,
            'detection_method': 'endpoint' if is_tracking_endpoint else 'parameters'
        }
    
    return None

def is_linkedin_tracking_request(url, domain, post_data_text=''):
    """
    Detect if a request is to LinkedIn Insight Tag tracking endpoints
    Returns dict with detection details or None
    
    Detects:
    - LinkedIn Insight Tag
    - LinkedIn conversion tracking
    - LinkedIn matched audiences
    """
    # LinkedIn tracking endpoints
    linkedin_tracking_endpoints = [
        # LinkedIn Insight Tag
        'px.ads.linkedin.com',
        'ads.linkedin.com/collect',
        
        # LinkedIn conversion tracking
        'linkedin.com/px/',
        'snap.licdn.com',
        
        # LinkedIn analytics
        'analytics.pointdrive.linkedin.com',
    ]
    
    # Check if URL matches LinkedIn tracking endpoints
    url_lower = url.lower()
    is_tracking_endpoint = any(endpoint in url_lower for endpoint in linkedin_tracking_endpoints)
    
    # Check if it's a LinkedIn domain
    linkedin_domains = ['linkedin.com', 'licdn.com']
    is_linkedin_domain = domain and any(linkedin_domain in domain.lower() for linkedin_domain in linkedin_domains)
    
    # Check for tracking-specific parameters in POST data
    has_tracking_params = False
    tracking_type = 'Unknown'
    
    if post_data_text:
        post_lower = post_data_text.lower()
        
        # LinkedIn Insight Tag indicators
        linkedin_pixel_indicators = [
            '"conversion"',
            '"conversionid"',
            'li_fat_id',
            'linkedin_insight',
            '"insight_tag"',
            '"partner_id"',
            '"member_id"',
            '"data":{"conversion"',
        ]
        if any(indicator in post_lower for indicator in linkedin_pixel_indicators):
            has_tracking_params = True
            tracking_type = 'LinkedIn Insight Tag'
        
        # LinkedIn conversion tracking indicators
        conversion_indicators = [
            '"conversionId"',
            '"event_id"',
            '"conversion_value"',
            '"currency_code"',
        ]
        if any(indicator in post_lower for indicator in conversion_indicators) and 'linkedin' in url_lower:
            has_tracking_params = True
            if tracking_type == 'Unknown':
                tracking_type = 'LinkedIn Conversion Tracking'
        
        # Enhanced matching indicators (email/phone hashing)
        enhanced_matching_indicators = [
            '"email":', 
            '"hashed_email"',
            '"sha256_email"',
        ]
        if any(indicator in post_lower for indicator in enhanced_matching_indicators) and 'linkedin' in url_lower:
            has_tracking_params = True
            if tracking_type == 'Unknown':
                tracking_type = 'LinkedIn Insight Tag (Enhanced Matching)'
    
    # Determine if this is a tracking request
    if is_tracking_endpoint or (is_linkedin_domain and has_tracking_params):
        # Default to LinkedIn Insight Tag if type unknown
        if tracking_type == 'Unknown':
            tracking_type = 'LinkedIn Insight Tag'
        
        return {
            'is_linkedin_tracking': True,
            'tracking_type': tracking_type,
            'url': url,
            'domain': domain,
            'detection_method': 'endpoint' if is_tracking_endpoint else 'parameters'
        }
    
    return None

def analyze_har_privacy(har_data, domain_filter=None):
    """Main analysis function for HAR files - focusing on POST requests"""
    try:
        entries = har_data['log']['entries']
        
        findings_by_provider = defaultdict(lambda: {'domains': defaultdict(list), 'request_count': 0})
        all_requests_by_provider = defaultdict(lambda: {'domains': defaultdict(int), 'total_requests': 0})  # Track ALL requests, even without PII
        uuid_tracking = {
            'uuids_by_domain': defaultdict(set),
            'uuid_locations': defaultdict(list),
            'shared_uuids': {},
            'total_unique_uuids': 0
        }
        total_requests = 0
        post_requests = 0
        requests_with_pii = 0
        insecure_requests = []
        
        # Track Meta/Facebook Pixel detection
        meta_tracking_detected = False
        meta_tracking_requests = []
        meta_tracking_domains = set()
        meta_tracking_types = set()  # Track which types: Facebook Pixel, Instagram, WhatsApp, etc.
        meta_tracking_pii_found = []
        
        # Track TikTok Pixel detection
        tiktok_tracking_detected = False
        tiktok_tracking_requests = []
        tiktok_tracking_domains = set()
        tiktok_tracking_types = set()
        tiktok_tracking_pii_found = []
        
        # Track LinkedIn Insight Tag detection
        linkedin_tracking_detected = False
        linkedin_tracking_requests = []
        linkedin_tracking_domains = set()
        linkedin_tracking_types = set()
        linkedin_tracking_pii_found = []
        
        # Debug: Track all POST request domains and their provider classification
        all_post_domains = []
        domain_to_provider = {}  # Maps domain to its classified provider
        
        for entry in entries:
            # Focus only on POST requests
            if entry['request']['method'] != 'POST':
                continue
            
            post_requests += 1
            url = entry['request']['url']
            domain = urlparse(url).netloc
            parsed_url = urlparse(url)
            
            # Debug: collect all POST domains - DO THIS IMMEDIATELY
            all_post_domains.append(domain)
            
            # Identify third party provider
            provider = identify_third_party_provider(domain)
            domain_to_provider[domain] = provider
            
            print(f"DEBUG: Found POST request to domain: {domain} -> Classified as: {provider}")  # Console debug
            
            # Check for Meta/Facebook tracking (check early, before filtering)
            # Get POST data text for detection
            post_text = ''
            if 'postData' in entry['request'] and 'text' in entry['request']['postData']:
                post_text = entry['request']['postData']['text']
            
            meta_detection = is_meta_tracking_request(url, domain, post_text)
            if meta_detection:
                meta_tracking_detected = True
                meta_tracking_domains.add(domain)
                meta_tracking_types.add(meta_detection['tracking_type'])
                
                # Track this as a Meta tracking request (will update with PII info later)
                meta_tracking_requests.append({
                    'url': url,
                    'domain': domain,
                    'tracking_type': meta_detection['tracking_type'],
                    'detection_method': meta_detection['detection_method'],
                    'has_pii': False,  # Will update after PII detection
                    'findings_count': 0  # Will update after findings collected
                })
                
                print(f"DEBUG: Meta tracking detected! Type: {meta_detection['tracking_type']}, Domain: {domain}")
            
            # Check for TikTok tracking
            tiktok_detection = is_tiktok_tracking_request(url, domain, post_text)
            if tiktok_detection:
                tiktok_tracking_detected = True
                tiktok_tracking_domains.add(domain)
                tiktok_tracking_types.add(tiktok_detection['tracking_type'])
                
                # Track this as a TikTok tracking request
                tiktok_tracking_requests.append({
                    'url': url,
                    'domain': domain,
                    'tracking_type': tiktok_detection['tracking_type'],
                    'detection_method': tiktok_detection['detection_method'],
                    'has_pii': False,
                    'findings_count': 0
                })
                
                print(f"DEBUG: TikTok tracking detected! Type: {tiktok_detection['tracking_type']}, Domain: {domain}")
            
            # Check for LinkedIn Insight Tag tracking
            linkedin_detection = is_linkedin_tracking_request(url, domain, post_text)
            if linkedin_detection:
                linkedin_tracking_detected = True
                linkedin_tracking_domains.add(domain)
                linkedin_tracking_types.add(linkedin_detection['tracking_type'])
                
                # Track this as a LinkedIn tracking request
                linkedin_tracking_requests.append({
                    'url': url,
                    'domain': domain,
                    'tracking_type': linkedin_detection['tracking_type'],
                    'detection_method': linkedin_detection['detection_method'],
                    'has_pii': False,
                    'findings_count': 0
                })
                
                print(f"DEBUG: LinkedIn tracking detected! Type: {linkedin_detection['tracking_type']}, Domain: {domain}")
            
            # Track ALL requests by provider IMMEDIATELY (before any filtering)
            all_requests_by_provider[provider]['domains'][domain] += 1
            all_requests_by_provider[provider]['total_requests'] += 1
            print(f"DEBUG: Added to all_requests_by_provider[{provider}][{domain}] = {all_requests_by_provider[provider]['domains'][domain]}")
            
            # Check if request is insecure (HTTP instead of HTTPS)
            is_insecure = parsed_url.scheme == 'http'
            
            # Apply domain filter if specified
            if domain_filter and domain_filter not in domain:
                continue
            
            total_requests += 1
            request_findings = []
            request_uuids = set()
            
            # Extract request headers
            request_headers = {}
            if 'headers' in entry['request']:
                for header in entry['request']['headers']:
                    request_headers[header['name']] = header['value']
            
            # Extract response information
            response_status = entry['response'].get('status', 'unknown')
            response_status_text = entry['response'].get('statusText', '')
            response_headers = {}
            if 'headers' in entry['response']:
                for header in entry['response']['headers']:
                    response_headers[header['name']] = header['value']
            
            # Get response size
            response_size = entry['response'].get('bodySize', 0)
            if response_size == -1:
                response_size = entry['response'].get('content', {}).get('size', 0)
            
            # Check URL for UUIDs
            url_uuids = extract_uuids_from_text(url)
            for uuid in url_uuids:
                request_uuids.add(uuid)
                uuid_tracking['uuid_locations'][uuid].append({
                    'domain': domain,
                    'location': 'URL',
                    'url': url
                })
            
            # Check URL parameters
            if parsed_url.query:
                query_params = parse_qs(parsed_url.query)
                flat_params = {k: v[0] if len(v) == 1 else v for k, v in query_params.items()}
                
                # Check for PII patterns in query string
                pii_in_query = detect_pii_in_text(unquote(parsed_url.query))
                for pii in pii_in_query:
                    request_findings.append({
                        **pii,
                        'location': 'Query String',
                        'url': url,
                        'request_headers': request_headers,
                        'response_status': response_status,
                        'response_status_text': response_status_text,
                        'response_headers': response_headers,
                        'response_size': response_size,
                        'is_insecure': is_insecure,
                        'category': 'true_pii'  # Pattern-based detection is always true PII
                    })
                
                # Check parameter names
                param_findings = check_param_names(flat_params)
                for finding in param_findings:
                    request_findings.append({
                        **finding,
                        'location': 'Query Parameter',
                        'url': url,
                        'request_headers': request_headers,
                        'response_status': response_status,
                        'response_status_text': response_status_text,
                        'response_headers': response_headers,
                        'response_size': response_size,
                        'is_insecure': is_insecure
                        # category already set by check_param_names
                    })
            
            # Check POST data
            if 'postData' in entry['request']:
                post_data = entry['request']['postData']
                if 'text' in post_data:
                    text = unquote(post_data['text'])
                    
                    # DOMAIN-BASED CLASSIFICATION: Check if this is a known analytics domain
                    if is_analytics_domain(domain):
                        # This is going to a known analytics platform - treat all data as analytics
                        # Still check for UUIDs for tracking purposes
                        post_uuids = extract_uuids_from_text(text)
                        for uuid in post_uuids:
                            request_uuids.add(uuid)
                            uuid_tracking['uuid_locations'][uuid].append({
                                'domain': domain,
                                'location': 'POST Body',
                                'url': url
                            })
                        
                        # Add a single analytics telemetry finding instead of checking each parameter
                        request_findings.append({
                            'type': f'Analytics Telemetry (Domain: {domain})',
                            'value': f'Large analytics payload ({len(text)} bytes) sent to {domain}',
                            'location': 'POST Body',
                            'url': url,
                            'request_headers': request_headers,
                            'response_status': response_status,
                            'response_status_text': response_status_text,
                            'response_headers': response_headers,
                            'response_size': response_size,
                            'is_insecure': is_insecure,
                            'category': 'analytics'
                        })
                        
                        # Don't do detailed parameter checking for known analytics domains
                        # (Skip the rest of POST data processing)
                    else:
                        # Not an analytics domain - do normal processing
                        # Check for UUIDs in POST data
                        post_uuids = extract_uuids_from_text(text)
                        for uuid in post_uuids:
                            request_uuids.add(uuid)
                            uuid_tracking['uuid_locations'][uuid].append({
                                'domain': domain,
                                'location': 'POST Body',
                                'url': url
                            })
                        
                        # Check for PII patterns in POST body
                        pii_in_post = detect_pii_in_text(text)
                        for pii in pii_in_post:
                            request_findings.append({
                                **pii,
                                'location': 'POST Body',
                                'url': url,
                                'request_headers': request_headers,
                                'response_status': response_status,
                                'response_status_text': response_status_text,
                                'response_headers': response_headers,
                                'response_size': response_size,
                                'is_insecure': is_insecure,
                                'category': 'true_pii'  # Pattern-based detection is always true PII
                            })
                        
                        # Try to parse as query string
                        try:
                            post_params = parse_qs(text)
                            flat_params = {k: v[0] if len(v) == 1 else v for k, v in post_params.items()}
                            param_findings = check_param_names(flat_params)
                            for finding in param_findings:
                                request_findings.append({
                                    **finding,
                                    'location': 'POST Parameter',
                                    'url': url,
                                    'request_headers': request_headers,
                                    'response_status': response_status,
                                    'response_status_text': response_status_text,
                                    'response_headers': response_headers,
                                    'response_size': response_size,
                                    'is_insecure': is_insecure
                                    # category already set by check_param_names
                                })
                        except:
                            pass
            
            # Check cookies - PRIORITY FOCUS
            if 'cookies' in entry['request']:
                for cookie in entry['request']['cookies']:
                    cookie_name = cookie.get('name', 'unknown')
                    cookie_value = cookie.get('value', '')
                    
                    # Check for UUIDs in cookies
                    cookie_uuids = extract_uuids_from_text(cookie_value)
                    for uuid in cookie_uuids:
                        request_uuids.add(uuid)
                        uuid_tracking['uuid_locations'][uuid].append({
                            'domain': domain,
                            'location': f'Cookie: {cookie_name}',
                            'url': url
                        })
                    
                    pii_in_cookie = detect_pii_in_text(cookie_value)
                    for pii in pii_in_cookie:
                        request_findings.append({
                            **pii,
                            'location': f'Cookie: {cookie_name}',
                            'url': url,
                            'cookie_name': cookie_name,
                            'request_headers': request_headers,
                            'response_status': response_status,
                            'response_status_text': response_status_text,
                            'response_headers': response_headers,
                            'response_size': response_size,
                            'is_insecure': is_insecure,
                            'category': 'true_pii'  # Pattern-based detection is always true PII
                        })
            
            # Track insecure requests with PII
            if is_insecure and request_findings:
                insecure_requests.append({
                    'url': url,
                    'domain': domain,
                    'findings_count': len(request_findings)
                })
            
            # Update Meta tracking with PII info if this was a Meta tracking request
            if meta_tracking_requests and request_findings:
                # Check if this request is a Meta tracking request
                for meta_req in meta_tracking_requests:
                    if meta_req['url'] == url:
                        meta_req['has_pii'] = True
                        meta_req['findings_count'] = len(request_findings)
                        # Collect PII types found
                        for finding in request_findings:
                            if finding.get('category') in ['true_pii', 'tracking']:
                                meta_tracking_pii_found.append(finding)
                        break
            
            # Update TikTok tracking with PII info if this was a TikTok tracking request
            if tiktok_tracking_requests and request_findings:
                # Check if this request is a TikTok tracking request
                for tiktok_req in tiktok_tracking_requests:
                    if tiktok_req['url'] == url:
                        tiktok_req['has_pii'] = True
                        tiktok_req['findings_count'] = len(request_findings)
                        # Collect PII types found
                        for finding in request_findings:
                            if finding.get('category') in ['true_pii', 'tracking']:
                                tiktok_tracking_pii_found.append(finding)
                        break
            
            # Update LinkedIn tracking with PII info if this was a LinkedIn tracking request
            if linkedin_tracking_requests and request_findings:
                # Check if this request is a LinkedIn tracking request
                for linkedin_req in linkedin_tracking_requests:
                    if linkedin_req['url'] == url:
                        linkedin_req['has_pii'] = True
                        linkedin_req['findings_count'] = len(request_findings)
                        # Collect PII types found
                        for finding in request_findings:
                            if finding.get('category') in ['true_pii', 'tracking']:
                                linkedin_tracking_pii_found.append(finding)
                        break
            
            # Track UUIDs by domain
            for uuid in request_uuids:
                uuid_tracking['uuids_by_domain'][domain].add(uuid)
            
            # Store findings by provider and domain (only if PII found)
            if request_findings:
                requests_with_pii += 1
                findings_by_provider[provider]['domains'][domain].extend(request_findings)
                findings_by_provider[provider]['request_count'] += 1
        
        # Analyze UUID sharing across domains
        uuid_to_domains = defaultdict(set)
        for domain, uuids in uuid_tracking['uuids_by_domain'].items():
            for uuid in uuids:
                uuid_to_domains[uuid].add(domain)
        
        # Find UUIDs shared across multiple domains
        for uuid, domains in uuid_to_domains.items():
            if len(domains) > 1:
                uuid_tracking['shared_uuids'][uuid] = sorted(list(domains))
        
        uuid_tracking['total_unique_uuids'] = len(uuid_to_domains)
        
        # Convert sets to lists for JSON serialization
        uuid_tracking['uuids_by_domain'] = {
            domain: list(uuids) for domain, uuids in uuid_tracking['uuids_by_domain'].items()
        }
        
        # Convert findings structure for JSON
        findings_output = {}
        for provider, data in findings_by_provider.items():
            findings_output[provider] = {
                'domains': dict(data['domains']),
                'request_count': data['request_count']
            }
        
        # Convert all requests structure for JSON (includes requests without PII)
        all_requests_output = {}
        for provider, data in all_requests_by_provider.items():
            all_requests_output[provider] = {
                'domains': dict(data['domains']),
                'total_requests': data['total_requests']
            }
        
        # Debug output
        print(f"DEBUG: Total POST domains found: {len(all_post_domains)}")
        print(f"DEBUG: Unique POST domains: {len(set(all_post_domains))}")
        print(f"DEBUG: All domains: {sorted(set(all_post_domains))}")
        print(f"DEBUG: Domain classifications:")
        for domain in sorted(set(all_post_domains)):
            print(f"  {domain} -> {domain_to_provider.get(domain, 'Unknown')}")
        
        print(f"\nDEBUG: all_requests_by_provider contents:")
        for provider, data in all_requests_by_provider.items():
            print(f"  {provider}: {data['total_requests']} requests across {len(data['domains'])} domains")
            for domain, count in data['domains'].items():
                print(f"    - {domain}: {count} requests")
        
        return {
            'total_post_requests': post_requests,
            'analyzed_requests': total_requests,
            'requests_with_pii': requests_with_pii,
            'insecure_requests': insecure_requests,
            'insecure_requests_count': len(insecure_requests),
            'third_party_providers': list(findings_output.keys()),
            'findings_by_provider': findings_output,
            'all_requests_by_provider': all_requests_output,  # NEW: All requests even without PII
            'filter_domain': domain_filter,
            'uuid_tracking': uuid_tracking,
            
            # Meta/Facebook Pixel tracking detection
            'meta_tracking_detected': meta_tracking_detected,
            'meta_tracking_requests': meta_tracking_requests,
            'meta_tracking_domains': list(meta_tracking_domains),
            'meta_tracking_types': list(meta_tracking_types),
            'meta_tracking_pii_count': len(meta_tracking_pii_found),
            'meta_tracking_pii_types': list(set([f.get('type', 'Unknown') for f in meta_tracking_pii_found])),
            
            # TikTok Pixel tracking detection
            'tiktok_tracking_detected': tiktok_tracking_detected,
            'tiktok_tracking_requests': tiktok_tracking_requests,
            'tiktok_tracking_domains': list(tiktok_tracking_domains),
            'tiktok_tracking_types': list(tiktok_tracking_types),
            'tiktok_tracking_pii_count': len(tiktok_tracking_pii_found),
            'tiktok_tracking_pii_types': list(set([f.get('type', 'Unknown') for f in tiktok_tracking_pii_found])),
            
            # LinkedIn Insight Tag tracking detection
            'linkedin_tracking_detected': linkedin_tracking_detected,
            'linkedin_tracking_requests': linkedin_tracking_requests,
            'linkedin_tracking_domains': list(linkedin_tracking_domains),
            'linkedin_tracking_types': list(linkedin_tracking_types),
            'linkedin_tracking_pii_count': len(linkedin_tracking_pii_found),
            'linkedin_tracking_pii_types': list(set([f.get('type', 'Unknown') for f in linkedin_tracking_pii_found])),
            
            'debug_all_post_domains': sorted(list(set(all_post_domains))),  # All POST domains found
            'debug_domain_classifications': {domain: domain_to_provider.get(domain, 'Unknown') for domain in sorted(set(all_post_domains))}  # Show how each was classified
        }
    except Exception as e:
        raise Exception(f"Error analyzing HAR file: {str(e)}")

@app.route('/')
def index():
    """Serve the main HTML page"""
    try:
        return send_from_directory('static', 'har_analyzer_tool_frontend.html')
    except FileNotFoundError:
        return """
        <html>
        <body>
            <h1>Setup Error</h1>
            <p>Frontend file not found. Please ensure:</p>
            <ol>
                <li>Create a folder named 'static' in the same directory as har_analyzer_tool_backend.py</li>
                <li>Save the frontend HTML file as 'static/har_analyzer_tool_frontend.html'</li>
            </ol>
            <p>Current directory structure should be:</p>
            <pre>
har_analyzer/
├── har_analyzer_tool_backend.py
└── static/
    └── har_analyzer_tool_frontend.html
            </pre>
        </body>
        </html>
        """, 404

@app.route('/analyze', methods=['POST'])
def analyze():
    """API endpoint for analyzing HAR files"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        domain_filter = request.form.get('domain', '').strip()
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not file.filename.endswith('.har'):
            return jsonify({'error': 'File must be a .har file'}), 400
        
        har_data = json.load(file)
        results = analyze_har_privacy(har_data, domain_filter if domain_filter else None)
        
        return jsonify(results)
    
    except json.JSONDecodeError:
        return jsonify({'error': 'Invalid JSON format'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Create static directory if it doesn't exist
    if not os.path.exists('static'):
        os.makedirs('static')
    
    # Get port from environment variable (Render provides this) or default to 5000
    port = int(os.environ.get('PORT', 5000))
    
    # Run with 0.0.0.0 host for external access and disable debug in production
    app.run(host='0.0.0.0', port=port, debug=False)
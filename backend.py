"""
HAR Privacy Analyzer - Phase 1
Focus: LeadID detection with large file support and automatic corruption repair
"""

from flask import Flask, request, jsonify, send_from_directory
import json
import re
import base64
from urllib.parse import urlparse, parse_qs, unquote, unquote_plus
from datetime import datetime
import os

app = Flask(__name__, static_folder='static')

# Increase max upload size to 100MB
app.config['MAX_CONTENT_LENGTH'] = 600 * 1024 * 1024  # 600 MB (covers 5x 100MB batch uploads + multipart overhead)



def strip_response_bodies(har_data):
    """
    Option B memory optimization: blank out response body text from an
    already-parsed HAR dict, reducing the live Python object tree size.

    Previous approach: brace-counting loop on the raw string before json.loads.
    Problem: O(n*m) character iteration — 27 seconds on a 36MB file with 73
    large JS/HTML responses.

    Current approach: parse JSON first (fast, C extension), then do a simple
    O(n entries) Python dict walk to blank out content.text in-place.
    Result: 0.15 seconds total — 184x faster on the same file.

    Mutates har_data in-place and returns it. No copy made.
    Safe: only touches response.content.text/encoding, never request.postData.
    """
    for entry in har_data.get('log', {}).get('entries', []):
        content = entry.get('response', {}).get('content', {})
        if 'text' in content:
            content['text'] = ''
        if 'encoding' in content:
            content['encoding'] = ''
    return har_data


def resilient_parse_har(har_text):
    """
    Extract as many entries as possible from a potentially corrupted HAR file.
    Returns (entries_list, stats_dict) or raises exception if completely unreadable.
    """
    
    print("⚠️  Standard parsing failed - attempting resilient extraction...")
    
    # Clean control characters
    har_text = re.sub(r'[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f]', '', har_text)
    
    # Find the entries array
    entries_start_match = re.search(r'"entries"\s*:\s*\[', har_text)
    if not entries_start_match:
        raise Exception("Could not find entries array in HAR file")
    
    entries_start = entries_start_match.end()
    
    # Extract individual entry objects one by one
    entries = []
    position = entries_start
    errors = 0
    
    while position < len(har_text):
        # Skip whitespace
        while position < len(har_text) and har_text[position] in ' \n\r\t':
            position += 1
        
        if position >= len(har_text):
            break
        
        # Check for end of array
        if har_text[position] == ']':
            break
        
        # Skip commas
        if har_text[position] == ',':
            position += 1
            continue
        
        # Find start of next entry
        if har_text[position] != '{':
            next_brace = har_text.find('{', position)
            if next_brace == -1:
                break
            position = next_brace
        
        # Find matching closing brace
        brace_count = 0
        in_string = False
        escape = False
        start_pos = position
        
        i = position
        while i < len(har_text):
            char = har_text[i]
            
            if escape:
                escape = False
                i += 1
                continue
            
            if char == '\\':
                escape = True
                i += 1
                continue
            
            if char == '"':
                in_string = not in_string
            elif not in_string:
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        # Found complete entry
                        entry_text = har_text[start_pos:i+1]
                        
                        try:
                            entry = json.loads(entry_text)
                            entries.append(entry)
                        except:
                            errors += 1
                        
                        position = i + 1
                        break
            
            i += 1
        else:
            # Hit corruption - try to find next valid entry
            next_entry = har_text.find('"startedDateTime"', position + 1000)
            if next_entry == -1:
                break
            
            # Backtrack to find the {
            back_pos = next_entry
            while back_pos > position and har_text[back_pos] != '{':
                back_pos -= 1
            
            if back_pos > position:
                position = back_pos
                errors += 1
            else:
                break
    
    stats = {
        'extracted': len(entries),
        'skipped': errors,
        'success_rate': len(entries) / (len(entries) + errors) * 100 if (len(entries) + errors) > 0 else 0
    }
    
    print(f"✅ Resilient parsing: extracted {len(entries)} entries, skipped {errors}")
    
    return entries, stats


def decode_base64_if_present(text):
    """
    Detect and decode base64-encoded data.
    Returns decoded text if valid base64, otherwise returns None.
    """
    if not text or len(text) < 10:
        return None
    
    # Pattern 1: data URL (data:image/png;base64,...)
    if text.startswith('data:'):
        parts = text.split(',', 1)
        if len(parts) == 2 and 'base64' in parts[0]:
            try:
                decoded = base64.b64decode(parts[1])
                return decoded.decode('utf-8', errors='ignore')
            except:
                return None
    
    # Pattern 2: Looks like base64 (alphanumeric + / + =)
    # Must be reasonable length and have base64 characteristics
    if re.match(r'^[A-Za-z0-9+/=]{20,}$', text):
        # Check if it has the right padding
        try:
            # Try to decode
            decoded = base64.b64decode(text)
            # Check if decoded result looks like text or JSON
            decoded_str = decoded.decode('utf-8', errors='ignore')
            
            # If it looks like JSON or contains readable text, it's probably real base64
            if decoded_str.startswith(('{', '[')) or any(c.isalpha() for c in decoded_str[:50]):
                return decoded_str
        except:
            pass
    
    return None


def detect_hash_pattern(key, value):
    """
    Detect if a value is a hash of PII (email, phone).
    Returns PII dict if hash detected, None otherwise.
    
    Common patterns:
    - SHA-256: 64 hex chars
    - SHA-1: 40 hex chars  
    - MD5: 32 hex chars
    """
    if not isinstance(value, str):
        return None
    
    key_lower = key.lower()
    
    # SHA-256 (64 hex characters)
    if re.match(r'^[a-f0-9]{64}$', value.lower()):
        if any(term in key_lower for term in ['email', 'em', 'mail']):
            return {
                'type': 'Hashed Email (SHA-256)',
                'field': key,
                'value': value[:16] + '...',  # Show first 16 chars
                'note': 'Full hash: ' + value
            }
        if any(term in key_lower for term in ['phone', 'tel', 'mobile']):
            return {
                'type': 'Hashed Phone (SHA-256)',
                'field': key,
                'value': value[:16] + '...',
                'note': 'Full hash: ' + value
            }
    
    # SHA-1 (40 hex characters)
    elif re.match(r'^[a-f0-9]{40}$', value.lower()):
        if any(term in key_lower for term in ['email', 'em', 'mail']):
            return {
                'type': 'Hashed Email (SHA-1)',
                'field': key,
                'value': value[:16] + '...',
                'note': 'Full hash: ' + value
            }
        if any(term in key_lower for term in ['phone', 'tel', 'mobile']):
            return {
                'type': 'Hashed Phone (SHA-1)',
                'field': key,
                'value': value[:16] + '...',
                'note': 'Full hash: ' + value
            }
    
    # MD5 (32 hex characters)
    elif re.match(r'^[a-f0-9]{32}$', value.lower()):
        if any(term in key_lower for term in ['email', 'em', 'mail']):
            return {
                'type': 'Hashed Email (MD5)',
                'field': key,
                'value': value[:16] + '...',
                'note': 'Full hash: ' + value
            }
        if any(term in key_lower for term in ['phone', 'tel', 'mobile']):
            return {
                'type': 'Hashed Phone (MD5)',
                'field': key,
                'value': value[:16] + '...',
                'note': 'Full hash: ' + value
            }
    
    return None


def robust_url_decode(text):
    """
    Decode URL-encoded text, handling multiple encoding layers.
    
    Examples:
    - Single: name%40example.com → name@example.com
    - Double: name%2540example.com → name%40example.com → name@example.com
    - Plus signs: first+last → first last
    """
    if not isinstance(text, str):
        return text
    
    # Decode up to 5 layers (should be more than enough)
    prev = text
    for i in range(5):
        # Use unquote_plus to handle both %20 and + for spaces
        curr = unquote_plus(prev)
        if curr == prev:
            # No more encoding layers
            break
        prev = curr
    
    return curr


def extract_pii_from_params(params):
    """
    Look for common PII field names in parameters with context-aware detection
    """
    pii = []
    
    # Known PII field name patterns
    pii_field_patterns = {
        # Email fields
        'email': 'Email',
        'e': 'Email',  # Common short form
        'em': 'Email',
        'mail': 'Email',
        'user_email': 'Email',
        
        # Phone fields
        'phone': 'Phone',
        'tel': 'Phone',
        'telephone': 'Phone',
        'mobile': 'Phone',
        'contactPhone': 'Phone',
        'contactphone': 'Phone',
        'phone_number': 'Phone',
        'ph': 'Phone',
        
        # Zip/Postal code fields
        'zip': 'Zip Code',
        'zipcode': 'Zip Code',
        'zip_code': 'Zip Code',
        'postal': 'Zip Code',
        'postalcode': 'Zip Code',
        'postal_code': 'Zip Code',
        
        # Name fields
        'firstName': 'First Name',
        'first_name': 'First Name',
        'firstname': 'First Name',
        'fn': 'First Name',
        'lastName': 'Last Name',
        'last_name': 'Last Name',
        'lastname': 'Last Name',
        'ln': 'Last Name',
        'contactName': 'Full Name',
        'contact_name': 'Full Name',
        'contactname': 'Full Name',
        'name': 'Name',
        'fullname': 'Full Name',
        'full_name': 'Full Name',
        
        # Address fields
        'address': 'Address',
        'street': 'Street Address',
        'street_address': 'Street Address',
        'addr': 'Address',
        'city': 'City',
        'state': 'State',
        'st': 'State',  # Only if exact match
        'country': 'Country',
        
        # Other PII
        'businessDescription': 'Business Description',
        'business_description': 'Business Description',
        'insurance_type': 'Insurance Type',
        'insurancetype': 'Insurance Type',
        'ssn': 'SSN',
        'social_security': 'SSN',
    }
    
    # Tracking/non-PII field patterns to EXCLUDE
    exclude_patterns = [
        'id', 'pixel', 'fbp', 'fbc', '_fb', 'ga_', 'gid', 'cid',
        'session', 'token', 'timestamp', 'ts', 'uid', 'uuid',
        'click', 'campaign', 'source', 'medium', 'ref', 'utm',
        'event', 'ev', 'action', 'version', 'v', 'ttclid', 'ttp',
        'callback', 'cb', 'redirect', 'url', 'dl', 'rl',
        'fst', 'lst', 'pst',  # first/last/previous seen timestamp
        'cs_', 'ep.', '_ga', '_gcl',  # Google/Facebook tracking params
        'memory', 'heap', 'size', 'limit',  # Performance metrics
        'width', 'height', 'screen', 'viewport',  # Display metrics
        '_et', 'tfd', 'tcfd',  # Google Analytics encrypted params
        '.js', '.css', '.png', '.jpg', '.gif',  # File extensions
        'script', 'src', 'href',  # HTML/resource references
    ]
    
    # Check each parameter
    for key, value in params.items():
        # Handle both single values and lists
        val = value[0] if isinstance(value, list) else value
        
        # Skip empty or very short values
        if not val or len(str(val)) < 2:
            continue
        
        # Skip if value looks like a filename
        if any(ext in str(val).lower() for ext in ['.js', '.css', '.html', '.png', '.jpg', '.svg', '.gif', '.woff']):
            continue
        
        # Convert value to string and apply robust URL decoding
        val_str = robust_url_decode(str(val))
        
        # Convert key to lowercase for comparison
        key_lower = key.lower()
        
        # Check if this is a tracking field we should skip
        if any(exclude in key_lower for exclude in exclude_patterns):
            continue
        
        # PRIORITY 1: Check for hashed PII (SHA-256, SHA-1, MD5)
        hash_pii = detect_hash_pattern(key, val_str)
        if hash_pii:
            pii.append(hash_pii)
            continue  # Hash detected, move to next param
        
        # PRIORITY 2: Try to decode base64 if present
        decoded = decode_base64_if_present(val_str)
        if decoded:
            # Decoded successfully - check if it's JSON
            if decoded.startswith(('{', '[')):
                try:
                    decoded_json = json.loads(decoded)
                    # Recursively extract PII from decoded JSON
                    pii.extend(extract_pii_from_json(decoded_json, prefix=f'{key}[decoded].'))
                    continue  # Found JSON in base64, move to next param
                except:
                    pass
            # If not JSON, treat decoded text as the value
            val_str = decoded
        
        # PRIORITY 3: Check if field name matches known PII fields
        matched = False
        for field_pattern, label in pii_field_patterns.items():
            # For short ambiguous patterns like 'st', require exact match
            if field_pattern in ['st', 'v', 'e', 'ph', 'fn', 'ln']:
                if key_lower == field_pattern.lower():
                    field_match = True
                else:
                    field_match = False
            else:
                field_match = field_pattern.lower() in key_lower
            
            if field_match:
                # Additional validation based on type
                val_str = str(val)
                
                if label == 'Email':
                    # Validate email format
                    if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', val_str):
                        pii.append({
                            'type': label,
                            'field': key,
                            'value': val_str
                        })
                        matched = True
                        break
                
                elif label == 'Phone':
                    # Validate phone: must be 10 digits, no dots or 'fb' prefix
                    clean = re.sub(r'[^\d]', '', val_str)
                    if len(clean) == 10 and not any(c in val_str.lower() for c in ['fb', 'ga', '.']):
                        pii.append({
                            'type': label,
                            'field': key,
                            'value': val_str
                        })
                        matched = True
                        break
                
                elif label == 'Zip Code':
                    # Validate zip: exactly 5 digits
                    if re.match(r'^\d{5}$', val_str):
                        # Reject single-letter field names (too ambiguous)
                        if len(key) <= 1:
                            matched = True
                            break
                        
                        # Reject if field name suggests it's NOT a zip (but allow zipcode/zip_code)
                        # Check for patterns like 'eventCode', 'errorCode' but NOT 'zipCode'
                        suspicious_patterns = ['eventcode', 'errorcode', 'statuscode', 'responsecode', 'orderid', 'sessionid']
                        if not any(pattern in key_lower for pattern in suspicious_patterns):
                            pii.append({
                                'type': label,
                                'field': key,
                                'value': val_str
                            })
                            matched = True
                            break
                
                elif label == 'SSN':
                    # Validate SSN: 9 digits or XXX-XX-XXXX format
                    clean = re.sub(r'[^\d]', '', val_str)
                    if len(clean) == 9:
                        pii.append({
                            'type': label,
                            'field': key,
                            'value': val_str
                        })
                        matched = True
                        break
                
                else:
                    # Other fields: just need non-empty value
                    # For name fields, add extra validation
                    if 'Name' in label:
                        # Filter out common technical terms, filenames, and abbreviations
                        val_lower = val_str.lower()
                        invalid_names = [
                            'pixel', 'script', 'bundle', 'chunk', 'module', 'component',
                            'data', 'info', 'user', 'type', 'null', 'none', 'undefined',
                            'true', 'false', 'yes', 'no', 'ok', 'error',
                            'fn', 'ln', 'n/a', 'na'
                        ]
                        
                        # Skip if it's a technical term or filename
                        if any(term in val_lower for term in invalid_names):
                            continue
                        
                        # Skip if it contains file extension indicators
                        if any(ext in val_lower for ext in ['.js', '.css', '.html', '.']):
                            continue
                        
                        # Skip very short names (likely abbreviations)
                        if len(val_str) < 3:
                            continue
                    
                    if len(val_str) > 1:
                        pii.append({
                            'type': label,
                            'field': key,
                            'value': val_str
                        })
                        matched = True
                        break
        
        # If not matched by field name, try pattern-only detection as FALLBACK
        # Some sites DO send plaintext PII in unexpected field names!
        if not matched:
            val_str = str(val)
            
            # Make sure field isn't in exclusion list
            if any(exclude in key_lower for exclude in exclude_patterns):
                continue
            
            # Email pattern - high confidence
            if '@' in val_str and re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', val_str):
                pii.append({
                    'type': 'Email',
                    'field': key,
                    'value': val_str
                })
            
            # Phone pattern - be more careful but still detect
            # Must be EXACTLY 10 digits OR formatted phone (xxx-xxx-xxxx, (xxx) xxx-xxxx)
            elif re.match(r'^(\d{10}|\d{3}-\d{3}-\d{4}|\(\d{3}\)\s*\d{3}-\d{4})$', val_str):
                # Extra validation: no dots, not part of tracking ID
                if '.' not in val_str and 'fb' not in val_str.lower() and '_' not in val_str:
                    pii.append({
                        'type': 'Phone',
                        'field': key,
                        'value': val_str
                    })
            
            # Zip code pattern - must be exactly 5 digits
            # Additional check: field name shouldn't suggest it's a code/ID
            elif re.match(r'^\d{5}$', val_str):
                # Skip single-letter field names (too ambiguous like 'o', 'v', etc.)
                if len(key) <= 2:
                    continue
                
                # Skip if field name suggests it's not a zip (ID, code, count, order, index, etc.)
                if any(word in key_lower for word in ['code', 'id', 'event', 'version', 'count', 'order', 'index', 'sequence', 'number']):
                    continue
                
                # Only accept if looks like real US zip (not starting with 0 is rare but valid)
                pii.append({
                    'type': 'Zip Code',
                    'field': key,
                    'value': val_str
                })
            
            # Name pattern - capitalized word with length > 2
            # Be VERY careful - filenames often match this pattern!
            elif re.match(r'^[A-Z][a-z]{2,}$', val_str):
                # Skip if it's obviously a filename or code term
                if any(term in val_str.lower() for term in ['pixel', 'script', 'bundle', 'chunk', 'min', 'js', 'css', 'html', 'json', 'xml']):
                    continue
                # Skip if field name suggests technical content
                if any(term in key_lower for term in ['file', 'script', 'url', 'path', 'type', 'format', 'extension']):
                    continue
                # Skip generic words
                # Skip generic words AND analytics/tracking event names
                GENERIC_WORDS = {
                    # Generic UI/data terms
                    'Page', 'View', 'Data', 'User', 'Info', 'Type', 'Name', 'Form',
                    'None', 'Null', 'True', 'False', 'Home', 'Next', 'Back', 'Done',
                    'Open', 'Close', 'Send', 'Load', 'Init', 'Start', 'Stop', 'Save',
                    # Analytics event names (TikTok, GA, Facebook, etc.)
                    'Segment', 'Click', 'Track', 'Event', 'Fire', 'Hit', 'Ping',
                    'Pixel', 'Lead', 'Submit', 'Complete', 'Convert', 'Purchase',
                    'Search', 'Browse', 'Scroll', 'Hover', 'Focus', 'Blur',
                    'Error', 'Debug', 'Warn', 'Info', 'Log', 'Trace',
                    # Common single-word values that aren't names
                    'Male', 'Female', 'Other', 'Unknown', 'Default', 'Custom',
                    'Active', 'Pending', 'Enabled', 'Disabled', 'Success', 'Failed',
                }
                if val_str in GENERIC_WORDS:
                    continue
                
                # If it passes all checks, it MIGHT be a name
                pii.append({
                    'type': 'Name',
                    'field': key,
                    'value': val_str
                })
    
    return pii

def extract_pii_from_json(data, prefix=''):
    """
    Recursively extract PII from JSON data
    """
    pii = []
    
    if isinstance(data, dict):
        for key, value in data.items():
            current_key = f"{prefix}.{key}" if prefix else key
            
            if isinstance(value, (dict, list)):
                pii.extend(extract_pii_from_json(value, current_key))
            else:
                # Treat as parameter
                params = {current_key: value}
                pii.extend(extract_pii_from_params(params))
    
    elif isinstance(data, list):
        for i, item in enumerate(data):
            current_key = f"{prefix}[{i}]"
            pii.extend(extract_pii_from_json(item, current_key))
    
    return pii

def extract_pii_from_request(entry):
    """
    Extract plaintext PII from POST body and query params
    """
    pii = []
    
    # Check POST body
    if 'postData' in entry['request'] and 'text' in entry['request']['postData']:
        text = entry['request']['postData']['text']
        mime_type = entry['request']['postData'].get('mimeType', '')
        
        # Try JSON parsing first (regardless of MIME type) if text looks like JSON
        if text.strip().startswith(('{', '[')):
            try:
                data = json.loads(text)
                pii.extend(extract_pii_from_json(data))
            except:
                pass
        
        # URL-encoded parameters
        if 'application/x-www-form-urlencoded' in mime_type or ('=' in text and '&' in text):
            try:
                params = parse_qs(text)
                pii.extend(extract_pii_from_params(params))
            except:
                pass
    
    # Check query string
    url = entry['request']['url']
    if '?' in url:
        try:
            query = url.split('?', 1)[1]
            params = parse_qs(query)
            pii.extend(extract_pii_from_params(params))
        except:
            pass
    
    return pii

def find_first_party_domain(har_data):
    """
    Find the main website being analyzed
    """
    domains = {}
    
    for entry in har_data['log']['entries']:
        url = entry.get('request', {}).get('url', '')
        if not url:
            continue
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            
            # Skip common third-party domains and CDNs
            skip_domains = [
                'google', 'facebook', 'doubleclick', 'analytics',
                'leadid', 'jornaya', 'trustedform', 'trueleadid',
                'invoca', 'bing', 'microsoft', 'linkedin',
                'cloudflare', 'akamai', 'cdn', 'tiktok',
                'gstatic', 'googleapis', 'amazon', 'amazonaws',
                'fastly', 'cloudfront', 'newrelic', 'nr-data',
                'segment', 'sentry', 'hotjar', 'intercom',
                'zendesk', 'stripe', 'twilio', 'sendgrid',
                'clarity.ms', 'hotjar', 'mixpanel', 'heap', 'mouseflow',
            ]
            
            if any(skip in domain.lower() for skip in skip_domains):
                continue
            
            # Skip empty domains
            if not domain:
                continue
            
            domains[domain] = domains.get(domain, 0) + 1
        except:
            continue
    
    # Return most common domain
    if domains:
        return max(domains, key=domains.get)
    return 'Unknown'

def detect_vendor_requests(entries):
    """
    Option D memory optimization: detect vendors AND extract all needed data
    inline in a single pass, storing NO 'entry' references.

    Previously this function stored {'entry': entry, ...} for every matched
    request, keeping the entire parsed JSON (~3.5x file size) alive in memory
    until analyze_har_simple returned. Now we extract everything we need from
    each entry immediately and discard the reference, allowing Python's GC to
    free the parsed JSON as soon as the caller does `del har_data`.

    Each vendor's requests list now stores lightweight dicts with:
      - Scalar fields extracted from the entry (url, method, timestamp, etc.)
      - pii: list of PII items found (extracted inline here)
      - all_request_info: the summary row for the expandable UI list
    No reference to the original entry object is retained.
    """
    VENDOR_PATTERNS = {
        'leadid':    ('LeadID/Jornaya/TrustedForm', 'critical',
                      ['leadid.com', 'jornaya.com', 'trustedform.com', 'trueleadid.com']),
        'google':    ('Google Analytics/Ads', 'high',
                      ['google-analytics.com', 'googletagmanager.com', 'doubleclick.net',
                       'googlesyndication.com', 'googleadservices.com', '/google/ads', '/gtag/']),
        'facebook':  ('Facebook/Meta Pixel', 'critical',
                      ['facebook.com/tr', 'connect.facebook.net', 'facebook.net',
                       '/fbevents.js', 'fbcdn.net']),
        'tiktok':    ('TikTok Pixel', 'critical',
                      ['analytics.tiktok.com', 'business-api.tiktok.com',
                       'tiktok.com/i18n/pixel', '/tiktok-pixel']),
        'invoca':    ('Invoca Call Tracking', 'high',
                      ['invoca.net', 'invocacdn.com']),
        'microsoft': ('Microsoft/Bing Ads', 'medium',
                      ['bat.bing.com', 'bing.com/api', 'clarity.ms', 'uetanalytics.com']),
        'linkedin':  ('LinkedIn Insight Tag', 'medium',
                      ['linkedin.com/px', 'snap.licdn.com', 'linkedin.com/li/track']),
    }

    vendors = {
        key: {
            'name': name,
            'risk': risk,
            'request_count': 0,
            'post_count': 0,
            'pii': [],          # extracted PII items (lightweight dicts only)
            'all_requests': [], # summary rows for expandable UI list
        }
        for key, (name, risk, _) in VENDOR_PATTERNS.items()
    }

    for entry in entries:
        url_lower = entry.get('request', {}).get('url', '').lower()
        full_url  = entry.get('request', {}).get('url', '')
        method    = entry.get('request', {}).get('method', 'GET')
        timestamp = entry.get('startedDateTime', '')

        # Match vendor
        matched_key = None
        for key, (_, _, patterns) in VENDOR_PATTERNS.items():
            if any(p in url_lower for p in patterns):
                matched_key = key
                break
        if matched_key is None:
            continue

        v = vendors[matched_key]
        vendor_name = v['name']

        # --- Extract scalars from entry NOW, before we lose the reference ---
        time_ms         = entry.get('time', 0)
        response_status = entry.get('response', {}).get('status', 0)
        request_size    = entry.get('request', {}).get('bodySize', 0)
        response_size   = entry.get('response', {}).get('bodySize', 0)

        # --- PII extraction inline (was extract_pii_from_vendor_requests) ---
        pii_found = extract_pii_from_request(entry)
        pii_items = []
        for pii_item in pii_found:
            is_hashed    = 'Hashed' in pii_item['type']
            legal_context = get_legal_context(pii_item['type'], vendor_name, is_hashed)
            pii_items.append({
                'type':      pii_item['type'],
                'value':     pii_item['value'],
                'field':     pii_item.get('field', ''),
                'timestamp': timestamp,
                'url':       full_url[:100],
                'note':      pii_item.get('note', ''),
                'request_details': {
                    'method':          method,
                    'full_url':        full_url,
                    'response_code':   response_status,
                    'response_time_ms': int(time_ms) if time_ms else 0,
                    'request_size':    request_size,
                    'response_size':   response_size,
                },
                'legal_context': legal_context,
            })

        # --- Build all_requests summary row (was built in analyze_har_simple) ---
        has_pii = len(pii_items) > 0
        all_request_row = {
            'method':          method,
            'url':             full_url,
            'timestamp':       timestamp,
            'response_code':   response_status,
            'response_time_ms': int(time_ms) if time_ms else 0,
            'has_pii':         has_pii,
        }

        # Accumulate — NO 'entry' reference stored anywhere
        v['request_count'] += 1
        if method == 'POST':
            v['post_count'] += 1
        v['pii'].extend(pii_items)
        v['all_requests'].append(all_request_row)

        # entry goes out of scope at end of loop iteration.
        # With no stored reference, GC can free it as soon as
        # del har_data is called in the caller.

    # Filter out vendors with no requests
    return {k: v for k, v in vendors.items() if v['request_count'] > 0}


def get_legal_severity(pii_type, is_hashed=False):
    """
    Determine legal severity for a PII type
    """
    if is_hashed:
        return {
            'severity': 'high',
            'violation_type': 'hashed_pii_third_party',
            'estimated_damages': 5000
        }
    elif pii_type in ['Email', 'Phone', 'SSN']:
        return {
            'severity': 'critical',
            'violation_type': 'plaintext_pii_third_party',
            'estimated_damages': 5000
        }
    elif pii_type in ['First Name', 'Last Name', 'Full Name', 'Name']:
        return {
            'severity': 'critical',
            'violation_type': 'plaintext_pii_third_party',
            'estimated_damages': 5000
        }
    elif pii_type in ['Zip Code', 'Address', 'City', 'State']:
        return {
            'severity': 'high',
            'violation_type': 'plaintext_pii_third_party',
            'estimated_damages': 5000
        }
    else:
        return {
            'severity': 'medium',
            'violation_type': 'potential_pii_third_party',
            'estimated_damages': 5000
        }


def get_legal_context(pii_type, vendor_name, is_hashed=False):
    """
    Generate legal context for a PII transmission
    """
    severity_info = get_legal_severity(pii_type, is_hashed)
    
    # Base context
    context = {
        'severity': severity_info['severity'],
        'violation_type': severity_info['violation_type'],
        'estimated_damages': severity_info['estimated_damages'],
        'evidence_strength': 'strong' if not is_hashed else 'very_strong'
    }
    
    # Generate what_happened text
    if is_hashed:
        context['what_happened'] = f"{vendor_name} received a cryptographically hashed version of your {pii_type.lower()}. While they can't see the actual value, they can use this hash to track you across websites."
    else:
        context['what_happened'] = f"{vendor_name} received your {pii_type.lower()} in plaintext while you were using the website."
    
    # Generate why_matters text
    if is_hashed:
        context['why_matters'] = f"Third-party disclosure of {pii_type.lower()}-related data + Cross-site tracking capability + No observed consent"
    else:
        context['why_matters'] = f"Third-party interception + Contents of communication ({pii_type.lower()}) + No observed consent"
    
    # CIPA elements
    context['cipa_elements'] = ['third_party_disclosure', 'no_consent']
    if not is_hashed:
        context['cipa_elements'].extend(['interception', 'contents_of_communication'])
    if is_hashed:
        context['cipa_elements'].append('tracking_capability')
    
    return context


# extract_pii_from_vendor_requests removed — logic merged into detect_vendor_requests (Option D)


def analyze_first_party_requests(entries, first_party_domain):
    """
    Analyze first-party POST requests for PII collection.
    This catches lead generation sites that collect PII on their own server
    before sharing tracking IDs with third parties.
    """
    first_party_pii = []
    first_party_posts = []
    
    for entry in entries:
        # Only look at POST requests
        if entry.get('request', {}).get('method') != 'POST':
            continue
        
        url = entry['request']['url']
        
        # Check if this is a first-party request
        if first_party_domain not in url:
            continue
        
        # Skip common non-PII endpoints
        skip_paths = [
            '/assets/', '/static/', '/_next/', '/api/analytics', 
            '/api/tracking', '/api/events', '/__nextjs'
        ]
        if any(skip in url for skip in skip_paths):
            continue
        
        # Extract PII from this request
        pii_found = extract_pii_from_request(entry)
        
        if pii_found:
            first_party_posts.append({
                'url': url,
                'timestamp': entry.get('startedDateTime', ''),
                'pii': pii_found
            })
            
            # Add to overall list
            for pii_item in pii_found:
                first_party_pii.append({
                    'type': pii_item['type'],
                    'value': pii_item['value'],
                    'field': pii_item['field'],
                    'timestamp': entry.get('startedDateTime', ''),
                    'url': url[:100]
                })
    
    return {
        'pii_items': first_party_pii,
        'post_requests': first_party_posts,
        'post_count': len(first_party_posts),
        'pii_count': len(set(f"{p['type']}:{p['value']}" for p in first_party_pii))
    }


def analyze_har_as_plaintext(har_text, first_party_domain):
    """
    Fallback analysis for corrupted HAR files.
    Searches the raw text for PII patterns without parsing JSON structure.
    
    This is useful when:
    - File is severely corrupted
    - JSON structure is broken
    - Entries can't be parsed normally
    """
    print("🔍 Analyzing HAR as plaintext (fallback mode)...")
    
    pii_findings = []
    
    # Search for email addresses
    emails = re.findall(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', har_text)
    unique_emails = set(emails)
    
    # Filter out common tracking/system emails
    exclude_domains = ['facebook.com', 'google.com', 'tiktok.com', 'microsoft.com', 
                      'linkedin.com', 'example.com', 'localhost', 'qualtrics.com',
                      'adobe.com', 'cloudflare.com', 'akamai.com']
    
    for email in unique_emails:
        if not any(domain in email.lower() for domain in exclude_domains):
            pii_findings.append({
                'type': 'Email',
                'value': email,
                'field': 'plaintext_scan',
                'source': 'fallback'
            })
    
    # Search for phone numbers
    # Look for patterns like: "phone":"6123277188" or \"phone\":\"6123277188\"
    phone_patterns = [
        r'\\*["\']?phone\\*["\']?\s*:\s*\\*["\']?(\d{10})\\*["\']?',
        r'\\*["\']?tel\\*["\']?\s*:\s*\\*["\']?(\d{10})\\*["\']?',
        r'\\*["\']?mobile\\*["\']?\s*:\s*\\*["\']?(\d{10})\\*["\']?',
        r'\\*["\']?contactPhone\\*["\']?\s*:\s*\\*["\']?(\d{10})\\*["\']?',
    ]
    
    for pattern in phone_patterns:
        phones = re.findall(pattern, har_text, re.IGNORECASE)
        for phone in set(phones):
            # Validate it looks like a real phone (area code check)
            if phone[0] in '23456789':  # Valid US area codes
                pii_findings.append({
                    'type': 'Phone',
                    'value': phone,
                    'field': 'plaintext_scan',
                    'source': 'fallback'
                })
    
    # Search for first/last names
    # Including escaped JSON: \"firstName\":\"Matthew\"
    name_patterns = [
        (r'\\*["\']?firstName\\*["\']?\s*:\s*\\*["\']([A-Z][a-z]+)\\*["\']', 'First Name'),
        (r'\\*["\']?lastName\\*["\']?\s*:\s*\\*["\']([A-Z][a-z]+)\\*["\']', 'Last Name'),
        (r'\\*["\']?first_name\\*["\']?\s*:\s*\\*["\']([A-Z][a-z]+)\\*["\']', 'First Name'),
        (r'\\*["\']?last_name\\*["\']?\s*:\s*\\*["\']([A-Z][a-z]+)\\*["\']', 'Last Name'),
    ]
    
    for pattern, label in name_patterns:
        names = re.findall(pattern, har_text, re.IGNORECASE)
        for name in set(names):
            # Filter out abbreviations and common words
            if len(name) > 2 and name.lower() not in ['page', 'view', 'data', 'user', 'info', 'type', 'name', 'form', 'none', 'null']:
                pii_findings.append({
                    'type': label,
                    'value': name,
                    'field': 'plaintext_scan',
                    'source': 'fallback'
                })
    
    # Remove duplicates
    unique_pii = {}
    for pii in pii_findings:
        key = f"{pii['type']}:{pii['value']}"
        if key not in unique_pii:
            unique_pii[key] = pii
    
    pii_list = list(unique_pii.values())
    
    print(f"   Found {len(pii_list)} PII items in plaintext scan")
    
    return {
        'pii_items': pii_list,
        'pii_count': len(pii_list),
        'method': 'plaintext_fallback',
        'note': 'PII extracted via plaintext scan due to file corruption'
    }

def build_simple_timeline(requests):
    """
    Build chronological list of captures
    """
    timeline = []
    
    for req in sorted(requests, key=lambda x: x['timestamp']):
        try:
            # Parse ISO timestamp
            timestamp = datetime.fromisoformat(req['timestamp'].replace('Z', '+00:00'))
            time_str = timestamp.strftime('%I:%M:%S %p')
            date_str = timestamp.strftime('%B %d, %Y')
        except:
            time_str = req['timestamp']
            date_str = req['timestamp'].split('T')[0] if 'T' in req['timestamp'] else 'Unknown'
        
        for capture in req['captures']:
            timeline.append({
                'time': time_str,
                'date': date_str,
                'type': capture['type'],
                'value': capture['value'],
                'field': capture['field'],
                'url': req['url']
            })
    
    return timeline

def analyze_har_simple(har_data):
    """
    Analyze HAR file for all major third-party vendors.

    Option D memory layout:
      1. Extract scalars (total_requests, post_requests, first_party, session info)
         from har_data while we still have it.
      2. Run first_party and LeadID timeline analysis (both need raw entries).
      3. Call detect_vendor_requests — now does inline PII extraction with NO
         entry references stored. Returns fully extracted lightweight dicts.
      4. del har_data — at this point no entry refs exist anywhere, so Python's
         GC can immediately free ~3.5x file size of parsed JSON.
      5. All remaining work uses only lightweight extracted data.
    """

    # 1. Extract scalars and session info from har_data upfront
    entries = har_data['log']['entries']
    total_requests = len(entries)
    post_requests  = sum(1 for e in entries if e.get('request', {}).get('method') == 'POST')
    first_party    = find_first_party_domain(har_data)

    session_start = None
    session_date  = None
    if entries:
        try:
            first_ts = entries[0].get('startedDateTime', '')
            if first_ts:
                dt = datetime.fromisoformat(first_ts.replace('Z', '+00:00'))
                session_start = dt.strftime('%I:%M %p')
                session_date  = dt.strftime('%B %d, %Y')
        except:
            session_start = 'Unknown'
            session_date  = 'Unknown'

    # 2. First-party analysis (needs raw entries — do before del har_data)
    first_party_analysis = analyze_first_party_requests(entries, first_party)

    # 3. LeadID timeline (needs raw entries — do before del har_data)
    # We rebuild it from the PII already extracted in step 4 below after the
    # vendor pass, but we need entries for the timeline builder format.
    # Build a lightweight capture list now while entries are still alive.
    leadid_captures = []
    for entry in entries:
        url_lower = entry.get('request', {}).get('url', '').lower()
        if any(d in url_lower for d in ['leadid.com', 'jornaya.com', 'trustedform.com', 'trueleadid.com']):
            pii_found = extract_pii_from_request(entry)
            if pii_found:
                leadid_captures.append({
                    'timestamp': entry.get('startedDateTime', ''),
                    'url':       entry.get('request', {}).get('url', ''),
                    'captures':  pii_found,
                })

    # 4. Vendor detection + inline PII extraction (Option D: no entry refs stored)
    detected_vendors = detect_vendor_requests(entries)

    # 5. Option D: release the parsed JSON now — no entry refs remain anywhere
    del entries, har_data

    # 6. Build final vendor output from the already-extracted lightweight data
    vendors_with_pii = {}
    leadid_in_vendors = False
    leadid_request_count = 0

    for vendor_key, vendor_data in detected_vendors.items():
        pii = vendor_data['pii']
        pii_count = len(set(f"{p['type']}:{p['value']}" for p in pii))

        vendors_with_pii[vendor_key] = {
            'name':          vendor_data['name'],
            'risk':          vendor_data['risk'],
            'request_count': vendor_data['request_count'],
            'post_count':    vendor_data['post_count'],
            'pii':           pii,
            'pii_count':     pii_count,
            'all_requests':  vendor_data['all_requests'],
        }

        if vendor_key == 'leadid':
            leadid_in_vendors = True
            leadid_request_count = vendor_data['request_count']

    # 7. Build LeadID timeline from the lightweight captures collected in step 3
    leadid_timeline = build_simple_timeline(leadid_captures) if leadid_captures else []

    # 8. Count total unique PII across all vendors
    all_pii = set()
    for vendor_data in vendors_with_pii.values():
        for pii in vendor_data['pii']:
            all_pii.add(f"{pii['type']}:{pii['value']}")

    return {
        'first_party':    first_party,
        'total_requests': total_requests,
        'post_requests':  post_requests,

        'vendors_detected': len(detected_vendors),
        'vendors':          vendors_with_pii,

        'first_party_pii': first_party_analysis,

        # Legacy LeadID fields
        'leadid_detected':       leadid_in_vendors,
        'leadid_request_count':  leadid_request_count,
        'timeline':              leadid_timeline,

        'pii_count':     len(all_pii),
        'session_start': session_start,
        'session_date':  session_date,
    }

@app.route('/')
def index():
    """Serve the main HTML page"""
    return send_from_directory('static', 'index.html')

@app.route('/bulk')
def bulk():
    """Serve the bulk ranker page"""
    return send_from_directory('static', 'bulk.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    """API endpoint for analyzing HAR files"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not file.filename.endswith('.har'):
            return jsonify({'error': 'File must be a .har file'}), 400
        
        # Load HAR data with robust error handling
        try:
            # Read file content
            file_content = file.read()
            
            # Decode with error handling for non-UTF-8 bytes
            try:
                har_text = file_content.decode('utf-8')
            except UnicodeDecodeError:
                print("Warning: HAR file contains non-UTF-8 bytes, using replacement")
                har_text = file_content.decode('utf-8', errors='replace')
            
            # Remove control characters that break JSON parsing
            # Option C: free the original decoded string immediately so both
            # full-file strings never coexist in memory at once.
            har_text_clean = re.sub(r'[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f]', '', har_text)
            del har_text  # Option C: release ~file_size MB here

            # Try standard JSON parsing first
            repair_used = False
            repair_stats = None
            
            try:
                har_data = json.loads(har_text_clean)
                
                # Validate HAR structure
                if 'log' not in har_data or 'entries' not in har_data['log']:
                    raise ValueError('Invalid HAR file structure - missing log.entries')

                # Option B: strip response body text from parsed dict.
                # O(n entries) dict walk — much faster than pre-parse string manipulation.
                strip_response_bodies(har_data)
                del har_text_clean  # string no longer needed
                
            except (json.JSONDecodeError, ValueError) as e:
                # Standard parsing failed - use resilient parser
                print(f"Standard parsing failed: {e}")
                
                try:
                    entries, repair_stats = resilient_parse_har(har_text_clean)
                    
                    if not entries:
                        raise Exception("Resilient parser could not extract any valid entries")
                    
                    # Build a valid HAR structure
                    har_data = {
                        'log': {
                            'version': '1.2',
                            'creator': {
                                'name': 'HAR Analyzer with Repair',
                                'version': '1.0'
                            },
                            'entries': entries
                        }
                    }
                    
                    repair_used = True
                    
                except Exception as repair_error:
                    # Even resilient parsing failed
                    error_msg = (
                        f'HAR file is severely corrupted and could not be repaired. '
                        f'Error: {str(repair_error)}. '
                        f'Try re-exporting the HAR file from your browser.'
                    )
                    return jsonify({'error': error_msg}), 400
        
        except Exception as e:
            return jsonify({'error': f'Error reading file: {str(e)}'}), 400
        
        # Analyze the HAR data (whether from standard or resilient parsing)
        results = analyze_har_simple(har_data)
        
        # Add repair information to results
        if repair_used:
            results['repair_used'] = True
            results['repair_stats'] = repair_stats
            
            # HYBRID APPROACH: Always run plaintext scan when file was repaired
            # This supplements structured parsing with plaintext extraction
            print("File was repaired - running supplemental plaintext scan...")
            
            try:
                first_party_domain = results.get('first_party', '')
                plaintext_pii = analyze_har_as_plaintext(har_text_clean, first_party_domain)
                
                if plaintext_pii['pii_count'] > 0:
                    # Merge plaintext PII with structured parsing results
                    existing_pii = results.get('first_party_pii', {})
                    existing_items = existing_pii.get('pii_items', [])
                    plaintext_items = plaintext_pii.get('pii_items', [])
                    
                    # Combine and deduplicate
                    all_pii = existing_items + plaintext_items
                    
                    # Deduplicate by type:value
                    unique_pii = {}
                    for pii in all_pii:
                        key = f"{pii['type']}:{pii['value']}"
                        if key not in unique_pii:
                            unique_pii[key] = pii
                    
                    combined_items = list(unique_pii.values())
                    
                    # Update results with combined data
                    results['first_party_pii'] = {
                        'pii_items': combined_items,
                        'pii_count': len(combined_items),
                        'post_count': existing_pii.get('post_count', 0),
                        'method': 'hybrid' if existing_items else 'plaintext_fallback',
                        'structured_count': len(existing_items),
                        'plaintext_count': len(plaintext_items),
                        'note': f'Combined: {len(existing_items)} from parsed entries + {len(plaintext_items)} from plaintext scan'
                    }
                    
                    results['plaintext_supplement_used'] = True
                    print(f"✅ Hybrid scan: {len(existing_items)} structured + {len(plaintext_items)} plaintext = {len(combined_items)} total PII")
                else:
                    results['plaintext_supplement_used'] = False
            except Exception as e:
                print(f"Plaintext supplement error: {e}")
                results['plaintext_supplement_used'] = False
        else:
            results['repair_used'] = False
            results['plaintext_supplement_used'] = False
        
        return jsonify(results)
    
    except Exception as e:
        print(f"Error analyzing HAR: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Error analyzing file: {str(e)}'}), 500



def compute_risk_score(results):
    """
    Compute a 0-100 privacy risk score using weighted sub-scores.

    Each signal is scored 0-100 on its own severity scale, then
    combined as a weighted average. This ensures even a single
    plaintext PII violation produces a meaningfully high score,
    rather than scoring against a theoretical maximum that real
    files almost never reach.

    Weights:
      40%  Plaintext PII to third parties  (most severe)
      20%  Hashed PII transmissions
      15%  Damages magnitude
      15%  Vendor exposure breadth
      10%  Aggravating factors (LeadID + GET with PII)

    Sub-score scales:
      Plaintext: 0=0, 1=72, 2=85, 3+=100
      Hashed:    0=0, 1=55, 2=75, 3+=100
      Damages:   $0=0, $5K=40, $10K=60, $25K=80, $40K+=100
      Vendors:   0=0, 1=45, 2=75, 3+=100
      Aggrav:    0 factors=0, 1=55, 2=100 (LeadID counts, GET PII counts)

    Grade thresholds:
      Critical  = any plaintext PII present, OR score >= 75
      High      = any hashed PII present,    OR score >= 50
      Elevated  = score >= 25
      Lower     = score <  25
    """
    vendors = results.get('vendors', {})

    # --- Deduplicate by type+value to avoid counting repeated requests ---
    seen_plain, seen_hashed, seen_dmg = set(), set(), set()
    plaintext_pii_items, hashed_pii_items = [], []
    total_damages = 0

    for v in vendors.values():
        for p in v.get('pii', []):
            key = f"{p.get('type','')}:{p.get('value','')}"
            is_hashed = p.get('type', '').startswith('Hashed')
            if is_hashed:
                if key not in seen_hashed:
                    seen_hashed.add(key)
                    hashed_pii_items.append(p)
            else:
                if key not in seen_plain:
                    seen_plain.add(key)
                    plaintext_pii_items.append(p)
            if key not in seen_dmg:
                seen_dmg.add(key)
                total_damages += p.get('legal_context', {}).get('estimated_damages', 0)

    vendors_with_pii = [v for v in vendors.values() if v.get('pii_count', 0) > 0]
    leadid_present   = results.get('leadid_detected', False)
    get_with_pii     = any(
        p.get('request_details', {}).get('method') == 'GET'
        for v in vendors.values()
        for p in v.get('pii', [])
    )

    # --- Sub-scores (0-100 each) ---
    n_plain  = len(plaintext_pii_items)
    n_hashed = len(hashed_pii_items)
    n_vendor = len(vendors_with_pii)
    n_aggrav = (1 if leadid_present else 0) + (1 if get_with_pii else 0)

    def _plain_sub(n):
        if n == 0: return 0
        if n == 1: return 72
        if n == 2: return 85
        return min(100, 85 + (n - 2) * 5)

    def _hashed_sub(n):
        if n == 0: return 0
        if n == 1: return 55
        if n == 2: return 75
        return min(100, 75 + (n - 2) * 10)

    def _damage_sub(d):
        if d == 0:      return 0
        if d <= 5000:   return 40
        if d <= 10000:  return 60
        if d <= 25000:  return 80
        return min(100, int((d / 40000) * 100))

    def _vendor_sub(n):
        if n == 0: return 0
        if n == 1: return 45
        if n == 2: return 75
        return min(100, 75 + (n - 2) * 10)

    def _aggrav_sub(n):
        return [0, 55, 100][min(n, 2)]

    sp = _plain_sub(n_plain)
    sh = _hashed_sub(n_hashed)
    sd = _damage_sub(total_damages)
    sv = _vendor_sub(n_vendor)
    sa = _aggrav_sub(n_aggrav)

    total_score = round(sp * 0.40 + sh * 0.20 + sd * 0.15 + sv * 0.15 + sa * 0.10)

    # --- Grade ---
    if plaintext_pii_items or total_score >= 75:
        grade, grade_label = 'critical', 'Critical Risk'
    elif hashed_pii_items or total_score >= 50:
        grade, grade_label = 'high', 'High Risk'
    elif total_score >= 25:
        grade, grade_label = 'elevated', 'Elevated Risk'
    else:
        grade, grade_label = 'lower', 'Lower Risk'

    # --- Top violations ---
    top_violations = []
    if plaintext_pii_items:
        unique_types = list(dict.fromkeys(p['type'] for p in plaintext_pii_items))
        top_violations.append(
            f"{n_plain} plaintext PII item{'' if n_plain == 1 else 's'} "
            f"sent to third parties ({', '.join(unique_types[:2])})"
        )
    if hashed_pii_items:
        top_violations.append(
            f"{n_hashed} unique hashed PII transmission{'' if n_hashed == 1 else 's'}"
        )
    if leadid_present:
        top_violations.append("LeadID/Jornaya intercepts form fields in real time")
    if get_with_pii:
        top_violations.append("PII exposed in GET request URLs (logged by servers)")
    if vendors_with_pii and not top_violations:
        names = [v['name'] for v in vendors_with_pii]
        top_violations.append(f"Vendors receiving data: {', '.join(names)}")

    return {
        'score':             total_score,
        'grade':             grade,
        'grade_label':       grade_label,
        'estimated_damages': total_damages,
        'top_violations':    top_violations[:3],
        'breakdown': {
            'plaintext': sp,
            'hashed':    sh,
            'damages':   sd,
            'vendors':   sv,
            'aggravating': sa,
        }
    }

@app.route('/analyze-bulk', methods=['POST'])
def analyze_bulk():
    """
    Sequential bulk analysis endpoint using Server-Sent Events (SSE).

    Memory strategy — save uploads to temp files immediately, then process
    one at a time from disk. This avoids holding all file contents in RAM
    simultaneously, which was the cause of OOM crashes on Render free tier.

    Previous approach: buffer all files as bytes in memory before streaming.
    Problem: decoding a 99MB file to a Python str (which uses 2x memory)
    while 4 other files' bytes are still in RAM spiked to 641MB+.

    Current approach:
      1. Stream each upload to a temp file on disk (64KB chunks, ~0 RAM)
      2. SSE generator opens each temp file one at a time, processes it,
         then deletes the temp file before moving to the next.
      3. Peak RAM = baseline + single file processing (~180MB for 5x100MB)
    """
    import tempfile, shutil

    MAX_FILES     = 5
    MAX_SIZE_BYTES = 100 * 1024 * 1024  # 100MB per file

    files = request.files.getlist('files')

    if not files or len(files) == 0:
        return jsonify({'error': 'No files uploaded'}), 400

    if len(files) > MAX_FILES:
        return jsonify({'error': f'Maximum {MAX_FILES} files allowed'}), 400

    # Phase 1: Stream each upload to a temp file — no full-file buffer in RAM
    temp_files = []   # list of (original_filename, temp_path, file_size)
    for f in files:
        fname = f.filename or 'unknown.har'
        tmp   = tempfile.NamedTemporaryFile(delete=False, suffix='.har')
        size  = 0
        try:
            for chunk in iter(lambda: f.stream.read(65536), b''):
                tmp.write(chunk)
                size += len(chunk)
        finally:
            tmp.close()
        temp_files.append((fname, tmp.name, size))

    def generate(temp_files):
        total     = len(temp_files)
        summaries = []

        for idx, (filename, tmp_path, file_size) in enumerate(temp_files):

            # Emit processing event immediately
            yield f"data: {json.dumps({'event': 'processing', 'index': idx, 'filename': filename, 'current': idx + 1, 'total': total})}\n\n"

            # --- Validation ---
            if not filename.endswith('.har'):
                result = {'event': 'file_done', 'index': idx, 'filename': filename,
                          'status': 'error', 'error': 'Not a .har file',
                          'current': idx + 1, 'total': total}
                summaries.append(result)
                os.unlink(tmp_path)
                yield f"data: {json.dumps(result)}\n\n"
                continue

            if file_size > MAX_SIZE_BYTES:
                size_mb = file_size / (1024 * 1024)
                result = {'event': 'file_done', 'index': idx, 'filename': filename,
                          'status': 'error', 'error': f'File too large ({size_mb:.0f}MB — max 100MB)',
                          'current': idx + 1, 'total': total}
                summaries.append(result)
                os.unlink(tmp_path)
                yield f"data: {json.dumps(result)}\n\n"
                continue

            # --- Read from disk one at a time ---
            repair_used = False
            try:
                try:
                    with open(tmp_path, 'r', encoding='utf-8', errors='replace') as fh:
                        har_text = fh.read()
                except Exception as e:
                    raise Exception(f'Could not read file: {str(e)}')
                finally:
                    os.unlink(tmp_path)  # delete temp file immediately after reading

                # Option C: clean then del original string
                har_text_clean = re.sub(r'[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f]', '', har_text)
                del har_text

            except Exception as e:
                result = {'event': 'file_done', 'index': idx, 'filename': filename,
                          'status': 'error', 'error': str(e),
                          'current': idx + 1, 'total': total}
                summaries.append(result)
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass
                yield f"data: {json.dumps(result)}\n\n"
                continue

            # --- Parse ---
            try:
                try:
                    har_data = json.loads(har_text_clean)
                    if 'log' not in har_data or 'entries' not in har_data['log']:
                        raise ValueError('Invalid HAR structure')
                except (json.JSONDecodeError, ValueError):
                    entries, _ = resilient_parse_har(har_text_clean)
                    if not entries:
                        raise Exception('No valid entries found')
                    har_data = {'log': {'version': '1.2', 'creator': {'name': 'Bulk Analyzer'}, 'entries': entries}}
                    repair_used = True

                # Option B: strip response bodies in-place after parse
                strip_response_bodies(har_data)
                del har_text_clean

            except Exception as e:
                result = {'event': 'file_done', 'index': idx, 'filename': filename,
                          'status': 'error', 'error': f'Parse failed: {str(e)}',
                          'current': idx + 1, 'total': total}
                summaries.append(result)
                try:
                    del har_text_clean
                except Exception:
                    pass
                yield f"data: {json.dumps(result)}\n\n"
                continue

            # --- Analyze ---
            try:
                results = analyze_har_simple(har_data)  # dels har_data internally (Option D)

                # Plaintext supplement for repaired files
                if repair_used:
                    try:
                        first_party_domain = results.get('first_party', '')
                        # Re-read from temp is not possible (deleted), skip plaintext supplement
                        # for repaired files in bulk mode to avoid re-reading
                    except Exception:
                        pass

                total_vendor_pii = sum(v.get('pii_count', 0) for v in results.get('vendors', {}).values())
                first_party_count = results.get('first_party_pii', {}).get('pii_count', 0)
                vendors_with_pii = [v['name'] for v in results.get('vendors', {}).values() if v.get('pii_count', 0) > 0]

                risk = compute_risk_score(results)

                summary = {
                    'event':             'file_done',
                    'index':             idx,
                    'filename':          filename,
                    'status':            'complete',
                    'domain':            results.get('first_party', 'Unknown'),
                    'total_entries':     results.get('total_requests', 0),
                    'vendors_detected':  results.get('vendors_detected', 0),
                    'vendors_with_pii':  vendors_with_pii,
                    'vendor_pii_count':  total_vendor_pii,
                    'first_party_pii_count': first_party_count,
                    'leadid_detected':   results.get('leadid_detected', False),
                    'repair_used':       repair_used,
                    'current':           idx + 1,
                    'total':             total,
                    'score':             risk['score'],
                    'grade':             risk['grade'],
                    'grade_label':       risk['grade_label'],
                    'estimated_damages': risk['estimated_damages'],
                    'top_violations':    risk['top_violations'],
                    'breakdown':         risk['breakdown'],
                }
                summaries.append(summary)

            except Exception as e:
                summary = {'event': 'file_done', 'index': idx, 'filename': filename,
                           'status': 'error', 'error': f'Analysis failed: {str(e)}',
                           'current': idx + 1, 'total': total}
                summaries.append(summary)
            finally:
                try:
                    del results
                except Exception:
                    pass

            yield f"data: {json.dumps(summary)}\n\n"

        # All done
        yield f"data: {json.dumps({'event': 'all_done', 'files_processed': len(summaries), 'summaries': summaries})}\n\n"

    return app.response_class(
        generate(temp_files),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
        }
    )

if __name__ == '__main__':
    # This file should be run via app.py
    # For direct execution during development:
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)


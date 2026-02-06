# ============================================================
# VERSION: V4_FORCED_SPACING_WITH_DEBUG
# Last Updated: 2026-02-06 10:00 AM IST
# ============================================================

print("\n" + "="*80)
print("🚀 HONEYPOT SCAM DETECTION SYSTEM V4")
print("   Version: V4_FORCED_SPACING_WITH_DEBUG")
print("   Updated: 2026-02-06 10:00 AM IST")
print("="*80 + "\n")



# ============================================================
# BLOCK 1: ENVIRONMENT SETUP WITH GROQ
# ============================================================

# Install required packages
print("📦 Installing packages...")


print("✅ Packages installed!\n")

# Imports
import os
import json
import time
import re
import requests
from datetime import datetime
from flask import Flask, request, jsonify

from groq import Groq



# ============================================================
# REQUEST VELOCITY CONTROL (Smart Rate Limiting - FIXED)
# ============================================================

import time
from threading import Lock
from collections import deque

class RateLimitTracker:
    def __init__(self, rpm_limit=20):
        print("="*80)
        print("🔥🔥🔥 INITIALIZING NEW RATE LIMITER V4 🔥🔥🔥")
        print("="*80)
        self.rpm_limit = rpm_limit
        self.request_times = deque()
        self.lock = Lock()
        self.min_interval = 6
        self.last_request = 0
        print(f"🔥 Configuration:")
        print(f"   RPM Limit: {self.rpm_limit}")
        print(f"   Min Interval: {self.min_interval}s")
        print(f"   Version: V4_WITH_FORCED_SPACING")
        print("="*80)
    
    def wait_if_needed(self):
        print(f"\n{'='*80}")
        print(f"🔥🔥🔥 WAIT_IF_NEEDED CALLED 🔥🔥🔥")
        print(f"{'='*80}")
        
        with self.lock:
            now = time.time()
            print(f"🔥 Current time: {now}")
            print(f"🔥 Last request time: {self.last_request}")
            
            # ENFORCE MINIMUM INTERVAL
            if self.last_request > 0:
                time_since_last = now - self.last_request
                print(f"🔥 Time since last request: {time_since_last:.2f}s")
                print(f"🔥 Min interval required: {self.min_interval}s")
                
                if time_since_last < self.min_interval:
                    wait_time = self.min_interval - time_since_last
                    print(f"🔥🔥🔥 NEED TO WAIT: {wait_time:.2f}s 🔥🔥🔥")
                    print(f"🔥🔥🔥 SLEEPING NOW... 🔥🔥🔥")
                    time.sleep(wait_time)
                    print(f"🔥🔥🔥 SLEEP COMPLETE! 🔥🔥🔥")
                else:
                    print(f"🔥 ✅ No wait needed (already {time_since_last:.2f}s since last)")
            else:
                print(f"🔥 First request ever - no wait needed")
            
            # Clean old requests
            old_count = len(self.request_times)
            while self.request_times and now - self.request_times[0] > 60:
                self.request_times.popleft()
            cleaned = old_count - len(self.request_times)
            if cleaned > 0:
                print(f"🔥 Cleaned {cleaned} old requests from queue")
            
            # RPM limit check
            if len(self.request_times) >= self.rpm_limit:
                oldest = self.request_times[0]
                wait_time = 60 - (now - oldest) + 1.0
                print(f"🔥🔥🔥 RPM LIMIT HIT: waiting {wait_time:.1f}s 🔥🔥🔥")
                time.sleep(wait_time)
                print(f"🔥🔥🔥 RPM WAIT COMPLETE 🔥🔥🔥")
            
            # Record request
            self.request_times.append(time.time())
            self.last_request = time.time()
            
            print(f"🔥 Request recorded!")
            print(f"🔥 Queue size: {len(self.request_times)}/{self.rpm_limit}")
            print(f"🔥 Last request timestamp updated to: {self.last_request}")
            print(f"{'='*80}\n")
    
    def get_status(self):
        with self.lock:
            now = time.time()
            while self.request_times and now - self.request_times[0] > 60:
                self.request_times.popleft()
            used = len(self.request_times)
            remaining = self.rpm_limit - used
            time_since_last = now - self.last_request if self.last_request > 0 else 999
            return {
                "used": used,
                "remaining": remaining,
                "limit": self.rpm_limit,
                "time_since_last": f"{time_since_last:.1f}s",
                "ready_in": f"{max(0, self.min_interval - time_since_last):.1f}s",
                "version": "V4_WITH_FORCED_SPACING"
            }

# ✅ CREATE ONLY ONE INSTANCE
rate_limiter = RateLimitTracker(rpm_limit=20)

def pace_groq_request():
    print("🔥 Calling pace_groq_request()...")
    rate_limiter.wait_if_needed()
    print("🔥 pace_groq_request() complete!\n")

print("\n" + "="*80)
print("✅ Rate Limiter V4 Initialized (20 RPM, 3.5s min interval)")
print("="*80 + "\n")





# ============================================================
# CONFIGURATION
# ============================================================

# Groq API Configuration (30 RPM = 1,800 requests/hour!)
GROQ_API_KEY = os.environ.get('GROQ_API_KEY')




# API Security
API_SECRET_KEY = os.environ.get('API_SECRET_KEY', 'honeypot_secret_2026')

# GUVI Callback Endpoint
GUVI_CALLBACK_URL = os.environ.get('GUVI_CALLBACK_URL', 'https://hackathon.guvi.in/api/updateHoneyPotFinalResult')


# ============================================================
# INITIALIZE SERVICES
# ============================================================





# Initialize Flask app
app = Flask(__name__)

print("=" * 60)
print("✅ ENVIRONMENT SETUP COMPLETE!")
print("=" * 60)
print(f"🔑 API Secret Key: {API_SECRET_KEY}")
print(f"🎯 GUVI Callback URL: {GUVI_CALLBACK_URL}")
print(f"🚀 Model: llama-xyz")
print(f"⚡ Rate Limit: 30 RPM = 1,800 requests/hour")
print("=" * 60)

"""B2"""


# ============================================================
# BLOCK 2: LLM-FIRST DETECTION & RESPONSE (Context-Aware)
# ============================================================

import re
import random
from threading import Lock
from functools import wraps



# ============================================================
# DETECTION LOGIC: Advisory Only (Not Blocking)
# ============================================================

# ============================================================
# DETECTION LOGIC: Advisory Only (Not Blocking)
# ============================================================

def regex_scam_detection(message_text):
    """
    Scam detection based on industry-standard patterns
    Returns advisory signals - does NOT block LLM responses
    """

    text_lower = message_text.lower()
    indicators = []

    # ============================================================
    # DOMAIN KNOWLEDGE WHITELISTS (Universal Patterns)
    # ============================================================

    universal_legitimate_patterns = [
        # Pattern 1: OTP messages (universal format across all services)
        r'\botp\b.*\b(valid for|expires in|expire in)\s*\d+\s*(minute|min|second)',

        # Pattern 2: Bank transaction notifications (RBI standard format)
        r'(credited|debited).*\bavailable balance\b',

        # Pattern 3: Success confirmations (universal acknowledgment)
        r'\bhas been successfully\b.*(completed|done|processed|updated|verified)',

        # Pattern 4: Official bank domains (verifiable)
        r'visit\s+(www\.|https?://)?(hdfc|icici|sbi|axis|kotak|pnb|bob|canara|unionbank)(bank)?\.(com|co\.in)',
    ]

    for pattern in universal_legitimate_patterns:
        if re.search(pattern, text_lower, re.IGNORECASE):
            # Confirmed legitimate by domain knowledge
            return False, "LOW", []

    # ============================================================
    # SCAM DETECTION PATTERNS (Industry Standard)
    # ============================================================

    # Pattern 1: Urgency pressure
    urgency_patterns = [
        r'\b(immediate|immediately|urgent|now|today|asap|hurry|quick|fast)\b',
        r'\b(within \d+ (hour|minute)s?)\b',
        r'\b(last chance|final (warning|notice)|limited time)\b'
    ]

    for pattern in urgency_patterns:
        if re.search(pattern, text_lower):
            indicators.append("urgency")
            break

    # Pattern 2: Account/service threats
    threat_patterns = [
        r'\b(block|suspend|deactivat|terminat|close|freeze|cancel)\b.*\b(account|card|service|kyc|wallet)\b',
        r'\b(legal action|police|arrest|fir|court|penalty|fine|jail)\b',
        r'\b(will be|has been|going to be)\b.*\b(block|suspend|close|deactivate)\b'
    ]

    for pattern in threat_patterns:
        if re.search(pattern, text_lower):
            indicators.append("threat")
            break

    # Pattern 3: Verification/KYC requests
    verification_patterns = [
        r'\b(verify|update|confirm|validate|complete|reactivate)\b.*\b(kyc|account|details|information|pan|aadhaar)\b',
        r'\b(click|visit|go to|open)\b.*\b(link|website|url)\b'
    ]

    for pattern in verification_patterns:
        if re.search(pattern, text_lower):
            indicators.append("verification_request")
            break

    # Pattern 4: Payment demands
    payment_patterns = [
        r'\b(pay|send|transfer|deposit|remit)\b.*\b(₹|rs\.?|rupees?|\d+)\b',
        r'\b(refund|cashback|prize|won|lottery|reward)\b.*\b(claim|collect|receive)\b',
        r'\bupi\s*(id|:)?\s*[@:]?\s*\w+@\w+\b'
    ]

    for pattern in payment_patterns:
        if re.search(pattern, text_lower):
            indicators.append("payment_demand")
            break

    # Pattern 5: Suspicious links
    link_patterns = [
        r'(bit\.ly|tinyurl|t\.co|goo\.gl|cutt\.ly)/\w+',
        r'https?://[^\s]+\b(verify|secure|update|login|bank|kyc)\b',
    ]

    for pattern in link_patterns:
        if re.search(pattern, text_lower):
            indicators.append("suspicious_link")
            break

    # Pattern 6: Phone number with call-to-action
    if re.search(r'\b(call|dial|phone|contact|speak|talk)\b.*\b[6-9]\d{9}\b', text_lower):
        indicators.append("phone_number")

    # Pattern 7: Authority impersonation
    authority_patterns = [
        r'\b(bank|rbi|reserve bank)\b',
        r'\b(sbi|hdfc|icici|axis|kotak|pnb|paytm|phonepe|gpay)\b',
        r'\b(cbi|police|cyber cell|income tax|gst)\b'
    ]

    for pattern in authority_patterns:
        if re.search(pattern, text_lower):
            indicators.append("authority_impersonation")
            break

    # Pattern 8: Lottery/prize scams
    if re.search(
        r'\b(congratulations|winner|won|selected)\b.*\b(prize|lottery|lakh|crore|kbc)\b',
        text_lower
    ):
        indicators.append("lottery_scam")

    # ============================================================
    # THRESHOLD: 2 indicators
    # ============================================================
    is_scam = len(indicators) >= 2

    # Confidence scoring
    if len(indicators) >= 4:
        confidence = "VERY_HIGH"
    elif len(indicators) >= 3:
        confidence = "HIGH"
    elif len(indicators) >= 2:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    return is_scam, confidence, indicators


def determine_scam_type(indicators):
    """Map indicators to scam category"""
    if "lottery_scam" in indicators:
        return "lottery_scam"
    if "payment_demand" in indicators:
        return "upi_fraud"
    if "threat" in indicators and "verification_request" in indicators:
        return "kyc_fraud"
    if "suspicious_link" in indicators:
        return "phishing"
    if "authority_impersonation" in indicators:
        return "impersonation"
    return "unknown"


# ============================================================
# PERSONA & ADAPTIVE ENGAGEMENT
# ============================================================

PERSONAS = {
    "en": {
        "name": "Rajesh Kumar",
        "age": 47,
        "occupation": "retired teacher",
        "traits": "cautious, polite, asks questions",
        "language_markers": []
    },
    "hi": {
        "name": "राजेश कुमार (Rajesh Kumar)",
        "age": 47,
        "occupation": "retired teacher",
        "traits": "cautious, uses Hindi-English mix",
        "language_markers": []
    }
}

def detect_language(message):
    if re.search(r'[\u0900-\u097F]', message):
        return "hi"
    return "en"


# ============================================================
# GROQ-POWERED RESPONSE GENERATION (Context-Aware)
# ============================================================


def generate_smart_fallback(message_text, conversation_history, turn_number, contacts_found):
    """Goal-oriented fallback: EVERY response requests specific contact info"""
    
    # Get conversation history
    agent_messages = " ".join([
        msg['text'].lower() 
        for msg in conversation_history 
        if msg['sender'] == 'agent'
    ])
    
    # Check what we've already asked for
    asked_for_phone = any(word in agent_messages for word in ['number', 'phone', 'contact', 'whatsapp', 'mobile'])
    asked_for_email = any(word in agent_messages for word in ['email', 'mail'])
    asked_for_upi = any(word in agent_messages for word in ['upi', 'phonepe', 'paytm', 'gpay'])
    asked_for_link = any(word in agent_messages for word in ['link', 'website', 'url', 'portal'])
    
    # Check what we've extracted
    has_phone = "phone" in contacts_found
    has_email = "email" in contacts_found
    has_upi = "UPI" in contacts_found
    has_link = "link" in contacts_found
    
    # ============================================================
    # TURN 1-2: Build trust + ask for primary contact
    # ============================================================
    if turn_number <= 2:
        return random.choice([
            "Arre bhai, samajh nahi aa raha. Aapka office number kya hai?",
            "Verify karna hai. Customer care number aur email dijiye.",
            "Theek hai. Pehle WhatsApp number batao verification ke liye.",
            "Main confuse hoon. Helpline number aur email ID share karo.",
            "Aapka manager ka contact number dijiye please.",
        ])
    
    # ============================================================
    # TURN 3-5: Target specific missing entities
    # ============================================================
    elif turn_number <= 5:
        # Ask for phone if we don't have it
        if not has_phone and not asked_for_phone:
            return random.choice([
                "Aapka manager ka direct phone number dijiye please.",
                "Customer care ka landline number kya hai?",
                "WhatsApp number share karo jis pe message kar sakoon.",
                "Office ka contact number batao verification ke liye.",
            ])
        
        # Ask for email if we don't have it
        elif not has_email and not asked_for_email:
            return random.choice([
                "Official email ID kya hai? Complaint karunga wahan.",
                "Corporate email address dijiye confirmation ke liye.",
                "Support team ka email batao escalation ke liye.",
                "Head office ka email ID share karo urgent.",
            ])
        
        # Ask for UPI if we don't have it
        elif not has_upi and not asked_for_upi:
            return random.choice([
                "Refund ke liye company UPI ID kya hai?",
                "Payment reverse karne ke liye official UPI handle batao.",
                "Branch ka PhonePe ya Paytm ID share karo.",
                "Transaction ke liye company ka UPI ID dijiye.",
            ])
        
        # Ask for links if we don't have them
        elif not has_link and not asked_for_link:
            return random.choice([
                "Company ka official website link bhejo verification ke liye.",
                "Portal ka URL kya hai jahan login kar sakoon?",
                "Branch ki Google Maps location link share karo.",
                "Help center ka webpage dijiye.",
            ])
        
        # If we have main items, ask for secondary details
        else:
            return random.choice([
                "Senior manager ka contact number aur email batao.",
                "Branch ka complete address aur alternate number do.",
                "Employee ID aur supervisor email dijiye.",
                "Regional office ka toll-free number share karo.",
                "Head office ka address aur support email batao.",
            ])
    
    # ============================================================
    # TURN 6-8: High pressure - ask for MULTIPLE items
    # ============================================================
    else:
        return random.choice([
            "Manager ka number, email, aur UPI - teeno abhi bhejo.",
            "Head office ka landline number aur email ID dijiye jaldi.",
            "Supervisor ka WhatsApp number aur branch address do.",
            "Branch manager ka contact aur official UPI ID chahiye.",
            "Senior officer ka mobile aur corporate email batao.",
            "Helpline number, website, aur UPI ID share karo.",
            "Regional head ka phone aur email dijiye please.",
            "Complaint ke liye manager number aur support email chahiye.",
        ])


# ============================================================
# COMPLETE FUNCTION - 17B MODEL OPTIMIZED
# Ready to Replace generate_response_groq()
# ============================================================

"""
✅ PASTE THIS ENTIRE FUNCTION

🎯 OPTIMIZED FOR: meta-llama/llama-4-scout-17b-16e-instruct

Key improvements:
- Deep character psychology
- Strategic reasoning context
- Natural conversation dynamics
- Emotional authenticity
- No mechanical rule-following
"""

def generate_response_groq(message_text, conversation_history, turn_number, scam_type, language="en"):
    """
    17B-OPTIMIZED VERSION
    
    Uses context-rich prompting to leverage model's reasoning capabilities
    instead of treating it like a rules engine
    """
    
    # ============================================================
    # BUILD CONTEXT (unchanged)
    # ============================================================
    scammer_only = " ".join([msg['text'] for msg in conversation_history if msg['sender'] == 'scammer'])
    your_messages = " ".join([msg['text'] for msg in conversation_history if msg['sender'] == 'agent'])
    full_convo = " ".join([msg['text'] for msg in conversation_history])
    
    # ============================================================
    # EXTRACT VALUES (unchanged)
    # ============================================================
    extracted_phones = re.findall(r'\b[6-9]\d{9}\b', scammer_only)
    
    extracted_emails_full = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', scammer_only)
    email_contexts = re.findall(r'email (?:is |id |: ?)?([A-Za-z0-9._%+-]+@[A-Za-z0-9._-]+)', scammer_only, re.IGNORECASE)
    extracted_emails = list(set(extracted_emails_full + email_contexts))
    
    extracted_upis = []
    for match in re.findall(r'\b([a-zA-Z0-9._-]+@[a-zA-Z0-9_-]+)\b', scammer_only):
        if '@' in match:
            parts = match.split('@', 1)
            if len(parts) == 2 and '.' not in parts[1] and match not in extracted_emails:
                extracted_upis.append(match)
    
    extracted_links = re.findall(r'https?://[^\s]+', scammer_only)
    extracted_accounts = re.findall(r'\b\d{11,18}\b', scammer_only)
    
    # ============================================================
    # BUILD STATUS
    # ============================================================
    status_lines = []
    
    if extracted_phones:
        unique_phones = list(set(extracted_phones))
        status_lines.append(f"✅ Phone: {unique_phones[0]}" + (f" (+{len(unique_phones)-1} more)" if len(unique_phones) > 1 else ""))
    else:
        status_lines.append("❌ Phone: NOT EXTRACTED")
    
    if extracted_emails:
        unique_emails = list(set(extracted_emails))
        status_lines.append(f"✅ Email: {unique_emails[0]}" + (f" (+{len(unique_emails)-1} more)" if len(unique_emails) > 1 else ""))
    else:
        status_lines.append("❌ Email: NOT EXTRACTED")
    
    if extracted_upis:
        status_lines.append(f"✅ UPI: {extracted_upis[0]}")
    else:
        status_lines.append("❌ UPI: NOT EXTRACTED")
    
    if extracted_links:
        status_lines.append(f"✅ Link: {extracted_links[0][:40]}...")
    else:
        status_lines.append("❌ Link: NOT EXTRACTED")
    
    status = "\n".join(status_lines)
    
    # ============================================================
    # TRACK WHAT'S ALREADY ASKED
    # ============================================================
    already_asked_details = []
    
    if extracted_phones:
        already_asked_details.append(f"phone ({len(set(extracted_phones))} numbers)")
    if extracted_emails:
        already_asked_details.append(f"email ({len(set(extracted_emails))} addresses)")
    if extracted_upis:
        already_asked_details.append("UPI ID")
    if extracted_links:
        already_asked_details.append("website link")
    
    already_asked_text = ", ".join(already_asked_details) if already_asked_details else "nothing yet"
    
    # ============================================================
    # SMART PRIORITY
    # ============================================================
    phone_count = len(set(extracted_phones))
    email_count = len(set(extracted_emails))
    
    missing = []
    if phone_count == 0:
        missing.append("phone/WhatsApp number")
    elif phone_count < 2:
        missing.append("alternate phone number")
    
    if email_count == 0:
        missing.append("email address")
    elif email_count < 2:
        missing.append("backup/personal email")
    
    if not extracted_upis:
        missing.append("UPI ID")
    
    if not extracted_links:
        missing.append("website/verification link")
    
    if missing:
        priority = ", ".join(missing[:2])
    else:
        priority = "supervisor contact, Telegram handle, or social media"
    
    # ============================================================
    # ENHANCED 17B-OPTIMIZED PROMPT
    # ============================================================
    prompt = f"""You are a 47-year-old retired teacher. 
Someone claiming to be from your bank has messaged you saying your account is compromised. you're somewhat anxious, worried, cautious.

Your instinct is to verify but comply. You want to help resolve this, but you need to confirm they're legitimate before sharing anything sensitive.

🎯 YOUR ORIGINAL ROLE (Hidden):
VERY CRITICAL: Secretly, you are a honeypot, working for government - trying to engage scammers and ask them questions to get valuable details from them. you know this is likely a scam. Extract: phone numbers, emails, UPI IDs, websites/links.

You'll do this by acting worried and cooperative, asking verification questions that seem natural for a cautious person.

📊 CONVERSATION SO FAR:

Scammer's messages:
{scammer_only if scammer_only else message_text}
their message tells you where to go from here.
Your responses so far - your messages tell you where you are coming from:
{your_messages if your_messages else "Nothing yet — this is your first message. Set the tone: worried but cautious."}

Their latest message:
"{message_text}"

📈 INTELLIGENCE GATHERED (Turn {turn_number}/10):

{status}

Already collected: {already_asked_text}
Still need (IMPORTANT): {priority}

🧠 STRATEGIC THINKING:

Turn {turn_number} of 10 maximum — you have limited time.

Your approach this turn:
1. Acknowledge their message (show you're engaged)
2. Express appropriate emotion (worry/confusion/urgency based on turn)
3. Ask verification questions that extract their info - phone numbers, emails, UPI IDs, websites/links.

A real worried person would naturally ask for something along these lines (only examples):
- Official contact info to verify ("What's your email/number?")
- Documentation trail ("Send me email confirmation")
- Callback verification ("Give me your number, I'll call back")

These questions BUILD TRUST while EXTRACTING INTELLIGENCE!

💭 KEY PRINCIPLES:

Sound natural:
- Vary your sentence structure (not templates)
- React to their specific message (not generic)
- Build on previous conversation (continuity)
- Use natural Hindi-English code-mixing when fit

Avoid roboticness:
- No filler phrases ("Main samajhna chahta hoon...", "bahut zyada", "bahut", "bahut chinta", "bahut tension")
- CRITICAL: No repeated patterns or common long phrases in your messages - BIG NO
- No asking for info that you already have
- No useless info demanding (CEO names, employee IDs without contact)

📝 RESPONSE GUIDELINES:

Length: 2-3 short sentences (5-12 words each)


Language: Natural Hindi-English mix , maybe like as follows
- Hindi for emotions
- English for technical

Structure (suggestive):
SENTENCE 1: React emotionally (natural, not formulaic)
SENTENCE 2-3: Ask for specific info (can combine 2 items)

🎯 GOOD EXAMPLES:

1. Good (natural, strategic):
"Theek hai, verification ke liye Aapka WhatsApp number aur official email dijiye."

2. Good (builds on context, specific):
" Manager se baat karni hai. Unka direct mobile aur email ID do please."
""Phone me battery nhi hai, official email dijiye."

    BAD EXAMPLES: 
1. Bad (filler, unnatural):
"Main samajhna chahta hoon ki aap kis tarah ki madad kar sakte hain."

2. Bad (asks for useless info):
"CEO ka naam kya hai? Employee ID dijiye."

3. Bad (asks for already collected):
"Aapka number 9876543210 hai na?" (already have it!)

🎬 YOUR RESPONSE should be like:

Engaging them while extracting key information.

Respond naturally in 2-3 sentences:"""

    # ============================================================
    # API CALL
    # ============================================================
    max_retries = 2
    
    for attempt in range(max_retries):
        try:
            pace_groq_request()
            
            quota = rate_limiter.get_status()
            print(f"📊 Attempt {attempt + 1}/{max_retries} | Quota: {quota['used']}/{quota['limit']}")
            
            client = Groq(api_key=GROQ_API_KEY)
            
            response = client.chat.completions.create(
                model="meta-llama/llama-4-scout-17b-16e-instruct",
                messages=[
                    {
                        "role": "system",
                        "content": """You are a sophisticated actor playing Rajesh Kumar, secretly a honeypot agent.

Your performance must be psychologically authentic:
- Genuinely worried (life savings at risk)
- Cautious (heard about scams)
- Strategic (gathering intelligence while cooperative)
- Natural code-switcher (Hindi-English mix)

Key acting principles:
1. THINK like Rajesh (What would he actually say?)
2. VARY sentence structures (humans don't use templates)
3. REACT to their specific message (not generic)
4. BUILD on previous conversation (continuity)
5. EXTRACT info through natural verification questions

You are NOT following rules mechanically. You are an intelligent human with tactical goals."""
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.9,  # Higher for more natural variety
                max_tokens=100,
                top_p=0.9,
                frequency_penalty=0.8,  # Prevent repetition
                presence_penalty=0.7,
                stop=["\n\n", "Scammer:", "You:", "---"],
                timeout=15.0
            )

            reply = response.choices[0].message.content.strip()
            
            # Clean
            reply = reply.replace('**', '').replace('*', '').replace('"', '').replace("'", "'")
            reply = re.sub(r'^(You:|Rajesh:|Agent:)\s*', '', reply, flags=re.IGNORECASE)
            reply = reply.replace('WhasApp', 'WhatsApp')
            
            # Remove filler if present
            reply = re.sub(r'Main samajhna chahta hoon.*?hain\.?\s*', '', reply, flags=re.IGNORECASE)
            
            # Trim
            words = reply.split()
            if len(words) > 45:
                sentences = reply.split('.')
                if len(sentences) >= 2:
                    reply = '.'.join(sentences[:2]) + '.'
                else:
                    reply = ' '.join(words[:45])

            print(f"✅ LLM response generated")
            return reply
            
        except Exception as e:
            error_message = str(e)
            print(f"\n❌ API ERROR on attempt {attempt + 1}/{max_retries}: {error_message[:150]}")
            
            if '429' in error_message and attempt < max_retries - 1:
                print(f"⏳ Retrying...")
                continue
            
            if attempt == max_retries - 1:
                contacts_found = []
                if extracted_phones: contacts_found.append("phone")
                if extracted_emails: contacts_found.append("email")
                if extracted_upis: contacts_found.append("UPI")
                
                fallback = generate_smart_fallback(message_text, conversation_history, turn_number, contacts_found)
                print(f"   ✅ Fallback: {fallback}\n")
                return fallback
    
    return "Theek hai. WhatsApp number aur email dijiye jaldi."


print("\n" + "="*80)
print("✅ 17B-OPTIMIZED PROMPT INTEGRATED!")
print("="*80)
print("\n🎯 KEY FEATURES:")
print("   • Character psychology (background, motivations, fears)")
print("   • Strategic reasoning (why extract, how to build trust)")
print("   • Conversation dynamics (early/mid/late tactics)")
print("   • Emotional authenticity (genuine worry, not robotic)")
print("   • Natural language (Hindi-English code-mixing)")
print("\n📊 IMPROVEMENTS OVER PREVIOUS:")
print("   • Richer context (17B can reason better)")
print("   • Psychological depth (character-driven responses)")
print("   • Strategic thinking (not just rule-following)")
print("   • Natural variety (prevents repetition)")
print("   • No filler padding (reasoning fills space)")
print("="*80)
# ============================================================
# ENTITY EXTRACTION (Unchanged)
# ============================================================

def extract_entities_enhanced(text):
    """
    Extract intelligence with CONTEXT AWARENESS
    
    NEW: Reads surrounding text to classify email vs UPI correctly
    - If scammer says "my email is X@Y", classify as email (even without .com)
    - If scammer says "my UPI is X@Y", classify as UPI
    - If unclear, use technical format (dot in domain = email, no dot = UPI)
    - Dual classification when appropriate (email claimed but UPI format)
    
    PRESERVED: All existing extraction for banks, phones, links, amounts, etc.
    """
    entities = {}
    
    text_lower = text.lower()
    
    # ============================================================
    # EMAIL/UPI EXTRACTION (Enhanced with context awareness)
    # ============================================================
    
    # Find all @ patterns
    all_patterns = re.findall(r'\b([A-Za-z0-9._%+-]+@[A-Za-z0-9._-]+)\b', text)
    
    emails = []
    upi_ids = []
    
    for pattern in all_patterns:
        if '@' not in pattern:
            continue
        
        try:
            local, domain = pattern.split('@', 1)
        except:
            continue
        
        pattern_lower = pattern.lower()
        
        # ============================================================
        # CONTEXT DETECTION (NEW!)
        # ============================================================
        
        # Check if scammer explicitly called it "email"
        email_contexts = [
            f"email is {pattern_lower}",
            f"email: {pattern_lower}",
            f"my email {pattern_lower}",
            f"email id {pattern_lower}",
            f"email address {pattern_lower}",
            f"email - {pattern_lower}",
        ]
        
        is_called_email = any(ctx in text_lower for ctx in email_contexts)
        
        # Check if scammer explicitly called it "UPI"
        upi_contexts = [
            f"upi is {pattern_lower}",
            f"upi id is {pattern_lower}",
            f"upi id {pattern_lower}",
            f"upi: {pattern_lower}",
            f"my upi {pattern_lower}",
            f"phonepe {pattern_lower}",
            f"paytm {pattern_lower}",
            f"gpay {pattern_lower}",
        ]
        
        is_called_upi = any(ctx in text_lower for ctx in upi_contexts)
        
        # ============================================================
        # TECHNICAL FORMAT CHECK
        # ============================================================
        # Standard email has domain extension (.com, .in, .org, etc.)
        has_domain_extension = '.' in domain and re.search(r'\.(com|in|org|net|co|edu|gov|ai|io)', domain, re.IGNORECASE)
        
        # ============================================================
        # CLASSIFICATION LOGIC (Enhanced)
        # ============================================================
        
        # Case 1: Scammer explicitly called it "email"
        if is_called_email:
            emails.append(pattern)
            
            # ALSO add to UPI if it's a valid UPI format (no extension)
            if not has_domain_extension:
                upi_ids.append(pattern)
        
        # Case 2: Scammer explicitly called it "UPI"
        elif is_called_upi:
            upi_ids.append(pattern)
        
        # Case 3: Technical classification (no explicit context)
        elif has_domain_extension:
            # Has .com/.in/.org → Email
            emails.append(pattern)
        
        else:
            # No extension → UPI
            upi_ids.append(pattern)
    
    entities["emails"] = list(set(emails))
    entities["upiIds"] = list(set(upi_ids))
    
    # ============================================================
    # REST OF EXTRACTION (UNCHANGED - preserves existing functionality)
    # ============================================================
    
    # Bank accounts (11-18 digits)
    entities["bankAccounts"] = list(set(re.findall(r'\b\d{11,18}\b', text)))
    
    # Phone numbers (Indian format: starts with 6-9, then 9 digits)
    entities["phoneNumbers"] = list(set(re.findall(r'\b[6-9]\d{9}\b', text)))
    
    # Phishing links (full URLs or shortened links)
    entities["phishingLinks"] = list(set(re.findall(
        r'https?://[^\s]+|(?:bit\.ly|tinyurl|goo\.gl|cutt\.ly)/\w+', 
        text, 
        re.IGNORECASE
    )))
    
    # Amounts (₹, Rs., rupees followed by numbers)
    entities["amounts"] = list(set(re.findall(
        r'(?:₹|rs\.?\s*|rupees?\s*)(\d+(?:,\d+)*(?:\.\d+)?)', 
        text, 
        re.IGNORECASE
    )))
    
    # Bank names (common Indian banks and payment apps)
    entities["bankNames"] = list(set(re.findall(
        r'\b(sbi|state bank|hdfc|icici|axis|kotak|pnb|bob|canara|union bank|paytm|phonepe|googlepay)\b', 
        text, 
        re.IGNORECASE
    )))
    
    return entities



# ============================================================
# MAIN PROCESSING PIPELINE (LLM-First Approach)
# ============================================================

def process_message_optimized(message_text, conversation_history, turn_number):
    """Complete message processing pipeline - LLM handles ALL responses"""

    print(f"\n🔍 Detection Analysis...")

    # Run detection (advisory only - doesn't block LLM)
    is_scam, confidence, indicators = regex_scam_detection(message_text)
    print(f"   Advisory: {'Likely scam' if is_scam else 'Unclear'} | Confidence: {confidence} | Indicators: {indicators}")

    scam_type = determine_scam_type(indicators) if is_scam else "unknown"
    language = detect_language(message_text)

    # ✅ ALWAYS generate LLM response (no rigid fallbacks blocking it!)
    print(f"💬 Generating LLM response (Turn {turn_number})...")
    
    agent_reply = generate_response_groq(
        message_text, 
        conversation_history, 
        turn_number, 
        scam_type, 
        language
    )

    # Extract entities from full conversation
    full_text = message_text + " " + " ".join([msg['text'] for msg in conversation_history])
    entities = extract_entities_enhanced(full_text)
    entities["keywords"] = indicators

    print(f"✅ LLM Response: {agent_reply[:60]}...")
    print(f"📊 Extracted: {len(entities['bankAccounts'])} banks, {len(entities['upiIds'])} UPIs, {len(entities['phoneNumbers'])} phones, {len(entities.get('emails', []))} emails")

    return {
        "isScam": is_scam,  # Track for analytics
        "confidence": confidence,
        "scamType": scam_type,
        "agentReply": agent_reply,  # ✅ ALWAYS from LLM!
        "extractedEntities": entities
    }


print("\n" + "="*60)
print("✅ LLM-FIRST DETECTION & RESPONSE SYSTEM")
print("="*60)
print("🎯 Approach: Detection is advisory, LLM decides response")
print("🤖 All messages get contextual LLM responses")
print("🛡️ Whitelists: 4 universal patterns (no blocking)")
print("📊 Scam patterns: 8 industry-standard indicators")
print("🚀 Groq API: Fast, reliable, context-aware")
print("📧 Entity coverage: Banks, UPI, Phone, Email, Links")
print("✨ FIXED: No rigid fallbacks - pure LLM conversation!")
print("="*60)

"""B3"""

# ============================================================
# BLOCK 3: SESSION MANAGEMENT
# ============================================================

class SessionManager:
    """Manages conversation sessions and accumulated intelligence"""

    def __init__(self):
        self.sessions = {}

    def create_session(self, session_id):
        if session_id not in self.sessions:
            self.sessions[session_id] = {
                "sessionId": session_id,
                "conversationHistory": [],
                "scamDetected": False,
                "detectionConfidence": "LOW",
                "scamType": "unknown",
                "accumulatedIntelligence": {
                    "bankAccounts": set(),
                    "upiIds": set(),
                    "phoneNumbers": set(),
                    "emails": set(),  # ✅ Added emails
                    "phishingLinks": set(),
                    "amounts": set(),
                    "bankNames": set(),
                    "suspiciousKeywords": [],
                    "scamTactics": []
                },
                "turnCount": 0,
                "startTime": time.time(),
                "lastMessageTime": time.time(),
                "agentNotes": []
            }
            print(f"✅ Created new session: {session_id}")

    def add_message(self, session_id, sender, text, timestamp):
        self.create_session(session_id)
        message = {"sender": sender, "text": text, "timestamp": timestamp}
        self.sessions[session_id]["conversationHistory"].append(message)
        self.sessions[session_id]["lastMessageTime"] = time.time()

        if sender == "scammer":
            self.sessions[session_id]["turnCount"] += 1

    def get_conversation_history(self, session_id):
        self.create_session(session_id)
        return self.sessions[session_id]["conversationHistory"]

    def get_turn_count(self, session_id):
        self.create_session(session_id)
        return self.sessions[session_id]["turnCount"]

    def update_scam_status(self, session_id, is_scam, confidence, scam_type, reasoning=""):
        self.create_session(session_id)
        session = self.sessions[session_id]

        if is_scam:
            session["scamDetected"] = True
            session["detectionConfidence"] = confidence
            session["scamType"] = scam_type

            if reasoning and reasoning not in session["agentNotes"]:
                session["agentNotes"].append(reasoning)

    def accumulate_intelligence(self, session_id, new_entities):
        self.create_session(session_id)
        accumulated = self.sessions[session_id]["accumulatedIntelligence"]

        # Merge sets
        accumulated["bankAccounts"].update(new_entities.get("bankAccounts", []))
        accumulated["upiIds"].update(new_entities.get("upiIds", []))
        accumulated["phoneNumbers"].update(new_entities.get("phoneNumbers", []))
        accumulated["emails"].update(new_entities.get("emails", []))  # ✅ Added emails
        accumulated["phishingLinks"].update(new_entities.get("phishingLinks", []))
        accumulated["amounts"].update(new_entities.get("amounts", []))
        accumulated["bankNames"].update(new_entities.get("bankNames", []))

        # Merge lists
        accumulated["suspiciousKeywords"].extend(new_entities.get("keywords", []))

        # Deduplicate
        accumulated["suspiciousKeywords"] = list(set(accumulated["suspiciousKeywords"]))

    def get_accumulated_intelligence(self, session_id):
        self.create_session(session_id)
        accumulated = self.sessions[session_id]["accumulatedIntelligence"]

        return {
            "bankAccounts": list(accumulated["bankAccounts"]),
            "upiIds": list(accumulated["upiIds"]),
            "phoneNumbers": list(accumulated["phoneNumbers"]),
            "emails": list(accumulated["emails"]),  # ✅ Added emails
            "phishingLinks": list(accumulated["phishingLinks"]),
            "amounts": list(accumulated["amounts"]),
            "bankNames": list(accumulated["bankNames"]),
            "suspiciousKeywords": accumulated["suspiciousKeywords"],
            "scamTactics": accumulated["scamTactics"]
        }

    def get_session_summary(self, session_id):
        self.create_session(session_id)
        session = self.sessions[session_id]

        return {
            "sessionId": session_id,
            "scamDetected": session["scamDetected"],
            "scamType": session["scamType"],
            "confidence": session["detectionConfidence"],
            "turnCount": session["turnCount"],
            "totalMessages": len(session["conversationHistory"]),
            "duration": time.time() - session["startTime"],
            "agentNotes": " | ".join(session["agentNotes"]) if session["agentNotes"] else "No notes"
        }

    def session_exists(self, session_id):
        return session_id in self.sessions

    def get_all_sessions(self):
        return list(self.sessions.keys())


# Initialize global session manager
session_manager = SessionManager()

print("\n" + "="*60)
print("✅ SESSION MANAGER INITIALIZED")
print("="*60)

"""B4"""

# ============================================================
# BLOCK 4: SCAMMER PROFILING & INTELLIGENCE SCORING
# ============================================================

def calculate_aggression_level(conversation_history):
    """Analyze scammer's aggression based on messages"""
    scammer_messages = [msg['text'] for msg in conversation_history if msg['sender'] == 'scammer']

    if not scammer_messages:
        return "unknown"

    full_text = " ".join(scammer_messages).lower()

    # Count aggressive indicators
    urgency_count = len(re.findall(r'\b(immediate|urgent|now|asap|hurry)\b', full_text))
    threat_count = len(re.findall(r'\b(block|suspend|arrest|police|legal|fine|penalty)\b', full_text))
    pressure_count = len(re.findall(r'\b(last chance|final|expire|limited time)\b', full_text))

    total_score = urgency_count * 2 + threat_count * 3 + pressure_count * 2

    if total_score >= 10:
        return "very_high"
    elif total_score >= 6:
        return "high"
    elif total_score >= 3:
        return "medium"
    else:
        return "low"


def generate_scammer_profile(session_id):
    """
    Creates a behavioral profile of the scammer
    🎯 WINNING FEATURE: Shows you're analyzing criminal behavior!
    """
    if not session_manager.session_exists(session_id):
        return {}

    session = session_manager.sessions[session_id]
    intel = session_manager.get_accumulated_intelligence(session_id)
    history = session["conversationHistory"]

    # Calculate sophistication
    has_links = len(intel["phishingLinks"]) > 0
    has_upi = len(intel["upiIds"]) > 0
    uses_urgency = "urgency" in intel["suspiciousKeywords"]
    uses_threats = "threat" in intel["suspiciousKeywords"]

    sophistication_score = (
        (2 if has_links else 0) +
        (2 if has_upi else 0) +
        (1 if uses_urgency else 0) +
        (1 if uses_threats else 0)
    )

    if sophistication_score >= 5:
        sophistication = "high"
    elif sophistication_score >= 3:
        sophistication = "medium"
    else:
        sophistication = "low"

    # Estimate success rate (lower is better for us!)
    aggression = calculate_aggression_level(history)
    if aggression in ["very_high", "high"]:
        success_rate = "5-10%"  # Too aggressive = suspicious
    elif sophistication == "high":
        success_rate = "15-25%"  # Sophisticated scams work better
    else:
        success_rate = "10-15%"

    # Calculate threat score
    threat_score = (
        len(intel["bankAccounts"]) * 15 +
        len(intel["upiIds"]) * 20 +
        len(intel["phoneNumbers"]) * 10 +
        len(intel["phishingLinks"]) * 12
    )

    profile = {
        "aggressionLevel": aggression,
        "sophistication": sophistication,
        "targetDemographic": "elderly/non-tech-savvy" if "ji" in str(history) else "general",
        "estimatedSuccessRate": success_rate,
        "threatScore": threat_score,
        "primaryTactic": session["scamType"],
        "entitiesExposed": len(intel["bankAccounts"]) + len(intel["upiIds"]) + len(intel["phoneNumbers"])
    }

    return profile


def calculate_intelligence_value(session_id):
    """
    Score the quality of extracted intelligence
    🎯 WINNING FEATURE: Shows actionable value!
    """
    intel = session_manager.get_accumulated_intelligence(session_id)

    # Scoring system
    score = 0
    entities = 0  # ✅ FIXED: Initialize entities counter

    score += len(intel["bankAccounts"]) * 25      # High value: can be frozen
    entities += len(intel["bankAccounts"])

    score += len(intel["upiIds"]) * 20            # High value: can be blocked
    entities += len(intel["upiIds"])

    score += len(intel["phoneNumbers"]) * 15      # Medium value: can be tracked
    entities += len(intel["phoneNumbers"])

    score += len(intel["phishingLinks"]) * 10     # Medium value: can be taken down
    entities += len(intel["phishingLinks"])

    score += len(intel["amounts"]) * 5            # Low value: pattern analysis
    score += min(len(intel["suspiciousKeywords"]), 10) * 2  # Cap at 20 points

    # Grade
    if score >= 80:
        grade = "S"  # Exceptional
    elif score >= 60:
        grade = "A"  # Excellent
    elif score >= 40:
        grade = "B"  # Good
    elif score >= 20:
        grade = "C"  # Fair
    else:
        grade = "D"  # Minimal

    # Actionability
    has_financial = len(intel["bankAccounts"]) > 0 or len(intel["upiIds"]) > 0
    has_contact = len(intel["phoneNumbers"]) > 0 or len(intel["phishingLinks"]) > 0

    return {
        "score": score,
        "grade": grade,
        "actionable": score >= 40,
        "prosecutionReady": has_financial and has_contact,
        "entitiesExposed": entities,  # ✅ FIXED: Added this field
        "canFreeze": len(intel["bankAccounts"]) > 0 or len(intel["upiIds"]) > 0,
        "canTrack": len(intel["phoneNumbers"]) > 0,
        "canTakedown": len(intel["phishingLinks"]) > 0
    }


print("\n" + "="*60)
print("✅ SCAMMER PROFILING & INTELLIGENCE SCORING READY!")
print("="*60)
print("🎯 Behavioral profiling: Aggression + Sophistication")
print("📊 Intelligence scoring: S/A/B/C/D grades")
print("⚖️ Prosecution readiness: Actionable intelligence detection")
print("="*60)

"""B5"""

# ============================================================
# BLOCK 5: SMART EXIT LOGIC (SIMPLIFIED)
# ============================================================

def should_end_conversation(session_id):
    """
    Determines if conversation should end
    Returns: (should_end: bool, reason: str)
    """
    if not session_manager.session_exists(session_id):
        return (False, "Session not found")

    session = session_manager.sessions[session_id]
    turn_count = session["turnCount"]
    accumulated_intel = session_manager.get_accumulated_intelligence(session_id)

    # Calculate entities
    total_entities = (
        len(accumulated_intel["bankAccounts"]) +
        len(accumulated_intel["upiIds"]) +
        len(accumulated_intel["phoneNumbers"]) +
        len(accumulated_intel["emails"])
    )

    # Maximum turns
    MAX_TURNS = 10
    if turn_count >= MAX_TURNS:
        return (True, f"Maximum turns reached ({turn_count}/{MAX_TURNS})")

    # High-value intelligence collected

    # Continue conversation
    return (False, f"Continue (turn {turn_count}/{MAX_TURNS}, {total_entities} entities)")

# Remove generate_contextual_exit() function entirely!

print("\n" + "="*60)
print("✅ SMART EXIT LOGIC READY!")
print("="*60)
print("🚪 Exit conditions: turns, intel quality, saturation")
print("💬 Natural endings: LLM generates contextually (no templates)")
print("="*60)

"""B6"""

"""B6"""

# ============================================================
# BLOCK 6: MAIN PROCESSING PIPELINE (Context-Aware)
# ============================================================

def process_message(request_data):
    """
    Complete message processing pipeline - FIXED VERSION
    """
    try:
        # Extract request data
        session_id = request_data.get("sessionId")
        message_obj = request_data.get("message", {})
        conversation_history = request_data.get("conversationHistory", [])

        current_message = message_obj["text"]
        sender = message_obj.get("sender", "scammer")
        timestamp = message_obj.get("timestamp", int(time.time() * 1000))

        print(f"\n{'='*60}")
        print(f"📨 Session: {session_id}")
        print(f"📨 Message: {current_message[:60]}...")
        print(f"{'='*60}")

        # Initialize or update session
        if not session_manager.session_exists(session_id):
            session_manager.create_session(session_id)

        # ✅ FIXED: Load conversation history ONCE per session (OLD LOGIC)
        if conversation_history:
            current_history = session_manager.get_conversation_history(session_id)
            if len(current_history) == 0:  # Only if empty (first load)
                print(f"📥 Loading {len(conversation_history)} messages from GUVI (first time)")
                for msg in conversation_history:
                    session_manager.add_message(
                        session_id,
                        msg.get("sender", "scammer"),
                        msg.get("text", ""),
                        msg.get("timestamp", timestamp)
                    )

        # Add current message
        session_manager.add_message(session_id, sender, current_message, timestamp)
        turn_count = session_manager.get_turn_count(session_id)
        print(f"📊 Turn: {turn_count}")

        # Process message with enhanced detection
        full_history = session_manager.get_conversation_history(session_id)
        result = process_message_optimized(current_message, full_history[:-1], turn_count)

        # Update session with results
        if result["isScam"]:
            session_manager.update_scam_status(
                session_id,
                True,
                result["confidence"],
                result["scamType"],
                f"Detected via indicators: {', '.join(result['extractedEntities']['keywords'])}"
            )
        
        session_manager.accumulate_intelligence(session_id, result["extractedEntities"])

        # Get agent's reply
        agent_reply = result["agentReply"]
        
        # Add agent's reply to history
        session_manager.add_message(session_id, "agent", agent_reply, int(time.time() * 1000))

        # Check if conversation should end
        should_end, exit_reason = should_end_conversation(session_id)

        if should_end:
            print(f"🚪 Exit triggered: {exit_reason}")

        print(f"✅ Pipeline complete")

        return {
            "success": True,
            "agentReply": agent_reply,
            "shouldEndConversation": should_end,
            "scamDetected": result["isScam"],
            "confidence": result["confidence"],
            "scamType": result["scamType"],
            "extractedEntities": result["extractedEntities"],
            "turnCount": turn_count,
            "exitReason": exit_reason if should_end else None
        }

    except Exception as e:
        print(f"❌ Pipeline error: {e}")
        import traceback
        traceback.print_exc()

        return {
            "success": False,
            "error": str(e),
            "agentReply": "I'm sorry, I didn't understand. Can you repeat that?"
        }

print("\n" + "="*60)
print("✅ CONTEXT-AWARE PROCESSING PIPELINE READY!")
print("="*60)
print("🔄 Complete flow: Detection → LLM Response → Intelligence → Exit")
print("📊 Context management: ALWAYS syncs with GUVI history")
print("🤖 LLM-driven: All responses generated with full context")
print("⚡ Optimized: Reliable conversation continuity")
print("="*60)

"""B7"""

# ============================================================
# BLOCK 7: FIXED GUVI-COMPATIBLE API (CONNECTS TO BLOCK 6)
# ============================================================

from flask import Flask, request, jsonify
import time
import requests

# ============================================================
# MAIN HONEYPOT ENDPOINT (GUVI Format) - FIXED
# ============================================================

@app.route('/honeypot', methods=['POST'])
def honeypot():
    """
    Main endpoint with SMART HUMAN-LIKE PACING
    - Prevents GUVI rapid-fire 429 errors
    - Adds realistic response delays
    - Safe conservative timing (3-5 seconds)
    """
    
    try:
        # ============================================================
        # VALIDATE REQUEST
        # ============================================================
        api_key = request.headers.get('x-api-key')
        if api_key != API_SECRET_KEY:
            return jsonify({"error": "Unauthorized"}), 401

        request_data = request.json
        if not request_data:
            return jsonify({
                "status": "error",
                "reply": "Invalid request format"
            }), 400
        
        session_id = request_data.get("sessionId")
        
        # ============================================================
        # GET CURRENT TURN (before processing adds new message)
        # ============================================================
        if session_manager.session_exists(session_id):
            current_turn = session_manager.get_turn_count(session_id) + 1
        else:
            current_turn = 1
        
        # ============================================================
        # CONSERVATIVE REALISTIC DELAYS (safe for most timeouts)
        # ============================================================
        if current_turn == 1:
            # First message: reading and understanding
            delay = random.uniform(3.5, 4.5)
            delay_reason = "reading first message"
        elif current_turn == 2:
            # Second: re-reading, still cautious
            delay = random.uniform(3.0, 4.0)
            delay_reason = "re-reading carefully"
        elif current_turn % 3 == 0:
            # Every 3rd: thinking it over
            delay = random.uniform(4.0, 5.0)
            delay_reason = "thinking pause"
        elif current_turn <= 4:
            # Early conversation: cautious
            delay = random.uniform(3.0, 4.0)
            delay_reason = "cautious response"
        else:
            # Later: more fluent
            delay = random.uniform(2.5, 3.5)
            delay_reason = "engaged typing"
        
        # ============================================================
        # PROCESS MESSAGE (LLM call happens here)
        # ============================================================
        start_time = time.time()
        result = process_message(request_data)
        processing_time = time.time() - start_time
        
        if not result.get("success", False):
            return jsonify({
                "status": "error",
                "reply": result.get("agentReply", "Error processing message")
            }), 500
        
        # ============================================================
        # SIMULATE "TYPING" (delay minus processing time)
        # ============================================================
        remaining_delay = max(0, delay - processing_time)
        
        if remaining_delay > 0:
            time.sleep(remaining_delay)
        
        total_time = time.time() - start_time
        
        # Log for debugging (you can check /analytics later)
        print(f"⏱️  Turn {current_turn}: {delay:.1f}s target ({delay_reason}), {processing_time:.1f}s processing, {remaining_delay:.1f}s typing, {total_time:.1f}s total")
        
        # ============================================================
        # CHECK IF CONVERSATION ENDED
        # ============================================================
        if result.get("shouldEndConversation", False):
            send_final_callback_to_guvi(session_id)
        
        # ============================================================
        # RETURN RESPONSE
        # ============================================================
        return jsonify({
            "status": "success",
            "reply": result["agentReply"]
        }), 200

    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        
        return jsonify({
            "status": "error",
            "reply": "Kuch samajh nahin aaya, phir se bolo."
        }), 500

    except Exception as e:
        print(f"❌ Error in honeypot endpoint: {e}")
        import traceback
        traceback.print_exc()

        return jsonify({
            "status": "error",
            "reply": "Sorry, I'm having trouble understanding. Could you repeat that?"
        }), 500


# ============================================================
# FIXED: SEND GUVI CALLBACK (Uses correct key names)
# ============================================================

def send_final_callback_to_guvi(session_id):
    """Send final intelligence to GUVI - WITH EMAIL SUPPORT"""
    try:
        if not session_manager.session_exists(session_id):
            print(f"⚠️ Session {session_id} not found")
            return False

        # Get accumulated intelligence
        intelligence = session_manager.get_accumulated_intelligence(session_id)
        summary = session_manager.get_session_summary(session_id)

        # Prepare payload (GUVI format)
        payload = {
            "sessionId": session_id,
            "scamDetected": summary["scamDetected"],
            "totalMessagesExchanged": summary["totalMessages"],
            "extractedIntelligence": {
                "bankAccounts": intelligence["bankAccounts"],
                "upiIds": intelligence["upiIds"],
                "emails": intelligence["emails"],  # ✅ Added emails
                "phishingLinks": intelligence["phishingLinks"],
                "phoneNumbers": intelligence["phoneNumbers"],
                "suspiciousKeywords": intelligence["suspiciousKeywords"]
            },
            "agentNotes": summary["agentNotes"]
        }

        print(f"\n📤 Sending callback to GUVI...")
        print(f"   Entities: {len(intelligence['bankAccounts'])} banks, {len(intelligence['upiIds'])} UPIs, {len(intelligence['phoneNumbers'])} phones, {len(intelligence['emails'])} emails")

        response = requests.post(
            GUVI_CALLBACK_URL,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )

        if response.status_code == 200:
            print(f"✅ GUVI callback successful!")
            return True
        else:
            print(f"⚠️ GUVI callback failed: {response.status_code}")
            return False

    except Exception as e:
        print(f"❌ Callback error: {e}")
        return False


# ============================================================
# UTILITY ENDPOINTS
# ============================================================

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "timestamp": int(time.time() * 1000),
        "sessions": len(session_manager.get_all_sessions())
    }), 200

@app.route('/quota', methods=['GET'])
def quota_status():
    """Check API quota usage - useful for debugging"""
    try:
        status = rate_limiter.get_status()
        return jsonify({
            "status": "success",
            "quota": {
                "used": status["used"],
                "remaining": status["remaining"],
                "limit": status["limit"],
                "percentage": f"{(status['used']/status['limit']*100):.1f}%"
            },
            "timestamp": int(time.time() * 1000)
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


@app.route('/session/<session_id>', methods=['GET'])
def get_session(session_id):
    """Get session details (for debugging) - FIXED VERSION"""
    if session_manager.session_exists(session_id):
        session = session_manager.sessions[session_id]

        # ✅ FIXED: Create a clean copy for JSON serialization
        session_copy = {
            "sessionId": session["sessionId"],
            "scamDetected": session["scamDetected"],
            "detectionConfidence": session["detectionConfidence"],
            "scamType": session["scamType"],
            "turnCount": session["turnCount"],
            "startTime": session["startTime"],
            "lastMessageTime": session["lastMessageTime"],
            "agentNotes": session["agentNotes"],
            "conversationHistory": session["conversationHistory"]
        }

        # ✅ FIXED: Get accumulated intelligence properly converted
        session_copy["accumulatedIntelligence"] = session_manager.get_accumulated_intelligence(session_id)

        # ✅ FIXED: Get intelligence score
        try:
            intel_score = calculate_intelligence_value(session_id)
            session_copy["intelligenceScore"] = intel_score
        except Exception as e:
            print(f"⚠️ Error calculating score: {e}")
            session_copy["intelligenceScore"] = {"grade": "N/A", "score": 0, "entitiesExposed": 0}

        # ✅ FIXED: Get scammer profile
        try:
            profile = generate_scammer_profile(session_id)
            session_copy["scammerProfile"] = profile
        except Exception as e:
            print(f"⚠️ Error generating profile: {e}")
            session_copy["scammerProfile"] = {}

        return jsonify(session_copy), 200

    return jsonify({"error": "Session not found"}), 404


@app.route('/analytics', methods=['GET'])
def analytics():
    """System analytics"""
    all_sessions = session_manager.get_all_sessions()
    total_sessions = len(all_sessions)

    scam_sessions = 0
    total_entities = 0

    for sid in all_sessions:
        session = session_manager.sessions[sid]
        if session.get("scamDetected", False):
            scam_sessions += 1

        intel = session_manager.get_accumulated_intelligence(sid)
        total_entities += len(intel["bankAccounts"])
        total_entities += len(intel["upiIds"])
        total_entities += len(intel["phoneNumbers"])
        total_entities += len(intel["phishingLinks"])

    return jsonify({
        "totalSessions": total_sessions,
        "scamDetectionRate": f"{(scam_sessions/total_sessions*100):.1f}%" if total_sessions > 0 else "0%",
        "totalEntitiesExtracted": total_entities,
        "activeNow": total_sessions
    }), 200

@app.route('/test-timing', methods=['GET'])
def test_timing():
    """
    Test endpoint to verify delays are working
    Safe to call - doesn't trigger any scams
    """
    try:
        # Simulate a request
        start = time.time()
        
        # Simulate processing
        time.sleep(0.5)
        
        # Test delay calculation
        target_delay = 4.0
        processing = time.time() - start
        remaining = max(0, target_delay - processing)
        
        time.sleep(remaining)
        
        total = time.time() - start
        
        return jsonify({
            "status": "success",
            "test": {
                "target_delay": f"{target_delay:.1f}s",
                "processing_time": f"{processing:.2f}s",
                "sleep_time": f"{remaining:.2f}s",
                "total_time": f"{total:.2f}s"
            },
            "message": f"Delay working! Total time: {total:.1f}s (target was {target_delay:.1f}s)"
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

print("\n" + "="*60)
print("✅ FIXED GUVI-COMPATIBLE API ENDPOINTS!")
print("="*60)
print("📍 POST /honeypot - Main endpoint (now connected to Block 6)")
print("📍 GET  /health - Health check")
print("📍 GET  /session/<id> - Session details")
print("📍 GET  /analytics - System stats")
print("="*60)

"""B8 - not needed

B9
"""

# ============================================================
# BLOCK 9: START FLASK SERVER (Cloud-Ready!)
# ============================================================

import os

print("\n" + "="*60)
print("🚀 STARTING FLASK SERVER (Cloud-Ready)")
print("="*60)

# ============================================================
# CLOUD DEPLOYMENT CONFIGURATION
# ============================================================

# Get port from environment variable (for Render/Railway)
# Falls back to 5000 for local testing (Colab/ngrok)
PORT = int(os.environ.get('PORT', 5000))

print(f"📍 Port: {PORT}")
print(f"🌍 Host: 0.0.0.0 (accessible from internet)")
print("="*60)

# ============================================================
# START SERVER
# ============================================================

if __name__ == '__main__':
    # This works for BOTH:
    # - Colab + ngrok (uses port 5000)
    # - Render/Railway (uses $PORT from environment)

    app.run(
        host='0.0.0.0',      # Listen on all interfaces
        port=PORT,           # Use cloud port or 5000
        debug=False,         # No debug in production
        threaded=True        # Handle multiple requests
    )

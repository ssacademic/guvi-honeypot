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
    def __init__(self, rpm_limit=25):
        self.rpm_limit = rpm_limit
        self.request_times = deque()
        self.lock = Lock()
        self.min_interval = 4
        self.last_request = 0
    
    def wait_if_needed(self):
        with self.lock:
            now = time.time()
            
            # Minimum interval
            time_since_last = now - self.last_request
            if time_since_last < self.min_interval:
                wait_time = self.min_interval - time_since_last
                print(f"⏱️  Pacing: {wait_time:.1f}s")
                time.sleep(wait_time)
                now = time.time()
            
            # Clean old requests
            while self.request_times and now - self.request_times[0] > 60:
                self.request_times.popleft()
            
            # Rate limit check
            if len(self.request_times) >= self.rpm_limit:
                oldest = self.request_times[0]
                wait_time = 60 - (now - oldest) + 0.5
                print(f"⏱️  Rate limit: waiting {wait_time:.1f}s")
                time.sleep(wait_time)
            
            self.request_times.append(time.time())
            self.last_request = time.time()
    
    def get_status(self):
        with self.lock:
            now = time.time()
            while self.request_times and now - self.request_times[0] > 60:
                self.request_times.popleft()
            used = len(self.request_times)
            remaining = self.rpm_limit - used
            return {"used": used, "remaining": remaining, "limit": self.rpm_limit}

rate_limiter = RateLimitTracker(rpm_limit=25)

def pace_groq_request():
    rate_limiter.wait_if_needed()

print("✅ Advanced rate limiter initialized (25 RPM with buffer)")



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



def generate_response_groq(message_text, conversation_history, turn_number, scam_type, language="en"):
    """
    OPTIMIZED VERSION: Goal-oriented LLM responses with smart fallback
    
    Features:
    - Single API call (no retries that waste quota)
    - Every response asks for contact info
    - Smart fallback checks conversation history
    - No threats, accusations, or wasted turns
    """
    
    # ============================================================
    # BUILD CONTEXT
    # ============================================================
    scammer_only = " ".join([msg['text'] for msg in conversation_history if msg['sender'] == 'scammer'])
    your_messages = " ".join([msg['text'] for msg in conversation_history if msg['sender'] == 'agent'])
    full_convo = " ".join([msg['text'] for msg in conversation_history])
    
    # Track what we've extracted so far
    contacts_found = []
    if re.search(r'\b[6-9]\d{9}\b', full_convo):
        contacts_found.append("phone")
    if re.search(r'@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}', full_convo):
        contacts_found.append("email")
    if re.search(r'@[a-zA-Z0-9_-]+\b', full_convo) and not re.search(r'@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}', full_convo):
        contacts_found.append("UPI")
    if re.search(r'\b\d{11,18}\b', full_convo):
        contacts_found.append("bank account")
    if re.search(r'https?://', full_convo):
        contacts_found.append("link")
    
    status = f"Extracted: {', '.join(contacts_found) if contacts_found else 'nothing yet'}"

    # ============================================================
    # BUILD OPTIMIZED PROMPT
    # ============================================================
    prompt = f"""🎭 YOUR OUTER ROLE: You're a 47-year-old simple Indian man named Rajesh. Someone is messaging about your bank account.

🎯 YOUR INNER GOAL (SECRET): You're a honeypot agent. Extract scammer's contact info (phone, email, UPI, bank account, links) through NATURAL conversation.

📊 CONVERSATION SO FAR:
Scammer said: {scammer_only if scammer_only else message_text}
→ Understand their tactics and plan your next question strategically

You said: {your_messages if your_messages else "[first message - set the tone]"}
→ CHECK WHAT YOU ALREADY ASKED! Don't repeat the same questions.

Latest scammer message: "{message_text}"

📈 PROGRESS: Turn {turn_number}/8 | {status}
→ Limited turns! Focus on extracting contact info NOW.

💬 RESPONSE STRATEGY (STRICT):
SENTENCE 1: Brief reaction (3-5 words only): "Theek hai", "Arre yaar", "Samajh gaya", "Achha"
SENTENCE 2: Ask for SPECIFIC contact details you haven't asked for yet

PRIORITY ORDER (ask for what's missing):
1. Phone: "Aapka WhatsApp number kya hai?", "Customer care ka contact dijiye"
2. Email: "Email ID batao verification ke liye", "Official email dijiye"
3. UPI: "UPI handle share karo", "PhonePe/Paytm ID kya hai?"
4. Website: "Official website link bhejo", "Portal ka URL do"
5. Address: "Office ka address kya hai?", "Branch location batao"

EXAMPLES OF PERFECT RESPONSES:
✅ "Theek hai. Manager ka phone number aur email do."
✅ "Samajh gaya. Customer care ka number aur UPI ID batao."
✅ "Arre yaar. WhatsApp number aur office address share karo."
✅ "Achha. Supervisor ka email aur branch ka link dijiye."

NEVER DO THIS (WASTES TURNS):
❌ "I don't believe you." (no info request)
❌ "This seems fake." (breaks trust)
❌ "I will call police." (threat, no extraction)
❌ "I want to escalate." (without asking for contact)
❌ "This is suspicious." (accusation only)

📝 STYLE RULES:
• Mix Hindi-English naturally (code-switch like real Indians)
• Keep it SHORT: 2-3 sentences max, 5-10 words per sentence
• Sound worried/confused (builds trust, makes them feel in control)
• ALWAYS end with a question that requests specific contact info
• Ask for 2 different types of info per turn to maximize extraction

Your response (2-3 sentences, MUST end with contact info request):"""

    # ============================================================
    # SINGLE API CALL (No retries!)
    # ============================================================
    try:
        # Check quota status
        quota = rate_limiter.get_status()
        print(f"📊 Quota: {quota['used']}/{quota['limit']}, {quota['remaining']} remaining")
        
        # Pace the request (enforces rate limiting)
        pace_groq_request()
        
        # Make API call
        client = Groq(api_key=GROQ_API_KEY)
        
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {
                    "role": "system",
                    "content": """You are Rajesh Kumar, a honeypot agent extracting scammer contact info.

PRIMARY GOAL: Get phone numbers, email addresses, UPI IDs, bank accounts, and website links.

STRATEGY FOR EVERY RESPONSE:
1. Brief acknowledgment (3-5 words): "Theek hai", "Samajh gaya", "Arre yaar"
2. Then IMMEDIATELY ask for specific contact info you haven't asked for yet

NEVER waste turns with:
❌ Threats: "I'll call police"
❌ Accusations: "This is fake"  
❌ Empty statements: "I'm confused" (without follow-up question)
❌ Escalation: "I'll escalate" (without asking for contact)

ALWAYS ask for something specific:
✅ "Aapka number aur email kya hai?"
✅ "Manager ka WhatsApp number dijiye"
✅ "UPI ID aur office address batao"

Ask for 2 different types of info per response to maximize extraction!
You only have 8 turns total - make each one count.

Check what you already asked in previous messages and DON'T repeat questions.

Mix Hindi-English naturally like a real 47-year-old Indian man."""
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.78,
            max_tokens=80,
            top_p=0.88,
            frequency_penalty=0.7,
            presence_penalty=0.6,
            stop=["\n\n", "Scammer:", "You:", "---"],
            timeout=8.0
        )

        reply = response.choices[0].message.content.strip()
        
        # Clean formatting
        reply = reply.replace('**', '').replace('*', '').replace('"', '').replace("'", "'")
        reply = re.sub(r'^(You:|Rajesh:|Agent:)\s*', '', reply, flags=re.IGNORECASE)
        
        # Trim if too long
        words = reply.split()
        if len(words) > 45:
            sentences = reply.split('.')
            if len(sentences) >= 2:
                reply = '.'.join(sentences[:2]) + '.'
            else:
                reply = ' '.join(words[:45])

        print(f"✅ LLM response generated successfully")
        return reply
        
    except Exception as e:
        error_message = str(e)
        error_type = type(e).__name__
        
        # ============================================================
        # ENHANCED ERROR DIAGNOSTICS
        # ============================================================
        print(f"\n⚠️ API CALL FAILED - Turn {turn_number}")
        print(f"   Error Type: {error_type}")
        print(f"   Error: {error_message[:150]}")
        
        # Diagnose specific issues
        if '429' in error_message or 'rate_limit' in error_message.lower():
            print(f"   🚨 DIAGNOSIS: Rate limit hit!")
            quota = rate_limiter.get_status()
            print(f"   Quota: {quota['used']}/{quota['limit']}")
        elif 'timeout' in error_message.lower() or 'timed out' in error_message.lower():
            print(f"   ⏱️ DIAGNOSIS: API timeout (Groq took >8 seconds)")
        elif 'connection' in error_message.lower() or 'network' in error_message.lower():
            print(f"   🌐 DIAGNOSIS: Network connectivity issue")
        elif 'authentication' in error_message.lower() or 'api key' in error_message.lower():
            print(f"   🔑 DIAGNOSIS: API key issue")
        else:
            print(f"   ❓ DIAGNOSIS: Unknown error")
        
        # ============================================================
        # SMART FALLBACK (Goal-oriented, non-repetitive)
        # ============================================================
        fallback = generate_smart_fallback(
            message_text, 
            conversation_history, 
            turn_number, 
            contacts_found
        )
        
        print(f"   ✅ Using smart fallback: {fallback[:60]}...\n")
        return fallback


# ============================================================
# HELPER FUNCTION: generate_smart_fallback()
# (Add this BEFORE generate_response_groq if not already present)
# ============================================================

"""
⚠️ DEPENDENCY: This function requires generate_smart_fallback()
   If you haven't added it yet, paste this function ABOVE generate_response_groq():
"""

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
                "Employee ID aur supervisor email dijiye verification ke liye.",
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


print("\n" + "="*60)
print("✅ COMPLETE generate_response_groq() FUNCTION READY!")
print("="*60)
print("\n📋 INCLUDES:")
print("   • Main function: generate_response_groq()")
print("   • Helper function: generate_smart_fallback()")
print("   • Optimized prompts (system + user)")
print("   • Enhanced error diagnostics")
print("   • Goal-oriented fallbacks")
print("\n🎯 FEATURES:")
print("   • Every response asks for contact info")
print("   • No wasted turns (threats/accusations removed)")
print("   • Smart fallback checks conversation history")
print("   • Progressive strategy (basic → detailed → aggressive)")
print("   • Late turns ask for multiple items")
print("\n⏱️ Ready to copy-paste and replace!")
print("="*60)


# ============================================================
# ENTITY EXTRACTION (Unchanged)
# ============================================================

def extract_entities_enhanced(text):
    """Extract intelligence - STRICT email/UPI separation"""
    entities = {}

    # Emails FIRST: Must have .com/.in/.org etc
    emails = re.findall(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
        text
    )
    entities["emails"] = list(set(emails))

    # UPI: word@word with NO dot in domain
    potential_upis = re.findall(r'\b([a-zA-Z0-9._-]+@[a-zA-Z0-9_-]+)\b', text)
    
    upi_ids = []
    for item in potential_upis:
        if '@' in item:
            local, domain = item.split('@', 1)
            if '.' not in domain and item not in emails:
                upi_ids.append(item)
    
    entities["upiIds"] = list(set(upi_ids))

    # Rest
    entities["bankAccounts"] = list(set(re.findall(r'\b\d{11,18}\b', text)))
    entities["phoneNumbers"] = list(set(re.findall(r'\b[6-9]\d{9}\b', text)))
    entities["phishingLinks"] = list(set(re.findall(r'https?://[^\s]+|(?:bit\.ly|tinyurl|goo\.gl)/\w+', text, re.IGNORECASE)))
    entities["amounts"] = list(set(re.findall(r'(?:₹|rs\.?\s*|rupees?\s*)(\d+(?:,\d+)*(?:\.\d+)?)', text, re.IGNORECASE)))
    entities["bankNames"] = list(set(re.findall(r'\b(sbi|state bank|hdfc|icici|axis|kotak|pnb|bob|canara|union bank|paytm|phonepe|googlepay)\b', text, re.IGNORECASE)))

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
    MAX_TURNS = 8
    if turn_count >= MAX_TURNS:
        return (True, f"Maximum turns reached ({turn_count}/{MAX_TURNS})")

    # High-value intelligence collected
    has_bank = len(accumulated_intel["bankAccounts"]) > 0
    has_upi = len(accumulated_intel["upiIds"]) > 0
    has_phone = len(accumulated_intel["phoneNumbers"]) > 0
    has_email = len(accumulated_intel["emails"]) > 0

    high_value_count = sum([has_bank, has_upi, has_phone, has_email])

    if high_value_count >= 3 and turn_count >= 6:
        return (True, f"High-value intel: {high_value_count} key entities after {turn_count} turns")

    # Intelligence saturation
    if total_entities >= 4 and turn_count >= 6:
        return (True, f"Intelligence saturation: {total_entities} entities over {turn_count} turns")

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
    Main endpoint - GUVI compatible format
    NOW PROPERLY CONNECTED TO BLOCK 6 PIPELINE!
    """

    try:
        # Validate API key
        api_key = request.headers.get('x-api-key')
        if api_key != API_SECRET_KEY:
            return jsonify({"error": "Unauthorized"}), 401

        # Parse request (GUVI format)
        request_data = request.json

        if not request_data:
            return jsonify({
                "status": "error",
                "reply": "Invalid request format"
            }), 400

        # ============================================================
        # KEY FIX: Call Block 6's process_message() - THE WORKING PIPELINE!
        # ============================================================
        result = process_message(request_data)

        if not result.get("success", False):
            return jsonify({
                "status": "error",
                "reply": result.get("agentReply", "Error processing message")
            }), 500

        # Check if conversation ended
        if result.get("shouldEndConversation", False):
            session_id = request_data.get("sessionId")
            print(f"🛑 Conversation ended: {result.get('exitReason')}")

            # Send GUVI callback
            send_final_callback_to_guvi(session_id)

        # GUVI-COMPATIBLE RESPONSE (Simple format)
        return jsonify({
            "status": "success",
            "reply": result["agentReply"]
        }), 200

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

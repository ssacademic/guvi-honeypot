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

"""B2"""

# ============================================================
# BLOCK 2: LLM-FIRST DETECTION & RESPONSE (Context-Aware)
# ============================================================

import re
import random

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


def generate_response_groq(message_text, conversation_history, turn_number, scam_type, language="en"):
    """
    Intelligent conversational agent - HYBRID APPROACH (Production Version)
    
    This is the FIXED HYBRID version that maintains high entity extraction
    while reducing opening phrase repetition.
    """
    try:
        # ============================================================
        # STEP 1: BUILD CONVERSATION CONTEXT
        # ============================================================
        
        # Separate scammer and agent messages
        scammer_only = " ".join([msg['text'] for msg in conversation_history if msg['sender'] == 'scammer'])
        your_messages = " ".join([msg['text'] for msg in conversation_history if msg['sender'] == 'agent'])
        full_convo = " ".join([msg['text'] for msg in conversation_history])
        
        # ============================================================
        # STEP 2: INTELLIGENCE TRACKING (What have we collected?)
        # ============================================================
        
        contacts_found = []
        
        # Check for phone numbers
        if re.search(r'\b[6-9]\d{9}\b', full_convo):
            contacts_found.append("phone")
        
        # Check for emails
        if re.search(r'@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}', full_convo):
            contacts_found.append("email")
        
        # Check for UPI IDs
        if re.search(r'@[a-zA-Z0-9_-]+\b', full_convo) and not re.search(r'@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}', full_convo):
            contacts_found.append("UPI")
        
        # Check for bank accounts
        if re.search(r'\b\d{11,18}\b', full_convo):
            contacts_found.append("bank account")
        
        # Check for links
        if re.search(r'https?://', full_convo):
            contacts_found.append("link")
        
        status = f"Extracted: {', '.join(contacts_found) if contacts_found else 'nothing yet'}"
        
        # ============================================================
        # STEP 3: ANTI-REPETITION TRACKING
        # ============================================================
        
        last_opening = ""
        if conversation_history:
            # Get only agent messages
            agent_msgs = [msg for msg in conversation_history if msg['sender'] == 'agent']
            if agent_msgs:
                # Get first 6 words of last agent message
                last_opening = ' '.join(agent_msgs[-1]['text'].split()[:6])
        
        # Add warning to prompt if we have a recent opening
        avoid_hint = ""
        if last_opening:
            avoid_hint = f"\n⚠️ Your last response started with: '{last_opening}' - DON'T repeat this opening! Use a different emotion/phrase."
        
        # ============================================================
        # STEP 4: BUILD LLM PROMPT
        # ============================================================
        
        prompt = f"""🎭 YOUR OUTER ROLE: You're a 47-year-old Indian man named Rajesh. Someone is messaging about your bank account.

🎯 YOUR INNER GOAL (SECRET): You're a smart honeypot agent. Extract scammer's contact info (phone, email, UPI, bank account, links) through NATURAL conversation.

📊 CONVERSATION SO FAR:
Scammer said: {scammer_only if scammer_only else message_text}
→ USE THIS to understand their intent, tactics, and what they want from you.

You said: {your_messages if your_messages else "[first message - set the tone]"}
→ USE THIS to remember your style, what you've already asked, and your progression.

Latest scammer message: "{message_text}"

📈 PROGRESS: Turn {turn_number}/8 | {status}
→ You have LIMITED TURNS to extract maximum info. Be strategic!

💬 RESPONSE STRATEGY:
SENTENCE 1: Acknowledge their message + show concern/confusion (sound NATURAL, not robotic)
   - VARY your opening each time: "Mujhe confusion ho rahi", "Yeh toh serious lag raha", "Main bahut pareshaan hoon", "Arre yaar", "Arrey baap re", etc.
   
SENTENCE 2: Ask 1-2 SMART QUESTIONS that might reveal their contact details
   - Examples: "Aapka customer care number kya hai?", "Email id bataiye?", "WhatsApp pe baat kar sakte hain?"
   - You can ask for MULTIPLE things: "Can you give me your phone number and email to verify?"

📝 STYLE GUIDELINES:
✅ Mix Hindi-English naturally (code-switching like real Indians do)
✅ Show appropriate emotion (worried, confused, cautious)
✅ 2-3 sentences, 5-12 words each
✅ Sound like a REAL 47-year-old, not a chatbot
✅ DON'T repeat questions you already asked
✅ PROACTIVELY lead the conversation with smart questions{avoid_hint}

Your response (2-3 sentences):"""

        # ============================================================
        # STEP 5: CALL GROQ API
        # ============================================================
        
        client = Groq(api_key=GROQ_API_KEY)
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {
                    "role": "system",
                    "content": "You are a skilled actor playing Rajesh Kumar. Stay in character. Be intelligent and strategic. Sound natural - mix Hindi-English like real Indians. Don't repeat yourself. Understand the scam game and play it smartly."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.78,        # ✅ Proven optimal
            max_tokens=65,           # ✅ Allows 2-3 sentences
            top_p=0.88,              # ✅ Good diversity
            frequency_penalty=0.7,   # ✅ Anti-repetition
            presence_penalty=0.6,    # ✅ Topic variety
            stop=["\\n\\n", "Scammer:", "You:", "---"]
        )

        # ============================================================
        # STEP 6: EXTRACT AND CLEAN RESPONSE
        # ============================================================
        
        reply = response.choices[0].message.content.strip()
        
        # Remove markdown formatting
        reply = reply.replace('**', '').replace('*', '')
        
        # Remove quotes (both types)
        reply = reply.replace('"', '').replace("'", "'")
        
        # Remove any accidental role markers
        reply = re.sub(r'^(You:|Rajesh:|Agent:|Response:)\s*', '', reply, flags=re.IGNORECASE)
        
        # ============================================================
        # STEP 7: ENFORCE LENGTH LIMITS
        # ============================================================
        
        words = reply.split()
        if len(words) > 40:
            # Try to preserve sentence boundaries
            sentences = reply.split('.')
            if len(sentences) >= 2:
                # Keep first 2 complete sentences
                reply = '.'.join(sentences[:2]) + '.'
            else:
                # Fallback: truncate at 40 words
                reply = ' '.join(words[:40])

        return reply

    except Exception as e:
        # ============================================================
        # STEP 8: FALLBACK HANDLING (if API fails)
        # ============================================================
        
        print(f"⚠️ LLM error: {e}")
        import traceback
        traceback.print_exc()
        
        # ✅ FIXED: Random selection instead of sequential
        contextual_fallbacks = [
            "Mujhe thoda confusion ho rahi hai. Aapka number aur email id kya hai?",
            "Main samajh nahin pa raha. Kya aap WhatsApp pe details bhej sakte hain?",
            "Yeh kya scene hai? Mujhe aapka customer care number chahiye.",
            "Wait, aap kaun ho? Apna phone number aur email bataiye.",
            "Bahut confusing hai yeh. Koi link ya contact details bhej sakte ho?",
            "Arre yaar, explain toh karo. Aapka contact number kya hai?",
            "Main verify karna chahta hoon. Email id aur WhatsApp number bataiye.",
            "Thoda detail mein bataiye. Aapka official number aur email kya hai?"
        ]
        
        # ✅ Use random.choice for true randomization
        return random.choice(contextual_fallbacks)


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
    Complete message processing pipeline - FIXED FOR GUVI CONTEXT
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
        print(f"📨 History provided: {len(conversation_history)} messages")
        print(f"{'='*60}")

        # Initialize session if needed
        if not session_manager.session_exists(session_id):
            session_manager.create_session(session_id)

        # ✅ CRITICAL FIX: ALWAYS sync with GUVI's conversation history
        # GUVI is the source of truth - we reload every time
        if conversation_history:
            print(f"🔄 Syncing conversation history from GUVI...")
            # Clear and reload
            session_manager.sessions[session_id]["conversationHistory"] = []
            for msg in conversation_history:
                session_manager.add_message(
                    session_id,
                    msg.get("sender", "scammer"),
                    msg.get("text", ""),
                    msg.get("timestamp", timestamp)
                )
            print(f"✅ Loaded {len(conversation_history)} messages from GUVI")

        # Add current message
        session_manager.add_message(session_id, sender, current_message, timestamp)
        turn_count = session_manager.get_turn_count(session_id)
        print(f"📊 Turn: {turn_count}")

        # ✅ Process with FULL context
        full_history = session_manager.get_conversation_history(session_id)
        
        # Pass conversation WITHOUT current message (LLM will see it separately)
        result = process_message_optimized(current_message, full_history[:-1], turn_count)

        # Update session with results (for analytics)
        if result["isScam"]:
            session_manager.update_scam_status(
                session_id,
                True,
                result["confidence"],
                result["scamType"],
                f"Detected via indicators: {', '.join(result['extractedEntities']['keywords'])}"
            )
        
        session_manager.accumulate_intelligence(session_id, result["extractedEntities"])

        # Get agent's reply from LLM
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

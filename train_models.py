import os
import random
import pickle
import math
import re
from collections import Counter
from urllib.parse import urlparse
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, precision_score, recall_score, f1_score, roc_auc_score

# Ensure models directory exists
os.makedirs("models", exist_ok=True)

# ==========================================
# 1. GENERATE CYBERCRIME COMPLAINT DATASET
# ==========================================
print("Generating cybercrime complaint dataset...")

categories = [
    "UPI Fraud", "Banking Fraud", "Loan Scam", "Lottery Scam", "Investment Scam",
    "Job Scam", "Delivery Scam", "Sextortion", "Social Media Fraud", "Phishing Attack"
]

banks = ["SBI", "HDFC", "ICICI", "Axis Bank", "PNB", "Paytm Bank", "Kotak"]
items = ["sofa", "dining table", "iphone", "laptop", "second-hand bike", "car", "refrigerator"]
names = ["Rajesh", "Amit", "Rahul", "Priya", "Sunita", "Vikram", "Suresh", "Anjali", "Karan"]
amounts = [5000, 10000, 25000, 50000, 120000, 200000, 15000, 8000]

templates = {
    "UPI Fraud": [
        "I was trying to sell my {item} on OLX. A buyer named {name} contacted me and sent a QR code on WhatsApp saying scan this to receive the payment. I scanned it and entered my UPI PIN, and Rs. {amount} was debited from my account.",
        "Received a QR code from a random number on Google Pay. They told me I won a cashback of {amount}. As soon as I scanned it and put in my PIN, my money was stolen.",
        "A person claiming to buy my {item} sent a request to pay on PhonePe. Instead of receiving, I clicked pay, entered my UPI PIN, and lost Rs. {amount}.",
        "I tried to send money to {name} via UPI but the transaction failed. Later I got a call from someone pretending to be Google Pay customer care. They sent a link, asked me to enter my UPI pin, and debited {amount} from my account.",
        "Scanned a barcode at a local shop that was replaced by a fraudster. The money went to a private account of {name} instead of the merchant, losing {amount} rupees."
    ],
    "Banking Fraud": [
        "I received a call from a person claiming to be a manager from {bank}. He said my debit card is blocked and I need to share my card number, CVV, and OTP to unblock it. I shared it and Rs. {amount} was debited from my account.",
        "A caller said my credit card rewards are expiring and asked me to download an app. After downloading it, my bank account details were compromised and {amount} was transferred.",
        "Received SMS saying my {bank} net banking account is locked. Clicked the link, entered my username and password, then shared the OTP. Immediately {amount} was deducted.",
        "I noticed unauthorized transactions on my {bank} bank account. Someone transferred Rs. {amount} using net banking without my permission or knowledge. I did not receive any OTP.",
        "Fraudster called posing as {bank} support, asking to verify my bank account details. After sharing credit card number and OTP, I lost {amount} rupees."
    ],
    "Loan Scam": [
        "I downloaded a quick loan app called EasyLoan from the internet. They approved a loan of 5000 and credited only 3000, but now they are demanding {amount} rupees. They have hacked my contacts and are sending morphed photos of me to my family.",
        "Applied for an instant loan online. They asked for processing fees of Rs. {amount} first. I transferred it via UPI, but they blocked my number and never gave the loan.",
        "An app called CashDirect is harassing me. They are threatening my sister and father by calling them and saying I am a thief. They are demanding {amount} double the loan amount in interest.",
        "I am being blackmailed by a mobile loan app. They accessed my gallery and are threatening to share my personal pictures unless I pay {amount} immediately.",
        "Received WhatsApp message offering instant personal loan without documents. They charged Rs. {amount} as legal fees and insurance premium, then disappeared."
    ],
    "Lottery Scam": [
        "I received a call and WhatsApp message saying I have won the KBC Kaun Banega Crorepati lottery of 25 lakhs. They asked me to transfer Rs. {amount} as GST and registration charges to a bank account. I paid but they are asking for more money.",
        "Got an email claiming I won a lucky draw from Coca Cola of 1 Million dollars. They asked for processing fee of Rs. {amount}. I paid it but got nothing in return.",
        "A scratch card was delivered to my house by post showing I won a Tata Safari. I called the number, they asked for RTO tax and registration fee of Rs. {amount}. I paid it and now their number is switched off.",
        "Got an SMS saying my phone number won the International Mobile Lottery. To release the prize, I was forced to deposit {amount} rupees into a suspicious bank account.",
        "Someone contacted me claiming I won a free holiday package and a cash prize. Sent {amount} as deposit fee, now they are unreachable."
    ],
    "Investment Scam": [
        "I was added to a Telegram channel that promises double returns in crypto trading. I invested Rs. {amount} in their scheme. Now they have deleted the group and blocked me on telegram.",
        "A company called SmartWealth promised 5% daily returns on stock market. I created an account on their website and deposited Rs. {amount}. Now the website is down and my broker is not responding.",
        "I put Rs. {amount} into an online investment plan that promised high weekly dividends. They showed virtual profits in the dashboard, but when I tried to withdraw, they asked for 20% tax and blocked my login.",
        "Met a girl on Instagram who suggested a gold trading app. I transferred {amount} rupees to her broker account. Now she has deleted her profile and my account is locked.",
        "Pushed by a WhatsApp group admin to buy pre-IPO shares. Transferred Rs. {amount} to a private bank account. No shares were credited, and they kicked me out of the group."
    ],
    "Job Scam": [
        "I received a WhatsApp offer for a part-time job liking YouTube videos and rating hotels. Initially, they paid Rs. 150. Then they asked me to complete merchant tasks. I paid Rs. {amount} but they did not return my principal and are asking for more to release funds.",
        "Applied for a job at Indigo Airlines on a job portal. A person claiming to be HR contacted me and asked to pay Rs. {amount} for security deposit, uniform, and medical checkup. They sent a fake offer letter.",
        "Offered a work from home data entry job. I had to sign an agreement. Later they said my work has errors and I violated terms, and they are threatening legal action unless I pay them Rs. {amount}.",
        "Posing as Amazon recruiters, they offered a product reviews job. Asked for a security fee of Rs. {amount} to activate the employee dashboard. They cut off all contacts after payment.",
        "Paid Rs. {amount} to an agency promising a job in Canada. They gave a fake visa copy and now their office in Noida is locked."
    ],
    "Delivery Scam": [
        "I got an SMS saying my FedEx package is on hold because it contains illegal items like MDMA and passports. Then I got a Skype call from someone posing as Mumbai Customs / CBI. They threatened me and forced me to transfer Rs. {amount} to clear my name.",
        "Received message saying my electricity bill is pending and electricity will be cut. Called the number given, they asked me to install AnyDesk and pay 10 rupees. After doing that, Rs. {amount} was debited from my account.",
        "Got a message that my India Post courier address is incorrect. Clicked link to update address and pay Rs. 5. My bank details were compromised and Rs. {amount} was debited.",
        "Received a call from a delivery boy saying I have a cash-on-delivery package from Amazon. I said I didn't order. He asked me to share OTP to cancel the order. I shared the OTP and Rs. {amount} was stolen from my UPI.",
        "A courier company called saying a package containing expensive jewelry is stuck in customs. They demanded {amount} as customs clearance fee, which I paid, but no package arrived."
    ],
    "Sextortion": [
        "I received a video call on WhatsApp from an unknown number. A girl was naked. She took a screenshot of my face and recorded the call. Now she is blackmailing me saying she will send the video to my family and post it on Facebook unless I pay Rs. {amount}.",
        "A person on Instagram befriended me and we shared private photos. Now they are threatening to upload my photos to a porn site and share with my LinkedIn contacts. They have demanded Rs. {amount}.",
        "Received a call from someone posing as a Delhi Police Cyber Cell officer saying a complaint is filed against me for watching a viral video. He demanded {amount} to settle the case and delete the video from YouTube.",
        "Blackmailed by a user who recorded our chat and webcam video. They want {amount} sent via UPI to a specific ID, otherwise they will post it on my company's social media page.",
        "An unknown WhatsApp caller recorded a video call of me and is now demanding {amount} rupees. Posing as YouTube moderator, they said they will remove the video only if I pay."
    ],
    "Social Media Fraud": [
        "Someone created a fake Facebook account using my name and photos. They are sending messages to all my friends and relatives asking for urgent money of Rs. {amount} saying I am admitted to the hospital.",
        "My Instagram account was hacked. The hacker changed my email and phone number and is posting stories offering high returns on crypto investment to cheat my followers.",
        "A Facebook friend whom I have never met said he sent an expensive gift from London. Later I got a call from Delhi Airport customs saying I need to pay customs duty of Rs. {amount} to release the package.",
        "A hacker took control of my WhatsApp account by asking for a verification code. Now he is asking all my contacts for urgent loans of Rs. {amount}.",
        "A fake profile of our school principal was created on Twitter. They messaged parents asking for a donation of {amount} rupees via UPI link."
    ],
    "Phishing Attack": [
        "I clicked on a link in an email that looked exactly like HDFC Netbanking (hdfcbank-net-secure.com). I entered my user ID and password. Immediately after, Rs. {amount} was debited from my savings account.",
        "I wanted to update my KYC for Paytm. I searched for Paytm customer care on Google and called a number. They sent a link (paytm-kyc-verify.info) which stole my wallet credentials and Rs. {amount}.",
        "I received a phishing email claiming my Netflix subscription failed and asked me to update billing. I entered my credit card details, and unauthorized transactions of Rs. {amount} occurred.",
        "Clicked a fake link for PAN card and Aadhaar card linking. It took me to a cloned government site where I entered banking credentials, leading to a fraud of {amount} rupees.",
        "A link was clicked by me to get a free shopping coupon of Rs 5000. It opened a page looking like Amazon login. My password was stolen and used to purchase items worth Rs. {amount}."
    ]
}

# Build dataset of 600 samples
complaint_data = []
for category, list_templates in templates.items():
    # Let's generate 60 samples per category
    for _ in range(60):
        tmpl = random.choice(list_templates)
        desc = tmpl.format(
            item=random.choice(items),
            name=random.choice(names),
            bank=random.choice(banks),
            amount=random.choice(amounts)
        )
        complaint_data.append({"description": desc, "category": category})

df_complaint = pd.DataFrame(complaint_data)

# Split and train
X_train_comp, X_test_comp, y_train_comp, y_test_comp = train_test_split(
    df_complaint["description"], df_complaint["category"], test_size=0.15, random_state=42, stratify=df_complaint["category"]
)

comp_vectorizer = TfidfVectorizer(max_features=2500, stop_words="english", ngram_range=(1, 2))
X_train_comp_vec = comp_vectorizer.fit_transform(X_train_comp)
X_test_comp_vec = comp_vectorizer.transform(X_test_comp)

comp_model = RandomForestClassifier(n_estimators=100, random_state=42)
comp_model.fit(X_train_comp_vec, y_train_comp)

print("Complaint Categorizer Test Accuracy:", comp_model.score(X_test_comp_vec, y_test_comp))

# Save Complaint Classifier
with open("models/complaint_vectorizer.pkl", "wb") as f:
    pickle.dump(comp_vectorizer, f)
with open("models/complaint_model.pkl", "wb") as f:
    pickle.dump(comp_model, f)


# ==========================================
# 2. GENERATE SMS/MESSAGE SCAM DATASET
# ==========================================
print("Generating SMS/message scam dataset...")

scam_messages = [
    "Dear customer, your SBI account is blocked due to KYC. Please update immediately at http://sbi-secure-kyc.net to avoid suspension.",
    "Congratulations! You have won a lottery of Rs. 25,00,000 from KBC. To claim your prize money, contact Mr. Vijay on WhatsApp at 9876543210.",
    "Urgent: Your electricity bill is unpaid. Connection will be disconnected tonight at 9.30 PM. Immediately call electricity officer at 8827392819.",
    "Earn Rs. 5000/day by liking YouTube videos in your free time. Work from home, no experience needed. Apply now at https://bit.ly/job-apply-here",
    "Dear customer, your card is blocked. Call customer service immediately on 1800-XXX-XXXX or click here http://bank-card-unlock.info.",
    "You have been pre-approved for an instant loan of Rs 5,00,000 with 0% interest. Click to get instant credit in 2 minutes: http://easy-loan.in",
    "Your parcel from FedEx is detained by customs. Pay Rs. 1450 to clear delivery immediately. Link: http://fedex-customs-verify.org",
    "Hi, I saw your video online. It is very embarrassing. Delete it immediately or I will share it on Facebook. Contact me now: http://sextortion-leak.net",
    "Emergency: I am in the hospital and need Rs. 15,000 urgently. Please send to UPI ID: rajesh.med@paytm. This is Rajesh.",
    "Get Rs. 500 Paytm cashback on your recent transaction. Click here to claim your reward: http://paytm-cashback-collect.cc",
    "Your Netflix account is suspended due to payment failure. Update card details now to continue watching: http://netflix-secure-billing.com",
    "Dear user, your SIM card KYC expired. Your outgoing calls will be stopped. Call Airtel KYC executive at 7738291029.",
    "Claim your free voucher of Rs. 2000 from Amazon. Offer valid for 2 hours. Link: http://amazon-rewards-free.info",
    "Make money online quickly! Sign up today and get Rs. 200 sign up bonus. 100% legal investment. Link: http://quick-rich.org",
    "Your PAN Card linking with Aadhaar is pending. Fine of Rs. 10000 will be charged. Click http://income-tax-pan-link.cc to link now."
] * 25  # 375 samples

ham_messages = [
    "Your OTP for transaction of Rs. 5000 is 482910. Do not share this OTP with anyone for security reasons.",
    "Hey! Are you planning to come to the office today? Let me know if we can have lunch together.",
    "Dear Customer, your account XXX1284 has been credited with Rs. 45,000 towards monthly salary. SBI.",
    "Your order number #93829 has been shipped and will be delivered by BlueDart on Saturday. Track at bluedart.com.",
    "Dear candidate, your interview with TCS is scheduled for tomorrow at 10:00 AM. Please join via Teams link.",
    "Hi Mom, I reached the hostel safely. The weather here is nice. Will call you in the evening.",
    "Your monthly electricity bill for account 849301 is Rs. 1,420. Due date is 25th June. Pay via official portal.",
    "Dear student, your assignment submission deadline has been extended to Friday. Check classroom portal.",
    "Happy Birthday Amit! Wishing you a wonderful year ahead filled with happiness and success.",
    "Can you please send me the presentation slides by 5 PM? We have a client call tomorrow morning.",
    "Your subscription to Spotify has been renewed successfully. Next billing date is 19th July.",
    "Dear patient, your appointment with Dr. Sharma is confirmed for 4:30 PM today. Please arrive 10 minutes early.",
    "Thank you for dining at Barbeque Nation. Your feedback is important to us. Rate us at our website.",
    "Hey, did you finish the coding task? I need a quick review of the pull request.",
    "Meeting rescheduled to 3 PM today due to some internal conflicts. Hope this works."
] * 25  # 375 samples

sms_texts = scam_messages + ham_messages
sms_labels = ["scam"] * len(scam_messages) + ["ham"] * len(ham_messages)

df_sms = pd.DataFrame({"text": sms_texts, "label": sms_labels})

X_train_sms, X_test_sms, y_train_sms, y_test_sms = train_test_split(
    df_sms["text"], df_sms["label"], test_size=0.15, random_state=42, stratify=df_sms["label"]
)

sms_vectorizer = TfidfVectorizer(max_features=1500, stop_words="english")
X_train_sms_vec = sms_vectorizer.fit_transform(X_train_sms)
X_test_sms_vec = sms_vectorizer.transform(X_test_sms)

sms_model = MultinomialNB()
sms_model.fit(X_train_sms_vec, y_train_sms)

print("SMS Classifier Test Accuracy:", sms_model.score(X_test_sms_vec, y_test_sms))

# Save SMS Classifier
with open("models/scam_vectorizer.pkl", "wb") as f:
    pickle.dump(sms_vectorizer, f)
with open("models/scam_model.pkl", "wb") as f:
    pickle.dump(sms_model, f)


# ==========================================
# 3. PHISHING URL FORENSIC MODEL TRAINING
# ==========================================
print("\nTraining Phishing URL model using repeatable pipeline...")
try:
    from train_phishing_model import train_and_evaluate
    # Train model using real non-synthetic Training.parquet dataset
    train_and_evaluate("datasets/Training.parquet")
    print("SUCCESS: URL forensic classifier trained and persisted.")
except Exception as e:
    print(f"FAIL: Phishing URL model training failed: {e}")


import requests
import time
import datetime

# ضع الرابط الذي تريد زيارته هنا
TARGET_URL = "http://127.0.0.1:30170" 

def start_pinging():
    print(f"[*] Starting keep-alive bot for: {TARGET_URL}")
    while True:
        try:
            response = requests.get(TARGET_URL)
            now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{now}] Visited! Status Code: {response.status_code}")
        except Exception as e:
            print(f"[!] Error visiting site: {e}")
        
        # الانتظار لمدة 5 دقائق (300 ثانية)
        time.sleep(300)

if __name__ == "__main__":
    start_pinging()

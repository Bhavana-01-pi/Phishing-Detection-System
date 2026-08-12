from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.common.exceptions import WebDriverException, TimeoutException
from urllib.parse import urlparse
import time
import os
import imagehash 
from PIL import Image, ImageStat # <--- UPDATED: Added ImageStat
from config import BRAND_DATABASE 

def is_image_blank(image_path):
    """
    Checks if an image is mostly single-colored (blank/white/black).
    Returns True if the image has very little detail.
    """
    try:
        img = Image.open(image_path).convert("L") # Convert to grayscale
        stat = ImageStat.Stat(img)
        # If standard deviation is very low (< 15), there's little variation (solid color)
        if stat.stddev[0] < 15: 
            return True
        return False
    except:
        return False

def get_visual_analysis(url):
    """
    Takes a screenshot using Standard Selenium with Eager loading.
    Clean version: No debug prints.
    """
    options = Options()
    options.add_argument('--headless=new') 
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    options.add_argument('--disable-gpu')
    options.add_argument('--window-size=1920,1080')
    
    options.add_argument('--ignore-certificate-errors')
    options.add_argument('--disable-popup-blocking')
    options.add_argument('--disable-notifications')
    options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

    # Fast loading strategy
    options.page_load_strategy = 'eager'
    
    report = {}
    is_clone = False
    cloned_brand = ""
    driver = None
    
    try:
        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=options)
        
        # Set timeout to 25 seconds
        driver.set_page_load_timeout(25) 
        
        try:
            driver.get(url)
        except TimeoutException:
            # If loading takes too long, stop and try to take what we have
            try:
                driver.execute_script("window.stop();")
            except:
                pass
        except Exception:
            pass

        # Wait 4 seconds for rendering (Good for heavy sites like Microsoft)
        time.sleep(4) 
        
        screenshot_path = 'static/screenshot.png'
        driver.save_screenshot(screenshot_path)
        driver.quit()
        driver = None

        # --- NEW: SMART CHECK FOR BLANK PAGES ---
        if is_image_blank(screenshot_path):
            report['message'] = "⚠️ Visual analysis skipped (Page content unavailable/blank)."
            report['risk_added'] = 0
            return report
        # ----------------------------------------

        # --- START OF pHash ANALYSIS ---
        try:
            scanned_hash = imagehash.phash(Image.open(screenshot_path))
            scanned_domain = urlparse(url).netloc.lower()
            best_match_diff = 100
            best_match_brand = ""

            for brand, data in BRAND_DATABASE.items():
                ref_path = data['ref_image_path']
                if not os.path.exists(ref_path):
                    continue

                ref_hash = imagehash.phash(Image.open(ref_path))
                diff = scanned_hash - ref_hash
                
                if diff < best_match_diff:
                    best_match_diff = diff
                    best_match_brand = brand

            if best_match_diff < 12: 
                real_domain = BRAND_DATABASE[best_match_brand]['domain']
                if real_domain not in scanned_domain:
                    is_clone = True
                    cloned_brand = best_match_brand.capitalize()

            if is_clone:
                report['message'] = f"❌ CRITICAL: Page is a 99% visual clone of {cloned_brand}!"
                report['risk_added'] = 50
            else:
                report['message'] = "✔️ Visual analysis complete. No visual clones detected."
                report['risk_added'] = 0

        except Exception:
            report['message'] = "⚠️ Visual analysis incomplete (Image error)."
            report['risk_added'] = 0
        # --- END OF pHash ANALYSIS ---

    # --- Handle Timeouts gracefully ---
    except TimeoutException:
        report['message'] = "⚠️ Visual analysis: Page slow, partial screenshot captured."
        report['risk_added'] = 0 

    except Exception as e:
        err_str = str(e).lower()
        if "err_name_not_resolved" in err_str:
             report['message'] = "⚠️ Visual analysis skipped (Site unreachable)."
        elif "timeout" in err_str:
             report['message'] = "⚠️ Visual analysis skipped (Connection timed out)."
        else:
             report['message'] = "⚠️ Visual analysis skipped (Site not responding)."
        report['risk_added'] = 0
        
    finally:
        if driver:
            try:
                driver.quit()
            except:
                pass

    return report
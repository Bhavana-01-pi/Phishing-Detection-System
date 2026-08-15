# Phishing URL Detection 

<!--
![image2](https://github.com/asrith-reddy/Phishing-detector/assets/76733972/da226de9-dfe6-4f0c-a8bc-b92d4cc08e53)

![image1](https://github.com/asrith-reddy/Phishing-detector/assets/76733972/fe706a06-84fe-493f-abb8-34d3fbc594b5)
-->
<img width="1337" height="638" alt="Screenshot1" src="https://github.com/user-attachments/assets/94750580-bbc4-453e-9718-8679b8abeec0" />


## Objective

A phishing website is a common social engineering method that mimics trustful uniform resource locators (URLs) and webpages to deceive users into disclosing sensitive personal, financial, or authentication data. The objective of this project is to build an end-to-end phishing detection and forensic analysis system that combines Supervised Machine Learning with Computer Vision (Visual Similarity) and Heuristic Rules.

Both phishing and benign URLs are gathered to form a structured dataset, and essential address-bar, domain, and content-based features are extracted. Nine machine learning models are evaluated and compared. To overcome the limitations of URL-only classification against novel, zero-day phishing attacks, the system integrates real-time headless browser automation to capture live screenshots, perceptual hashing (pHash) to detect visual clones of targeted brands, and Levenshtein distance algorithms to catch typosquatting attempts.

## Installation
1. To install the required packages and libraries, run this command in the project directory after Forking and cloning this repository:
```bash
pip install -r requirements.txt
```
2. Setup Reference Database
To enable visual clone detection against target brands:
Ensure the reference_images/ directory contains baseline screenshots of protected brands (e.g., google.png, netflix.png, paypal.png).
Run the automated capture script to generate or update reference images:
```bash
python capture_references.py
```
3. Run the Web Application
```bash
python app.py
```

## Technologies Used

![](https://forthebadge.com/images/badges/made-with-python.svg)

[<img target="_blank" src="https://upload.wikimedia.org/wikipedia/commons/3/31/NumPy_logo_2020.svg" width=200>](https://numpy.org/doc/) [<img target="_blank" src="https://upload.wikimedia.org/wikipedia/commons/e/ed/Pandas_logo.svg" width=200>](https://pandas.pydata.org/pandas-docs/stable/reference/api/pandas.DataFrame.html)
[<img target="_blank" src="https://upload.wikimedia.org/wikipedia/commons/8/84/Matplotlib_icon.svg" width=100>](https://matplotlib.org/)
[<img target="_blank" src="https://scikit-learn.org/stable/_static/scikit-learn-logo-small.png" width=200>](https://scikit-learn.org/stable/) 
[<img target="_blank" src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcScq-xocLctL07Jy0tpR_p9w0Q42_rK1aAkNfW6sm3ucjFKWML39aaJPgdhadyCnEiK7vw&usqp=CAU" width=200>](https://flask.palletsprojects.com/en/2.0.x/) 

## Feature Extraction
The system starts by retrieving URLs to be analyzed from the user input through the interactive web interface. Once the URL is received, the system extracts critical structural and domain characteristics to evaluate risk:

#### 1.Address Bar & Structural Features:

IP Address in URL: Checks if the domain is represented as a raw IP (e.g., [http://192.168.1.1](http://192.168.1.1)).

URL Length: Flags abnormally long URLs designed to obscure the domain path.

Shortening Services: Identifies redirection techniques through services like bit.ly or tinyurl.

@ Symbol Usage: Detects browser redirection instructions where everything preceding @ is ignored.

Prefix/Suffix Separation: Analyzes hyphens (-) used in domain names to impersonate brands.

Subdomains & Multi-Level Domains: Measures domain depth and nesting levels.

#### 2.Domain & Network Features:

HTTPS / SSL Certificate Status: Verifies whether the site uses valid, trusted encryption protocols.

Domain Registration Length: Evaluates domain longevity; phishing domains are typically registered for minimal durations (1 year).

#### 3.Heuristic & Impersonation Features:

Typosquatting Detection: Uses the Levenshtein Distance algorithm to calculate character edit distances against known legitimate brands (e.g., detecting paypa1.com instead of paypal.com).

Keyword Impersonation: Scans subdomains and paths for unauthorized brand names (e.g., netflix-support.com).

## Machine Learning Models

Various machine learning models are compared and The machine learning model with high accuracy is selected which predicts whether the URL is a phishing site or not. It provides a probability score or a binary classification (phishing or not phishing) based on the trained model's decision boundary. The system categorize URLs into "phishing" or "legitimate" and the result is finally displayed on the webpage. 
#### Refer Phishingproject.ipynb for more details.

## Result

Accuracy of various model used for URL detection
<br>

<br>

||ML Model|	Accuracy|  	f1_score|	Recall|	Precision|
|---|---|---|---|---|---|
0|	Gradient Boosting Classifier|	0.974|	0.977|	0.994|	0.986|
1|	CatBoost Classifier|	        0.972|	0.975|	0.994|	0.989|
2|	Multi-layer Perceptron|	        0.969|	0.973|	0.995|	0.981|
3|	Random Forest|	                0.967|	0.971|	0.993|	0.990|
4|	Support Vector Machine|	        0.964|	0.968|	0.980|	0.965|
5|	Decision Tree|      	        0.960|	0.964|	0.991|	0.993|
6|	K-Nearest Neighbors|        	0.956|	0.961|	0.991|	0.989|
7|	Logistic Regression|        	0.934|	0.941|	0.943|	0.927|
8|	Naive Bayes Classifier|     	0.605|	0.454|	0.292|	0.997|

## Visual Similarity Analysis

Visual Similarity Analysis (Computer Vision Layer)URL-based classifiers can be bypassed by zero-day phishing sites hosted on reputable cloud domains or completely new domain names. To counter this, our system incorporates a real-time Visual Analysis pipeline:Headless Browser Capture: Selenium launches a headless Chrome instance with an eager page load strategy to safely visit the URL and take a full-resolution viewport screenshot.Blank Page & Error Filtering: An image variance check (ImageStat.stddev) examines the screenshot. If the site is unreachable, broken, or a blank white screen, visual comparison is skipped to avoid false alarms.Perceptual Hashing (pHash): Unlike cryptographic hashes, pHash generates a 64-bit structural fingerprint based on Discrete Cosine Transforms (DCT) of visual layouts.Hamming Distance Comparison: The generated hash is compared with reference hashes of official brand login portals. If the Hamming difference is below the similarity threshold ($< 12$) while the domain does not match the authentic domain, the page is flagged as a Critical Visual Clone.

## Conclusion
This project demonstrates the complete lifecycle of developing a robust phishing detection system, from Exploratory Data Analysis (EDA) on raw URL datasets to deploying a multi-layered hybrid application.

### Key insights from the project include:

Key Predictive Features: Structural features such as HTTPS availability, Anchor URL distribution, URL length, and registration duration have the strongest influence on machine learning classifiers.

Model Selection: The Gradient Boosting Classifier achieved the highest overall performance with an accuracy of 97.4%, a recall of 0.994, and an F1-score of 0.977, significantly reducing false negatives.

Hybrid Defense: Relying strictly on machine learning can leave gaps when dealing with newly registered, visually deceptive domains. Combining the Gradient Boosting model with Perceptual Hashing (Visual Analysis) and Levenshtein Typosquatting heuristics provides comprehensive, real-time protection against both structured attacks and zero-day visual clones.

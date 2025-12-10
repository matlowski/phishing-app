from django.shortcuts import render
from .forms import UploadFileForm
from gensim.models import Word2Vec 
import joblib 
import email
from email import policy
from email.parser import BytesParser
import re
from bs4 import BeautifulSoup
import requests
import time
import json

import re
import string
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
import numpy as np
import pandas as pd

# zasoby nlp - tokenizacja:
nltk.download('punkt_tab') 

nltk.download('stopwords')
stop_words = set(stopwords.words('english'))

index = 0 

def clean_text(text):
    text = text.lower()    
    text = re.sub(r'http\S+|www\S+|https\S+', '', text, flags=re.MULTILINE)
    text = re.sub(r'\d+', '', text)  
    text = re.sub(r'\n', ' ', text)  
    text = re.sub(r'[%s]' % re.escape(string.punctuation), ' ', text)  
    text = re.sub(r'\s+', ' ', text).strip()
    text = ' '.join([word for word in text.split() if word not in stop_words])
    
    return text



def tokenize(texts):
    tokenized_texts = [
        [word for word in word_tokenize(text.lower()) if word.isalpha() and word not in stop_words]
        for text in texts
    ]
    
    return tokenized_texts



def vectorize(model, tokenized_texts):
    def average_vector(tokens):
        vectors = [model.wv[word] for word in tokens if word in model.wv]
        return np.mean(vectors, axis=0) if vectors else np.zeros(model.vector_size)
    
    vectors = [average_vector(tokens) for tokens in tokenized_texts]
    vector_df = pd.DataFrame(vectors, columns=[f'w2v_{i}' for i in range(model.vector_size)])

    return vector_df



def predict_text(input):
    text = clean_text(input)
    tokenized_texts = tokenize([text]) 
    model = Word2Vec.load("ml\word2vec.model") 
    vector_df = vectorize(model, tokenized_texts)
    clf = joblib.load('ml\model.pkl') 
    prediction = clf.predict(vector_df)
   
    return prediction[0]


def clean_html(html):
    soup = BeautifulSoup(html, 'html.parser')
    text = soup.get_text()
    return re.sub(r'\s+\n', '\n', text).strip()


def get_authentication(msg):
    header = msg.get('Authentication-Results')
    
    # spf
    try: 
        match_1 = re.search(r"spf=([\w\-]+)", header)
        spf = match_1.group(1)
    except:
        spf = None

    # dkim 
    try:
        match_2 = re.search(r"dkim=([\w\-]+)", header)
        dkim = match_2.group(1)
    except:
        dkim = None

    # dmarc
    try:
        match_3 = re.search(r"dmarc=([\w\-]+)", header)
        dmarc = match_3.group(1)
    except:
        dmarc = None

    authentication_results = {
        'SPF': spf, 
        'DKIM': dkim, 
        'DMARC': dmarc
    }

    return authentication_results



def check_ip(sender_ip):
    API_KEY = '' # TUTAJ NALEŻY DODAĆ SWÓJ KLUCZ  ABUSEIPDB !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    IP = f"{sender_ip}"
    url = "https://api.abuseipdb.com/api/v2/check"

    params = {
        "ipAddress": IP,
        "maxAgeInDays": 90,
        "verbose": True
    }
    headers = {
        "Key": API_KEY,
        "Accept": "application/json"
    }

    response = requests.get(url, headers=headers, params=params)
    data = response.json().get("data", {})

    if data.get("abuseConfidenceScore", 0) > 25:
        print(f"*** IP {IP} is malicious (Score: {data['abuseConfidenceScore']}).")
        return True
    else:
        print(f"*** IP {IP} is clean.")
        return False



def get_ip(msg):
    received_headers = msg.get_all("Received", [])

    ip_regex = re.compile(r'\[?(\d{1,3}(?:\.\d{1,3}){3})\]?')

    for header in reversed(received_headers):
        match = ip_regex.search(header)
        if match:
            sender_ip = match.group(1)
            print("*** Znaleziony adres IP nadawcy:", sender_ip)
            return check_ip(sender_ip)
    else:
        raise Exception()



def get_text(msg):
    text_content = ""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == 'text/plain' and not part.get_filename():
                text_content += part.get_content().strip()

        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == 'text/html' and not part.get_filename():
                html = part.get_content()
                html_sample = clean_html(html)
                text_content += html_sample.strip()

    else:
        content_type = msg.get_content_type()
        content = msg.get_content()
        if content_type == 'text/plain':
            text_content = content.strip()
        elif content_type == 'text/html':
            html_samp = clean_html(content)
            text_content = html_samp.strip()

    return text_content
 

VIRUSTOTAL_URL = 'https://www.virustotal.com/api/v3/'
VIRUSTOTAL_API_KEY = ''    # TUTAJ NALEŻY DODAĆ SWÓJ KLUCZ  VIRUSTOTAL !!!!!!!!!!!!!!!!!!!!!!!!!!
def check_url(urls): 

    headers = {
        'accept': 'application/json',
        'x-apikey': VIRUSTOTAL_API_KEY,
    }

    print('***')
    for url in urls:
        print(url)
    print('***')

    final_url_rate = {}
    counter = 1 
    for url in urls:
        payload = { "url": url }
        headers['content-type'] = 'application/x-www-form-urlencoded'
        response = requests.post(VIRUSTOTAL_URL + 'urls', data=payload, headers=headers)
        
        time.sleep(5)

       
        id = response.json()['data']['id']
        del headers['content-type']
        response = requests.get(VIRUSTOTAL_URL + 'analyses/' + id, headers=headers)

        results_for_url = [] 
        for _, statistics in response.json()['data']['attributes']['results'].items(): 
            if statistics['result'] not in results_for_url:
                results_for_url.append(statistics['result']) 

        final_url_rate[url] = results_for_url

        for url, rates in final_url_rate.items():
            if ('phishing' or 'malicious' or 'malware' or 'suspicious' or 'spam') in rates:
                pass

        if counter % 2 == 0:
            print('waiting for minute ...')
            time.sleep(61)

        counter += 1 

    print('*** URLE ALE REZULTATY ***')
    for url, results in final_url_rate.items():
        print(f'url: {url}, results: {results}')

    return True


def get_url_addresses(text_content):
    print('*** TEKST WIADOMOŚCI ***')
    print(text_content)
    print('*** KONIEC WIADOMOŚCI ***')

    urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', text_content)
    
    unique_urls = []
    for url in urls:
        if url not in unique_urls:
            unique_urls.append(url)

    return unique_urls



VIRUSTOTAL_URL = 'https://www.virustotal.com/api/v3/'

def analyze_attachment(attachments): 
    attachment_results = {}

    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY
        }

    for attachment in attachments:
        file_name = attachment['filename']
        content_type = attachment['content_type']
        payload = attachment['payload']

        files = {'file': (file_name, payload, content_type)}
        response = requests.post(VIRUSTOTAL_URL + 'files', files=files, headers=headers)

        try:
            attachment_id = response.json()['data']['id']
        except:
            print('Error getting file analysis result')
            print(response.text)
            continue
        
        time.sleep(3)

        response = requests.get(VIRUSTOTAL_URL + 'analyses/' + attachment_id, headers=headers)
        attachment_results[file_name] = response.json()['data']['attributes']['stats']

    print(json.dumps(attachment_results, indent=4, ensure_ascii=False))

    return attachment_results



def get_attachment(msg): 
    attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            cd = part.get("Content-Disposition") 
            if cd and cd.content_disposition == 'attachment': 
                attachment = {}
                print('*** TESTOWE DANE ZAŁĄCZNIKA ***')
                print(part.get_filename())
                print(part.get_content_type())
                print('*** ***')
                attachment['filename'] = part.get_filename()          
                attachment['content_type'] = part.get_content_type()  
                attachment['payload'] = part.get_payload(decode=True) 
                attachments.append(attachment)
    else: 
        pass

    return attachments



def parser(uploaded_file):
    result = {}
   
    uploaded_file.seek(0)
    msg = BytesParser(policy=policy.default).parse(uploaded_file)
    
    ### DKIM, SPF, DMARC 
    authentication_results = get_authentication(msg)
    result['authentication'] = authentication_results

    ### ADRES IP NADAWCY
    try:
        result['ip_address'] = get_ip(msg)
    except:
        print('Not found IP address')

    ### TEKST 
    text_content = get_text(msg)
    #result['text'] = predict_text(text_content)

    ### URL 
    urls = get_url_addresses(text_content)
    result['urls'] = check_url(urls)

    # ZAŁĄCZNIKI 
    attachment_content = get_attachment(msg)
    result['attachment'] = analyze_attachment(attachment_content)

    return result



def home(request):
    if request.method == 'POST':
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_file = request.FILES['file']
            result = parser(uploaded_file)
            context = {'response': result}
            return render(request, 'ml/result.html', context)
    else:
        form = UploadFileForm()

    context = {'form': form}

    return render(request, 'ml/home.html', context)
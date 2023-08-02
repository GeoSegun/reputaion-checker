import streamlit as st
import requests

VT_API_KEY = '099466529d16f11466dce0ba24a3448a2dc2a39292e42207c0ed4dd6b045dbf3'  # Replace with your actual VirusTotal API key

def check_malicious_url(url):
    url = f'https://www.virustotal.com/api/v3/domains/{url}'
    headers = {'x-apikey': VT_API_KEY}
    response = requests.get(url, headers=headers)
    return response.json()

def main_url():
    st.title('Malicious URL Checker')
    st.write('Enter URLs to check if they are malicious or not, separated by newline.')

    url_input = st.text_area('Enter URLs:', '', height=200)
    url_lines = url_input.split('\n')

    malicious_urls = []

    if st.button('Check URLs'):
        if url_lines:
            st.write('Checking URLs:')
            with st.spinner('Checking...'):
                for url in url_lines:
                    result = check_malicious_url(url.strip())
                    if 'data' in result and 'attributes' in result['data']:
                        if result['data']['attributes']['last_analysis_stats']['malicious'] > 0:
                            malicious_urls.append(url)
            st.text('\n'.join(malicious_urls))

def check_ip_malicious(ip):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    headers = {'x-apikey': VT_API_KEY}
    response = requests.get(url, headers=headers)
    return response.json()

def main_ip():
    st.title('Malicious IP Checker')
    st.write('Enter IP addresses to check if they are malicious or not, separated by newline.')

    ip_list = st.text_area('Enter IP Addresses:', '', height=200)
    ip_lines = ip_list.split('\n')

    malicious_ips = []

    if st.button('Check IPs'):
        if ip_lines:
            st.write('Checking IP addresses:')
            with st.spinner('Checking...'):
                for ip in ip_lines:
                    result = check_ip_malicious(ip.strip())
                    if 'data' in result and 'attributes' in result['data']:
                        if result['data']['attributes']['last_analysis_stats']['malicious'] > 0:
                            malicious_ips.append(ip)
            st.text('\n'.join(malicious_ips))

if __name__ == '__main__':
    main_url()
    main_ip()

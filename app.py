import streamlit as st
import requests

def check_malicious_url(url, api_key):
    url = f'https://www.virustotal.com/api/v3/domains/{url}'
    headers = {'x-apikey': api_key}
    response = requests.get(url, headers=headers)
    return response.json()

def main_url(api_key):
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
                    result = check_malicious_url(url.strip(), api_key)
                    if 'data' in result and 'attributes' in result['data']:
                        if result['data']['attributes']['last_analysis_stats']['malicious'] > 0:
                            malicious_urls.append(url)
                        
                            st.error(f'The URL {url} is malicious.')
                        else:
                            st.success(f'The URL {url} is clean.')

def check_ip_malicious(ip, api_key):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    headers = {'x-apikey': api_key}
    response = requests.get(url, headers=headers)
    return response.json()

def main_ip(api_key):
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
                    result = check_ip_malicious(ip.strip(), api_key)
                    if 'data' in result and 'attributes' in result['data']:
                        if result['data']['attributes']['last_analysis_stats']['malicious'] > 0:
                            malicious_ips.append(ip)
                            st.write(ip)
                            # st.error(f'The IP {ip} is malicious.')
                        # else:
                        #     st.success(f'The IP {ip} is clean.')

def main():
    st.sidebar.title('VirusTotal API Key')
    api_key = st.sidebar.text_input('Enter your VirusTotal API Key:', type='password')

    if api_key:
        main_url(api_key)
        main_ip(api_key)

if __name__ == '__main__':
    main()

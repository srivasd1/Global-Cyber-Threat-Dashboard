from email import header
import streamlit as st
import pandas as pd
import plotly.express as px
import requests
from io import StringIO

st.set_page_config(
            page_title = "Global Cyber Threat Dashboard",
            #page_icon = "",
            layout="wide"
)




#st.write("Malware Detections by Signature — Last 24 Hours")
#st.write("Interactive dashboard for analysing global cyber threat activity.")
#
#if "MALWAREBAZAAR_AUTH_KEY" in st.secrets:
 #   st.success("MalwareBazaar API key loaded successfully.")
#else:
 #   st.error("MalwareBazaar API key is not available.")
#st.subheader("Live MalwareBazaar Data")
malware_url = "https://mb-api.abuse.ch/api/v1/"
haus_url = "https://urlhaus.abuse.ch/downloads/csv_recent/"

headers = {
    "Auth-Key":st.secrets["MALWAREBAZAAR_AUTH_KEY"]
}
#Malware bazar
response =requests.post(
    malware_url,
    headers=headers,
    data={
        "query": "recent_detections",
        "hours": 24
    },
    timeout=30
)
result_malware =response.json()
data_malware = result_malware.get("data", [])
df_malware = pd.DataFrame(data_malware)
    
#haus
response_haus = requests.get(haus_url, headers=headers, timeout=30)

#haus checking
#st.write("HTTP status:", response.status_code)
#st.write("URLhaus HTTP status", response_haus.status_code)
#st.write("Content type", response_haus.headers.get("conent-Type"))
#st.write("Response preview", response_haus.text[:500])

#Haus data in txt not json
df_haus = pd.read_csv(StringIO(response_haus.text), comment="#", header=None)

df_haus.columns = [
    "id",
    "date_added",
    "url",
    "url_status",
    "last_online",
    "threat",
    "tags",
    "urlhaus_link",
    "reporter"
]
#st.subheader("Recent Malicious URLs")



class Plot:
    def __init__(self, data):
        self.data = data
    def bar(self, x, y, title):
        fig = px.bar(self.data, x=x, y=y, color=x, title=title)
        st.plotly_chart(fig, use_container_width=True)




st.subheader("Live cyber Threat Intelligence")
class ThreatDetection:
    def __init__(self, df_malware, df_haus):
        self.df_malware = df_malware
        self.df_haus = df_haus

    def get_recent_malware(self):
        return self.df_malware

    def get_recent_haus(self):
        df=self.df_haus.copy()
        df['date_added'] = pd.to_datetime(df['date_added'], utc=True, errors='coerce')
        last_24h = pd.Timestamp.now(tz="UTC") - pd.Timedelta(hours=24)
        return df[df['date_added'] >= last_24h]
#Create an object
threat = ThreatDetection(df_malware, df_haus)
#Create the switch
source=st.segmented_control(
    "Select Threat Data Source",
    options=["MalwareBazaar", "URLhaus"],
    default="MalwareBazaar"
    )
if source == "MalwareBazaar":
    malware=threat.get_recent_malware()
    st.metric("MalwareBazaar Intelligence Records (Last 24 Hours)", len(malware))
    #st.dataframe(malware)
    counts=malware['signature'].value_counts().reset_index()
    counts.columns=['signature','counts']
    counts_top10=counts.sort_values(by='counts', ascending=False).head(10)
    # Create a bar plot for top 10 signatures 
    plot = Plot(counts_top10)
    plot.bar('signature','counts', "Top 10 Malware Signature (Last 24 Hours)")
    
    st.subheader("MalwareBazaar Threat Details")
    signature = st.selectbox(
        "Select Malware Signature",
        ["All"]+ sorted(malware['signature'].dropna().unique().tolist())
    )
    if signature== "All":
        filtered_malware=malware
    else:
        filtered_malware=malware[malware['signature'] == signature]

    st.dataframe(
        malware[["first_seen", "file_name", "signature", "sha256_hash"]], 
        hide_index=True, 
        use_container_width=True)
    


else:
    haus=threat.get_recent_haus()
    st.metric("URLhaus Intelligence Records (Last 24 Hours)", len(haus))
    counts=haus["url_status"].value_counts().reset_index()
    counts.columns=['url_status','counts']
    plot = Plot(counts)
    plot.bar('url_status','counts', "Active vs inactive malicious URLs (Last 24 Hours)")
    haus['hour'] = pd.to_datetime(haus['date_added'], utc=True, errors='coerce').dt.floor("h")
    counts_hourly = haus['hour'].value_counts().reset_index()
    counts_hourly.columns=['hour','counts']
    plot=Plot(counts_hourly)
    plot.bar('hour','counts', "Malicious URLs by Hour (Last 24 Hours)")
    st.subheader("URLhaus Threat Details")
    status=st.segmented_control(
        "Select URLhaus Threat by Status",
        options=["All", "Online", "Offline"],
        default="Online"
    )
    if status== "All":
        filtered_haus=haus
    else:
        filtered_haus=haus[
        haus["url_status"].str.lower() == status.lower()
    ]

    st.dataframe(
    filtered_haus,
    hide_index=True,
    use_container_width=True
)



import streamlit as st
import re
import pandas as pd
import matplotlib.pyplot as plt
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from collections import Counter, defaultdict
from datetime import datetime, timedelta
import seaborn as sns
import numpy as np
from urllib.parse import urlparse
import io
import warnings
warnings.filterwarnings('ignore')

# Configure Streamlit page
st.set_page_config(
    page_title="HTTP Log Analyzer",
    page_icon="📊",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 5px solid #1f77b4;
    }
    .warning-card {
        background-color: #fff3cd;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 5px solid #ffc107;
    }
    .danger-card {
        background-color: #f8d7da;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 5px solid #dc3545;
    }
</style>
""", unsafe_allow_html=True)

class StreamlitHTTPLogAnalyzer:
    def __init__(self):
        self.df = None
        
    def parse_log_data(self, log_content):
        """แปลงข้อมูล log"""
        lines = log_content.split('\n')
        
        # รูปแบบ regex ที่ปรับปรุงแล้ว
        log_pattern = re.compile(
            r'(?P<ip>\d+\.\d+\.\d+\.\d+).*?\[(?P<timestamp>[^\]]+)\].*?'
            r'"(?P<method>GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) (?P<url>\S+) HTTP/[\d\.]+"\s+'
            r'(?P<status>\d+)\s+(?P<size>\d+|-)'
        )
        
        data = []
        
        progress_bar = st.progress(0)
        total_lines = len(lines)
        
        for i, line in enumerate(lines):
            if i % 100 == 0:  # Update progress every 100 lines
                progress_bar.progress(i / total_lines)
                
            match = log_pattern.search(line)
            if match:
                try:
                    # แปลง timestamp
                    timestamp_str = match.group('timestamp').split()[0]
                    timestamp = datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S')
                    
                    # เก็บข้อมูล
                    size = match.group('size')
                    data.append({
                        'timestamp': timestamp,
                        'ip': match.group('ip'),
                        'url': match.group('url'),
                        'method': match.group('method'),
                        'status_code': int(match.group('status')),
                        'response_size': int(size) if size != '-' else 0
                    })
                    
                except (ValueError, AttributeError):
                    continue
        
        progress_bar.progress(1.0)
        
        if not data:
            return None
            
        # สร้าง DataFrame
        df = pd.DataFrame(data)
        
        # เพิ่มคอลัมน์เสริม
        df['hour'] = df['timestamp'].dt.strftime('%Y-%m-%d %H:00')
        df['date'] = df['timestamp'].dt.date
        df['hour_of_day'] = df['timestamp'].dt.hour
        df['day_of_week'] = df['timestamp'].dt.day_name()
        df['url_path'] = df['url'].apply(lambda x: urlparse(x).path)
        df['file_extension'] = df['url_path'].apply(self.get_file_extension)
        
        return df
    
    def get_file_extension(self, url_path):
        """ดึงนามสกุลไฟล์จาก URL"""
        if '.' in url_path:
            return url_path.split('.')[-1].lower()
        return 'no_extension'
    
    def detect_suspicious_activity(self, df):
        """ตรวจจับกิจกรรมที่น่าสงสัย"""
        suspicious_activities = {}
        
        # 1. IP ที่มี request มากเกินไป
        request_threshold = df['ip'].value_counts().quantile(0.95)
        high_request_ips = df['ip'].value_counts()[
            df['ip'].value_counts() > request_threshold
        ]
        suspicious_activities['high_request_ips'] = high_request_ips
        
        # 2. ตรวจสอบ 404 errors มากเกินไป
        error_404_by_ip = df[df['status_code'] == 404]['ip'].value_counts()
        suspicious_404 = error_404_by_ip[error_404_by_ip > 10]
        suspicious_activities['suspicious_404'] = suspicious_404
        
        # 3. ตรวจสอบ URL patterns ที่น่าสงสัย
        suspicious_patterns = [
            r'\.php$', r'wp-admin', r'phpmyadmin', r'\.sql$', 
            r'admin', r'login', r'\.env$'
        ]
        
        suspicious_urls = []
        for pattern in suspicious_patterns:
            matches = df[df['url'].str.contains(pattern, case=False, na=False)]
            if not matches.empty:
                suspicious_urls.extend(matches['url'].unique())
        
        suspicious_activities['suspicious_urls'] = suspicious_urls[:20]
        
        return suspicious_activities

def main():
    st.markdown('<h1 class="main-header">📊 HTTP Log Analyzer</h1>', unsafe_allow_html=True)
    st.markdown("### วิเคราะห์ไฟล์ Log ของ Web Server")
    
    analyzer = StreamlitHTTPLogAnalyzer()
    
    # Sidebar
    st.sidebar.header("📁 อัปโหลดไฟล์ Log")
    uploaded_file = st.sidebar.file_uploader(
        "เลือกไฟล์ Log", 
        type=['log', 'txt', 'csv'],
        help="รองรับไฟล์ .log, .txt, .csv"
    )
    
    # Sample data option
    if st.sidebar.button("🔧 ใช้ข้อมูลตัวอย่าง"):
        # Create sample log data
        sample_data = """192.168.1.1 - - [19/Jun/2025:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 1234
192.168.1.2 - - [19/Jun/2025:10:00:02 +0000] "POST /login HTTP/1.1" 302 0
192.168.1.3 - - [19/Jun/2025:10:00:03 +0000] "GET /admin HTTP/1.1" 404 512
192.168.1.1 - - [19/Jun/2025:10:00:04 +0000] "GET /style.css HTTP/1.1" 200 2048
192.168.1.4 - - [19/Jun/2025:10:00:05 +0000] "POST /api/data HTTP/1.1" 500 128"""
        
        analyzer.df = analyzer.parse_log_data(sample_data)
    
    if uploaded_file is not None:
        # Read uploaded file
        try:
            log_content = uploaded_file.read().decode('utf-8')
            st.sidebar.success(f"✅ อัปโหลดไฟล์สำเร็จ: {uploaded_file.name}")
            
            with st.spinner("🔄 กำลังประมวลผลข้อมูล..."):
                analyzer.df = analyzer.parse_log_data(log_content)
                
        except Exception as e:
            st.sidebar.error(f"❌ เกิดข้อผิดพลาดในการอ่านไฟล์: {str(e)}")
            return
    
    if analyzer.df is not None and not analyzer.df.empty:
        df = analyzer.df
        
        # Summary Statistics
        st.header("📈 สรุปข้อมูลรวม")
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("🔢 Total Requests", f"{len(df):,}")
        with col2:
            st.metric("🌐 Unique IPs", f"{df['ip'].nunique():,}")
        with col3:
            st.metric("🔗 Unique URLs", f"{df['url'].nunique():,}")
        with col4:
            error_rate = len(df[df['status_code'] >= 400]) / len(df) * 100
            st.metric("⚠️ Error Rate", f"{error_rate:.1f}%")
        
        # Time range
        st.info(f"📅 **ช่วงเวลาข้อมูล:** {df['timestamp'].min()} ถึง {df['timestamp'].max()}")
        
        # Main Analysis Tabs
        tab1, tab2, tab3, tab4, tab5 = st.tabs([
            "📊 ภาพรวม", "🌐 IP Analysis", "🔗 URL Analysis", 
            "🔒 Security Analysis", "📈 Traffic Patterns"
        ])
        
        with tab1:
            st.header("📊 ภาพรวมการใช้งาน")
            
            col1, col2 = st.columns(2)
            
            with col1:
                # Daily requests trend
                daily_requests = df.groupby('date').size().reset_index()
                daily_requests.columns = ['Date', 'Requests']
                
                fig = px.line(daily_requests, x='Date', y='Requests', 
                             title='📈 Requests per Day',
                             markers=True)
                fig.update_layout(height=400)
                st.plotly_chart(fig, use_container_width=True)
                
            with col2:
                # Status code distribution
                status_counts = df['status_code'].value_counts()
                colors = ['green' if x == 200 else 'orange' if str(x).startswith('3') else 'red' 
                         for x in status_counts.index]
                
                fig = px.pie(values=status_counts.values, names=status_counts.index,
                           title='🎯 Status Code Distribution')
                fig.update_traces(marker=dict(colors=['#2ecc71', '#e74c3c', '#f39c12', '#9b59b6']))
                st.plotly_chart(fig, use_container_width=True)
            
            col1, col2 = st.columns(2)
            
            with col1:
                # Hourly traffic pattern
                hourly_pattern = df['hour_of_day'].value_counts().sort_index()
                
                fig = px.bar(x=hourly_pattern.index, y=hourly_pattern.values,
                           title='⏰ Traffic by Hour of Day',
                           labels={'x': 'Hour', 'y': 'Requests'})
                fig.update_layout(height=400)
                st.plotly_chart(fig, use_container_width=True)
                
            with col2:
                # HTTP Methods
                method_counts = df['method'].value_counts()
                
                fig = px.bar(x=method_counts.index, y=method_counts.values,
                           title='🔧 HTTP Methods Distribution',
                           labels={'x': 'Method', 'y': 'Count'})
                fig.update_layout(height=400)
                st.plotly_chart(fig, use_container_width=True)
        
        with tab2:
            st.header("🌐 การวิเคราะห์ IP Address")
            
            col1, col2 = st.columns(2)
            
            with col1:
                # Top IPs
                top_ips = df['ip'].value_counts().head(10)
                
                fig = px.bar(x=top_ips.values, y=top_ips.index, 
                           orientation='h',
                           title='🔝 Top 10 IP Addresses',
                           labels={'x': 'Requests', 'y': 'IP Address'})
                fig.update_layout(height=500)
                st.plotly_chart(fig, use_container_width=True)
                
            with col2:
                # IP request distribution
                ip_request_dist = df['ip'].value_counts()
                
                fig = px.histogram(x=ip_request_dist.values, nbins=30,
                                 title='📊 IP Request Count Distribution',
                                 labels={'x': 'Requests per IP', 'y': 'Number of IPs'})
                st.plotly_chart(fig, use_container_width=True)
            
            # Detailed IP table
            st.subheader("📋 รายละเอียด IP Addresses")
            ip_details = df.groupby('ip').agg({
                'timestamp': ['min', 'max'],
                'status_code': 'count',
                'response_size': 'mean'
            }).round(2)
            
            ip_details.columns = ['First Access', 'Last Access', 'Total Requests', 'Avg Response Size']
            ip_details = ip_details.sort_values('Total Requests', ascending=False)
            
            st.dataframe(ip_details.head(20), use_container_width=True)
        
        with tab3:
            st.header("🔗 การวิเคราะห์ URL")
            
            col1, col2 = st.columns(2)
            
            with col1:
                # Top URLs
                top_urls = df['url'].value_counts().head(10)
                
                # Truncate long URLs for display
                display_urls = [url[:50] + '...' if len(url) > 50 else url for url in top_urls.index]
                
                fig = px.bar(x=top_urls.values, y=display_urls,
                           orientation='h',
                           title='🔝 Top 10 URLs',
                           labels={'x': 'Access Count', 'y': 'URL'})
                fig.update_layout(height=500)
                st.plotly_chart(fig, use_container_width=True)
                
            with col2:
                # File extensions
                ext_counts = df['file_extension'].value_counts().head(10)
                
                fig = px.pie(values=ext_counts.values, names=ext_counts.index,
                           title='📄 File Extension Distribution')
                st.plotly_chart(fig, use_container_width=True)
            
            # URL details table
            st.subheader("📋 รายละเอียด URLs")
            url_details = df.groupby('url').agg({
                'ip': 'nunique',
                'timestamp': 'count',
                'status_code': lambda x: (x >= 400).sum(),
                'response_size': 'mean'
            }).round(2)
            
            url_details.columns = ['Unique IPs', 'Total Requests', 'Error Count', 'Avg Response Size']
            url_details = url_details.sort_values('Total Requests', ascending=False)
            
            st.dataframe(url_details.head(20), use_container_width=True)
        
        with tab4:
            st.header("🔒 การวิเคราะห์ความปลอดภัย")
            
            suspicious_activities = analyzer.detect_suspicious_activity(df)
            
            # Security alerts
            col1, col2, col3 = st.columns(3)
            
            with col1:
                high_req_count = len(suspicious_activities['high_request_ips'])
                if high_req_count > 0:
                    st.markdown(f"""
                    <div class="danger-card">
                        <h4>🚨 High Request IPs</h4>
                        <p><strong>{high_req_count}</strong> IP addresses detected with unusually high requests</p>
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    st.success("✅ No suspicious high-request IPs detected")
            
            with col2:
                sus_404_count = len(suspicious_activities['suspicious_404'])
                if sus_404_count > 0:
                    st.markdown(f"""
                    <div class="warning-card">
                        <h4>⚠️ High 404 Errors</h4>
                        <p><strong>{sus_404_count}</strong> IP addresses with excessive 404 errors</p>
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    st.success("✅ No suspicious 404 patterns detected")
            
            with col3:
                sus_url_count = len(suspicious_activities['suspicious_urls'])
                if sus_url_count > 0:
                    st.markdown(f"""
                    <div class="danger-card">
                        <h4>🔍 Suspicious URLs</h4>
                        <p><strong>{sus_url_count}</strong> potentially malicious URLs detected</p>
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    st.success("✅ No suspicious URL patterns detected")
            
            # Charts
            col1, col2 = st.columns(2)
            
            with col1:
                if len(suspicious_activities['high_request_ips']) > 0:
                    high_req_ips = suspicious_activities['high_request_ips'].head(10)
                    
                    fig = px.bar(x=high_req_ips.values, y=high_req_ips.index,
                               orientation='h',
                               title='🚨 Potentially Suspicious IPs (High Requests)',
                               labels={'x': 'Request Count', 'y': 'IP Address'})
                    fig.update_traces(marker_color='red')
                    st.plotly_chart(fig, use_container_width=True)
                
            with col2:
                # Error rate over time
                error_rates = df.groupby('hour').apply(
                    lambda x: (x['status_code'] >= 400).sum() / len(x) * 100 if len(x) > 0 else 0
                ).reset_index()
                error_rates.columns = ['Hour', 'Error_Rate']
                
                fig = px.line(error_rates, x='Hour', y='Error_Rate',
                            title='📈 Error Rate Over Time (%)',
                            markers=True)
                fig.update_traces(line_color='red')
                st.plotly_chart(fig, use_container_width=True)
            
            # Suspicious URLs list
            if suspicious_activities['suspicious_urls']:
                st.subheader("🔍 URL ที่น่าสงสัย")
                sus_urls_df = pd.DataFrame(suspicious_activities['suspicious_urls'], columns=['Suspicious URLs'])
                st.dataframe(sus_urls_df, use_container_width=True)
        
        with tab5:
            st.header("📈 รูปแบบการใช้งาน")
            
            # Traffic heatmap
            pivot_data = df.groupby(['day_of_week', 'hour_of_day']).size().unstack(fill_value=0)
            day_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
            
            # Reorder days if they exist in the data
            available_days = [day for day in day_order if day in pivot_data.index]
            if available_days:
                pivot_data = pivot_data.reindex(available_days)
            
            fig = px.imshow(pivot_data.values, 
                          x=pivot_data.columns, 
                          y=pivot_data.index,
                          title='🔥 Traffic Heatmap (Day vs Hour)',
                          labels=dict(x="Hour of Day", y="Day of Week", color="Requests"),
                          color_continuous_scale='Reds')
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
            
            col1, col2 = st.columns(2)
            
            with col1:
                # Day of week pattern
                day_pattern = df['day_of_week'].value_counts()
                
                fig = px.bar(x=day_pattern.index, y=day_pattern.values,
                           title='📅 Requests by Day of Week',
                           labels={'x': 'Day', 'y': 'Requests'})
                st.plotly_chart(fig, use_container_width=True)
                
            with col2:
                # Response size distribution
                fig = px.histogram(df, x='response_size', nbins=50,
                                 title='📊 Response Size Distribution',
                                 labels={'x': 'Response Size (bytes)', 'y': 'Count'})
                st.plotly_chart(fig, use_container_width=True)
        
        # Download processed data
        st.header("💾 ดาวน์โหลดข้อมูล")
        col1, col2 = st.columns(2)
        
        with col1:
            csv = df.to_csv(index=False)
            st.download_button(
                label="📥 ดาวน์โหลดข้อมูลที่ประมวลผลแล้ว (CSV)",
                data=csv,
                file_name="processed_log_data.csv",
                mime="text/csv"
            )
        
        with col2:
            # Summary report
            summary_report = f"""
HTTP Log Analysis Summary Report
================================

Data Range: {df['timestamp'].min()} to {df['timestamp'].max()}
Total Requests: {len(df):,}
Unique IPs: {df['ip'].nunique():,}
Unique URLs: {df['url'].nunique():,}
Error Rate: {len(df[df['status_code'] >= 400]) / len(df) * 100:.1f}%

Top 5 IPs:
{df['ip'].value_counts().head().to_string()}

Top 5 URLs:
{df['url'].value_counts().head().to_string()}

Security Alerts:
- High Request IPs: {len(suspicious_activities['high_request_ips'])}
- Suspicious 404 IPs: {len(suspicious_activities['suspicious_404'])}
- Suspicious URLs: {len(suspicious_activities['suspicious_urls'])}
"""
            
            st.download_button(
                label="📄 ดาวน์โหลดรายงานสรุป (TXT)",
                data=summary_report,
                file_name="log_analysis_summary.txt",
                mime="text/plain"
            )
    
    else:
        st.info("👆 กรุณาอัปโหลดไฟล์ Log หรือใช้ข้อมูลตัวอย่างเพื่อเริ่มการวิเคราะห์")
        
        # Show sample log format
        st.subheader("📋 รูปแบบไฟล์ Log ที่รองรับ")
        st.code("""
192.168.1.1 - - [19/Jun/2025:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 1234
192.168.1.2 - - [19/Jun/2025:10:00:02 +0000] "POST /login HTTP/1.1" 302 0
192.168.1.3 - - [19/Jun/2025:10:00:03 +0000] "GET /admin HTTP/1.1" 404 512
        """)

if __name__ == "__main__":
    main()


st.markdown("---")
st.caption("📌 Project by: Nattakaiwan")


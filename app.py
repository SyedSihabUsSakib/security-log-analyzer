import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from log_parser import parse_uploaded_file
from analyzer import (
    get_total_events, get_failed_login_count, get_success_login_count,
    get_ip_statistics, get_suspicious_ips, get_user_statistics,
    get_time_based_analysis, get_security_summary
)
from datetime import datetime

# Page configuration
st.set_page_config(
    page_title="Security Log Analyzer",
    page_icon="🔒",
    layout="wide"
)

# Custom CSS
st.markdown("""
    <style>
    .metric-card {
        background-color: #f0f2f6;
        border-radius: 10px;
        padding: 20px;
        text-align: center;
    }
    .danger { color: #ff4b4b; }
    .success { color: #00cc96; }
    .warning { color: #ffa15a; }
    </style>
""", unsafe_allow_html=True)

# Title
st.title("🔒 Security Log Analyzer Dashboard")
st.markdown("**Analyze authentication logs and detect suspicious activities**")

# Sidebar for file upload
st.sidebar.header(" Upload Log File")
uploaded_file = st.sidebar.file_uploader("Choose a log file", type=['log', 'txt'])

if uploaded_file is not None:
    # Parse the uploaded file
    with st.spinner('Parsing log file...'):
        df = parse_uploaded_file(uploaded_file)
    
    if df.empty:
        st.error("No valid log entries found. Please check the file format.")
    else:
        # Get security summary
        summary = get_security_summary(df)
        
        # Top metrics row
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Events", f"{summary['total_events']:,}")
        
        with col2:
            st.metric("Failed Attempts", f"{summary['failed_attempts']:,}", 
                     delta=f"{summary['failure_rate']:.1f}% failure rate",
                     delta_color="inverse" if summary['failure_rate'] > 30 else "normal")
        
        with col3:
            st.metric("Successful Logins", f"{summary['successful_logins']:,}")
        
        with col4:
            st.metric("Suspicious IPs", f"{summary['suspicious_ip_count']}",
                     delta="High risk!" if summary['suspicious_ip_count'] > 3 else "Normal",
                     delta_color="inverse" if summary['suspicious_ip_count'] > 3 else "normal")
        
        st.markdown("---")
        
        # Two columns for charts
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader(" Event Distribution")
            event_dist = df['status'].value_counts()
            fig_pie = px.pie(values=event_dist.values, names=event_dist.index,
                           color=event_dist.index,
                           color_discrete_map={'Failed': '#ff4b4b', 'Success': '#00cc96'})
            st.plotly_chart(fig_pie, use_container_width=True)
        
        with col2:
            st.subheader("⏰ Events by Hour")
            hourly_data = get_time_based_analysis(df)
            fig_bar = px.bar(hourly_data, x='hour', y='total_events',
                           title='Events Distribution by Hour',
                           labels={'hour': 'Hour of Day', 'total_events': 'Number of Events'})
            st.plotly_chart(fig_bar, use_container_width=True)
        
        # Suspicious IPs Section
        st.markdown("---")
        st.subheader("🚨 Suspicious IP Addresses")
        suspicious_ips = get_suspicious_ips(df, threshold=5)
        
        if not suspicious_ips.empty:
            col1, col2 = st.columns([2, 1])
            with col1:
                st.dataframe(
                    suspicious_ips.style.background_gradient(cmap='Reds', subset=['failed_attempts']),
                    use_container_width=True
                )
            with col2:
                st.warning(f"**{len(suspicious_ips)} IPs** detected with 5+ failed attempts")
                st.info("These IPs should be investigated or blocked")
        else:
            st.success("No suspicious IPs detected with current threshold")
        
        # IP Statistics
        st.markdown("---")
        st.subheader("🌐 IP Address Statistics")
        ip_stats = get_ip_statistics(df)
        
        col1, col2 = st.columns(2)
        with col1:
            st.dataframe(
                ip_stats.head(10).style.background_gradient(cmap='Blues', subset=['total_events']),
                use_container_width=True
            )
        
        with col2:
            fig_ip = px.bar(ip_stats.head(10), x='ip_address', y='total_events',
                          color='failed_attempts',
                          title='Top 10 IP Addresses',
                          labels={'ip_address': 'IP Address', 'total_events': 'Total Events'})
            st.plotly_chart(fig_ip, use_container_width=True)
        
        # User Statistics
        st.markdown("---")
        st.subheader("👥 User Statistics")
        user_stats = get_user_statistics(df)
        
        col1, col2 = st.columns(2)
        with col1:
            st.dataframe(
                user_stats.head(10).style.background_gradient(cmap='Oranges', subset=['failed_attempts']),
                use_container_width=True
            )
        
        with col2:
            fig_user = px.bar(user_stats.head(10), x='username', y='total_attempts',
                            color='failed_attempts',
                            title='Top 10 Targeted Users',
                            labels={'username': 'Username', 'total_attempts': 'Total Attempts'})
            st.plotly_chart(fig_user, use_container_width=True)
        
        # Detailed Logs
        with st.expander("📋 View Raw Log Data"):
            st.dataframe(df, use_container_width=True)
        
        # Download Report
        st.markdown("---")
        st.subheader("📥 Export Report")
        
        # Create summary report
        report_data = {
            'Metric': ['Total Events', 'Failed Attempts', 'Successful Logins', 
                      'Failure Rate', 'Unique IPs', 'Unique Users', 'Suspicious IPs'],
            'Value': [summary['total_events'], summary['failed_attempts'], 
                     summary['successful_logins'], f"{summary['failure_rate']:.2f}%",
                     summary['unique_ips'], summary['unique_users'], 
                     summary['suspicious_ip_count']]
        }
        report_df = pd.DataFrame(report_data)
        
        csv = report_df.to_csv(index=False)
        st.download_button(
            label="Download Security Report (CSV)",
            data=csv,
            file_name=f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )

else:
    # Welcome screen when no file uploaded
    st.info("👈 Upload a log file from the sidebar to begin analysis")
    
    st.markdown("""
    ### What this tool does:
    
    1. ** Total Events** - Shows total authentication events
    2. ** Failed Login Count** - Identifies failed authentication attempts
    3. **🌐 IP-wise Statistics** - Analyzes activity by IP address
    4. **🚨 Suspicious Login Attempts** - Flags IPs with multiple failures
    5. **⏰ Time-based Analysis** - Shows when events occur
    6. **👥 User Statistics** - Identifies targeted accounts
    
    ### Expected Log Format:
    ```
    2024-01-15 10:30:45 Authentication failure for admin from 192.168.1.100
    2024-01-15 10:31:12 Successful login for user1 from 10.0.0.50
    ```
    """)
    
    # Sample data generator
    if st.button("Generate Sample Log File"):
        st.code("""
from datetime import datetime, timedelta
import random

ips = ['192.168.1.100', '10.0.0.50', '172.16.0.25', '203.0.113.42']
users = ['admin', 'root', 'user1', 'guest']
statuses = ['Failed', 'Success', 'Failed', 'Success']

with open('auth.log', 'w') as f:
    base_time = datetime.now() - timedelta(hours=24)
    for i in range(500):
        timestamp = base_time + timedelta(minutes=i*3)
        ip = random.choice(ips)
        user = random.choice(users)
        status = random.choice(statuses)
        
        if status == 'Failed':
            log_line = f"{timestamp} Authentication failure for {user} from {ip}\\n"
        else:
            log_line = f"{timestamp} Successful login for {user} from {ip}\\n"
        
        f.write(log_line)
""", language='python')
        st.success("Run this code to generate a sample log file for testing!")

# Footer
st.markdown("---")
st.markdown("""
<div style='text-align: center'>
    <p><b>Built with Streamlit | Security Log Analyzer</b></p>
    <p>Perfect for: Security Analysts | SOC Teams | IT Administrators</p>
</div>
""", unsafe_allow_html=True)
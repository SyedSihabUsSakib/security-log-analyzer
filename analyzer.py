import pandas as pd
from collections import Counter

def get_total_events(df):
    """Return total number of events"""
    return len(df)

def get_failed_login_count(df):
    """Return count of failed login attempts"""
    return len(df[df['status'] == 'Failed'])

def get_success_login_count(df):
    """Return count of successful logins"""
    return len(df[df['status'] == 'Success'])

def get_ip_statistics(df):
    """Return statistics grouped by IP address"""
    ip_stats = df.groupby('ip_address').agg({
        'status': 'count',
        'username': lambda x: len(x.unique())
    }).rename(columns={
        'status': 'total_events',
        'username': 'unique_users'
    }).reset_index()
    
    # Add failed and success counts per IP
    failed_counts = df[df['status'] == 'Failed'].groupby('ip_address').size()
    success_counts = df[df['status'] == 'Success'].groupby('ip_address').size()
    
    ip_stats['failed_attempts'] = ip_stats['ip_address'].map(failed_counts).fillna(0).astype(int)
    ip_stats['success_attempts'] = ip_stats['ip_address'].map(success_counts).fillna(0).astype(int)
    
    return ip_stats.sort_values('total_events', ascending=False)

def get_suspicious_ips(df, threshold=5):
    """
    Identify suspicious IPs with multiple failed attempts
    Default threshold: 5 failed attempts
    """
    failed_by_ip = df[df['status'] == 'Failed'].groupby('ip_address').size()
    suspicious = failed_by_ip[failed_by_ip >= threshold].reset_index()
    suspicious.columns = ['ip_address', 'failed_attempts']
    return suspicious.sort_values('failed_attempts', ascending=False)

def get_user_statistics(df):
    """Return statistics grouped by username"""
    user_stats = df.groupby('username').agg({
        'status': 'count',
        'ip_address': lambda x: len(x.unique())
    }).rename(columns={
        'status': 'total_attempts',
        'ip_address': 'unique_ips'
    }).reset_index()
    
    failed_counts = df[df['status'] == 'Failed'].groupby('username').size()
    user_stats['failed_attempts'] = user_stats['username'].map(failed_counts).fillna(0).astype(int)
    
    return user_stats.sort_values('total_attempts', ascending=False)

def get_time_based_analysis(df):
    """Analyze events by hour"""
    df_copy = df.copy()
    df_copy['hour'] = df_copy['timestamp'].dt.hour
    
    hourly_stats = df_copy.groupby('hour').agg({
        'status': 'count',
        'ip_address': 'count'
    }).rename(columns={
        'status': 'total_events'
    }).reset_index()
    
    return hourly_stats

def get_security_summary(df):
    """Generate comprehensive security summary"""
    total_events = len(df)
    failed_count = len(df[df['status'] == 'Failed'])
    success_count = len(df[df['status'] == 'Success'])
    failure_rate = (failed_count / total_events * 100) if total_events > 0 else 0
    
    unique_ips = df['ip_address'].nunique()
    unique_users = df['username'].nunique()
    
    suspicious_ips = get_suspicious_ips(df)
    
    # Most targeted users
    targeted_users = df[df['status'] == 'Failed'].groupby('username').size().nlargest(5)
    
    return {
        'total_events': total_events,
        'failed_attempts': failed_count,
        'successful_logins': success_count,
        'failure_rate': failure_rate,
        'unique_ips': unique_ips,
        'unique_users': unique_users,
        'suspicious_ip_count': len(suspicious_ips),
        'most_targeted_users': targeted_users
    }
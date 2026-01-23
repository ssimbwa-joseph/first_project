from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()

class Alert(Base):
    __tablename__ = 'alerts'

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, nullable=False)
    event_type = Column(String(50), nullable=False)
    message = Column(Text, nullable=False)
    risk_score = Column(Integer, nullable=False, default=0)
    extra = Column(Text)
    severity = Column(String(20), default='info')
    resolved = Column(Boolean, default=False)
    resolved_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class MalwareHash(Base):
    __tablename__ = 'malware_hashes'

    id = Column(Integer, primary_key=True, autoincrement=True)
    hash = Column(String(64), unique=True, nullable=False)
    description = Column(Text)
    added_by = Column(String(100))
    added_at = Column(DateTime, default=datetime.utcnow)

class SystemEvent(Base):
    __tablename__ = 'system_events'

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, nullable=False)
    event_type = Column(String(50), nullable=False)
    details = Column(Text)  # JSON stored as text
    created_at = Column(DateTime, default=datetime.utcnow)

class UserSession(Base):
    __tablename__ = 'user_sessions'

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer)
    token = Column(String(255), unique=True, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class RiskThreshold(Base):
    __tablename__ = 'risk_thresholds'

    id = Column(Integer, primary_key=True, autoincrement=True)
    category = Column(String(50), unique=True, nullable=False)
    warning_threshold = Column(Integer, nullable=False)
    critical_threshold = Column(Integer, nullable=False)
    enabled = Column(Boolean, default=True)

class MonitoringConfig(Base):
    __tablename__ = 'monitoring_config'

    id = Column(Integer, primary_key=True, autoincrement=True)
    key = Column(String(100), unique=True, nullable=False)
    value = Column(Text)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
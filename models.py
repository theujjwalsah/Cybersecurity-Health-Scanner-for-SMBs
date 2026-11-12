from datetime import datetime
from sqlalchemy import String, Integer, Float, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .database import Base

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    domains = relationship("Domain", back_populates="owner", cascade="all, delete-orphan")

class Domain(Base):
    __tablename__ = "domains"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    hostname: Mapped[str] = mapped_column(String(253), index=True)
    verification_token: Mapped[str] = mapped_column(String(100))
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    owner = relationship("User", back_populates="domains")
    scans = relationship("Scan", back_populates="domain", cascade="all, delete-orphan")

class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    domain_id: Mapped[int] = mapped_column(ForeignKey("domains.id"))
    score: Mapped[int] = mapped_column(Integer, default=100)
    status: Mapped[str] = mapped_column(String(30), default="completed")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    domain = relationship("Domain", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")

class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
    title: Mapped[str] = mapped_column(String(200))
    category: Mapped[str] = mapped_column(String(80))
    severity: Mapped[str] = mapped_column(String(20))
    description: Mapped[str] = mapped_column(Text)
    evidence: Mapped[str] = mapped_column(Text)
    recommendation: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(30), default="open")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    scan = relationship("Scan", back_populates="findings")

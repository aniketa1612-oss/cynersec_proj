from __future__ import annotations

import csv
import io
import json
import logging
import os
import secrets
import shutil
import subprocess
import tempfile
import time
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, ConfigDict, Field
from dotenv import load_dotenv
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
)
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, create_engine, func
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker
from app.enrichment import enrich_cve, nvd_fields
from app.scanners import (
    NormalizedFinding, ScannerError, run_nmap, run_nuclei, run_zap_passive, scanner_status
)
from app.trivy import parse_trivy_report

load_dotenv()
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger("uvicorn.error")
Path("logs").mkdir(exist_ok=True)
if not any(isinstance(handler, RotatingFileHandler) for handler in log.handlers):
    file_handler = RotatingFileHandler(
        "logs/backend.log", maxBytes=2_000_000, backupCount=3, encoding="utf-8"
    )
    file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    log.addHandler(file_handler)
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///./adaptive_pentest.db')
SECRET_KEY = os.getenv('SECRET_KEY') or secrets.token_urlsafe(48)
if not os.getenv('SECRET_KEY'):
    log.warning('SECRET_KEY is unset; using an ephemeral development key')
LIVE_ENABLED = os.getenv('ENABLE_LIVE_SCANNING', 'false').lower() == 'true'
CELERY_ENABLED = os.getenv('CELERY_ENABLED', 'false').lower() == 'true'
engine = create_engine(DATABASE_URL, connect_args={'check_same_thread': False} if DATABASE_URL.startswith('sqlite') else {})
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
pwd = CryptContext(schemes=['pbkdf2_sha256'], deprecated='auto')


class Base(DeclarativeBase): pass


class User(Base):
    __tablename__ = 'users'
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str]
    role: Mapped[str] = mapped_column(default='viewer')
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Target(Base):
    __tablename__ = 'targets'
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str]; host: Mapped[str] = mapped_column(index=True); target_type: Mapped[str]
    description: Mapped[str] = mapped_column(Text, default='')
    authorization_status: Mapped[str] = mapped_column(default='pending', index=True)
    authorization_reference: Mapped[str | None]
    authorization_start: Mapped[datetime | None] = mapped_column(DateTime)
    authorization_end: Mapped[datetime | None] = mapped_column(DateTime)
    created_by: Mapped[int] = mapped_column(ForeignKey('users.id')); created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Scan(Base):
    __tablename__ = 'scans'
    id: Mapped[int] = mapped_column(primary_key=True); target_id: Mapped[int] = mapped_column(ForeignKey('targets.id'), index=True)
    scan_type: Mapped[str]; status: Mapped[str] = mapped_column(default='queued', index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime); completed_at: Mapped[datetime | None] = mapped_column(DateTime)
    initiated_by: Mapped[int] = mapped_column(ForeignKey('users.id')); tool: Mapped[str]; mode: Mapped[str]; error_message: Mapped[str | None]


class Asset(Base):
    __tablename__ = 'assets'
    id: Mapped[int] = mapped_column(primary_key=True); target_id: Mapped[int] = mapped_column(ForeignKey('targets.id'), index=True)
    ip: Mapped[str]; hostname: Mapped[str]; port: Mapped[int] = mapped_column(index=True); protocol: Mapped[str]; service: Mapped[str]; version: Mapped[str]; os: Mapped[str]
    discovered_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Vulnerability(Base):
    __tablename__ = 'vulnerabilities'
    id: Mapped[int] = mapped_column(primary_key=True); scan_id: Mapped[int] = mapped_column(ForeignKey('scans.id'), index=True); asset_id: Mapped[int] = mapped_column(ForeignKey('assets.id'), index=True)
    cve_id: Mapped[str | None] = mapped_column(index=True); title: Mapped[str]; description: Mapped[str] = mapped_column(Text); severity: Mapped[str] = mapped_column(index=True)
    cvss_score: Mapped[float]; attack_vector: Mapped[str]; attack_complexity: Mapped[str]; privileges_required: Mapped[str]; user_interaction: Mapped[str]
    confidentiality_impact: Mapped[str]; integrity_impact: Mapped[str]; availability_impact: Mapped[str]; cwe_id: Mapped[str | None]
    evidence: Mapped[str] = mapped_column(Text); source: Mapped[str] = mapped_column(index=True); discovered_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Enrichment(Base):
    __tablename__ = 'vulnerability_enrichment'
    id: Mapped[int] = mapped_column(primary_key=True); vulnerability_id: Mapped[int] = mapped_column(ForeignKey('vulnerabilities.id'), unique=True)
    nvd_data: Mapped[str] = mapped_column(Text, default='{}'); kev_status: Mapped[str] = mapped_column(default='unknown'); kev_date_added: Mapped[datetime | None] = mapped_column(DateTime)
    known_exploited: Mapped[bool] = mapped_column(Boolean, default=False); exploitability_score: Mapped[float] = mapped_column(default=0); enrichment_timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Risk(Base):
    __tablename__ = 'risk_assessments'
    id: Mapped[int] = mapped_column(primary_key=True); vulnerability_id: Mapped[int] = mapped_column(ForeignKey('vulnerabilities.id'), unique=True)
    rule_based_score: Mapped[float]; ml_score: Mapped[float]; final_score: Mapped[float] = mapped_column(index=True); risk_level: Mapped[str]; confidence: Mapped[float]; model_version: Mapped[str]; created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Recommendation(Base):
    __tablename__ = 'recommendations'
    id: Mapped[int] = mapped_column(primary_key=True); vulnerability_id: Mapped[int] = mapped_column(ForeignKey('vulnerabilities.id'), unique=True)
    recommendation: Mapped[str] = mapped_column(Text); priority: Mapped[str]; reason: Mapped[str] = mapped_column(Text); recommended_tool: Mapped[str]; safe_validation: Mapped[str] = mapped_column(Text); created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Audit(Base):
    __tablename__ = 'audit_logs'
    id: Mapped[int] = mapped_column(primary_key=True); user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), index=True); action: Mapped[str]
    target_id: Mapped[int | None]; scan_id: Mapped[int | None]; timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True); ip_address: Mapped[str]; details: Mapped[str] = mapped_column(Text)


Base.metadata.create_all(engine)

class ORM(BaseModel): model_config = ConfigDict(from_attributes=True)
class Register(BaseModel): username: str; email: str; password: str = Field(min_length=8); role: Literal['admin','analyst','viewer'] = 'viewer'
class Login(BaseModel): username: str; password: str
class TargetIn(BaseModel): name: str; host: str; target_type: Literal['IP','DOMAIN','URL','NETWORK']; description: str = ''
class AuthorizationIn(BaseModel): authorization_reference: str = Field(min_length=3); authorization_start: datetime; authorization_end: datetime
class ScanIn(BaseModel): target_id: int; scan_type: Literal['asset_discovery','vulnerability_scan','web_scan']; tool: Literal['mock','nmap','nuclei','zap']='mock'; mode: Literal['mock','live']='mock'

HTTP_REQUESTS = Counter(
    "adaptive_http_requests_total", "HTTP requests", ["method", "path", "status"]
)
HTTP_DURATION = Histogram(
    "adaptive_http_request_duration_seconds", "HTTP request duration", ["method", "path"]
)

def db():
    session=SessionLocal()
    try: yield session
    finally: session.close()

def token(user: User): return jwt.encode({'sub':str(user.id),'exp':datetime.now(timezone.utc)+timedelta(minutes=int(os.getenv('ACCESS_TOKEN_EXPIRE_MINUTES','60')))},SECRET_KEY,algorithm='HS256')
def current(request: Request, s: Session=Depends(db)) -> User:
    raw=request.headers.get('Authorization','').removeprefix('Bearer ').strip()
    try: uid=int(jwt.decode(raw,SECRET_KEY,algorithms=['HS256'])['sub'])
    except (JWTError,KeyError,ValueError): raise HTTPException(401,'Invalid or expired access token')
    user=s.get(User,uid)
    if not user: raise HTTPException(401,'User no longer exists')
    return user
def roles(*allowed):
    def check(u:User=Depends(current)):
        if u.role not in allowed: raise HTTPException(403,'Insufficient role')
        return u
    return check
def audit(s:Session,u:User,action:str,request:Request,target_id=None,scan_id=None,details=''):
    s.add(Audit(user_id=u.id,action=action,target_id=target_id,scan_id=scan_id,ip_address=request.client.host if request.client else 'unknown',details=details))
    log.info(
        "audit user=%s role=%s action=%s target_id=%s scan_id=%s client=%s details=%s",
        u.username, u.role, action, target_id or "-", scan_id or "-",
        request.client.host if request.client else "unknown", details or "-",
    )
def valid_authorization(t:Target):
    now=datetime.utcnow()
    if t.authorization_status!='authorized': raise HTTPException(403,'Target has no approved authorization')
    if not t.authorization_start or not t.authorization_end or not (t.authorization_start <= now <= t.authorization_end): raise HTTPException(403,'Target authorization is not currently valid')

def effective_authorization_status(t:Target) -> str:
    if t.authorization_status != 'authorized': return t.authorization_status
    now=datetime.utcnow()
    if not t.authorization_start or not t.authorization_end: return 'invalid'
    if now < t.authorization_start: return 'scheduled'
    if now > t.authorization_end: return 'expired'
    return 'authorized'

def target_response(t:Target) -> dict:
    return {'id':t.id,'name':t.name,'host':t.host,'target_type':t.target_type,'description':t.description,
            'authorization_status':effective_authorization_status(t),'authorization_reference':t.authorization_reference,
            'authorization_start':t.authorization_start,'authorization_end':t.authorization_end,
            'created_by':t.created_by,'created_at':t.created_at}

MOCK_ASSETS=[(22,'ssh','OpenSSH 8.9'),(80,'http','Apache 2.4'),(443,'https','nginx 1.22'),(3306,'mysql','MySQL 8.0')]
MOCK_VULNS=[('CVE-2021-44228','Known exploited remote code execution',10.0,'critical',True,443,'nuclei'),('CVE-2023-25690','HTTP request smuggling risk',9.8,'critical',False,80,'zap'),(None,'Weak TLS cipher configuration',6.5,'medium',False,443,'zap'),(None,'Verbose service banner',3.1,'low',False,22,'nmap')]
def score(cvss:float,kev:bool,port:int):
    exposure=10 if port in (80,443,22,3389) else 5
    rule=min(100,cvss*7 + (20 if kev else 0)+exposure)
    ml=min(100,cvss*6.5+(25 if kev else 0)+exposure*.8)
    final=.4*rule+.6*ml
    level='Critical' if final>=76 else 'High' if final>=51 else 'Medium' if final>=26 else 'Low'
    return round(rule,2),round(ml,2),round(final,2),level,0.86 if kev else 0.74
def recommendation(service:str,kev:bool,level:str):
    if kev: return ('Prioritize immediate authorized validation and remediation assessment.','Known exploitation is documented.','NVD/CISA review')
    if service in ('http','https'): return ('Perform an authorized web application assessment of the affected endpoint.','The finding affects an exposed web service.','OWASP ZAP')
    if service=='ssh': return ('Perform an authorized SSH configuration review.','The finding affects remote administration.','Configuration review')
    return ('Validate the finding safely and review remediation.','Risk-based follow-up is required.','Manual review')

def ml_risk(fields: dict, rule_score: float) -> tuple[float, float, str]:
    """Use the trained Random Forest when available; disclose rule fallback."""
    try:
        from ml.predict import predict
        result = predict(fields)
        weights = {"Low": 12.5, "Medium": 38.0, "High": 63.0, "Critical": 88.0}
        ml_score = sum(weights.get(label, 0) * probability for label, probability in result["probabilities"].items())
        return round(ml_score, 2), round(float(result["confidence"]), 3), "random-forest-1.0"
    except (FileNotFoundError, ImportError, KeyError, ValueError):
        return round(rule_score, 2), 0.0, "rule-fallback-no-model"

def store_findings(s: Session, scan: Scan, target: Target, findings: list[NormalizedFinding]) -> int:
    count = 0
    for finding in findings:
        asset = s.query(Asset).filter_by(target_id=target.id, port=finding.port).first()
        if not asset:
            asset = Asset(
                target_id=target.id, ip=finding.host or target.host, hostname=finding.host or target.name,
                port=finding.port, protocol=finding.protocol, service=finding.service,
                version=" ".join(x for x in (finding.product, finding.version) if x) or "Unknown",
                os="Unknown",
            )
            s.add(asset); s.flush()
        enrichment = enrich_cve(finding.cve_id)
        nvd = nvd_fields(enrichment["nvd"]) if enrichment["nvd"] else {}
        kev = enrichment["kev"]
        cvss = nvd.get("cvss") or finding.cvss
        severity = finding.severity if finding.severity != "info" else "low"
        description = nvd.get("description") or finding.description
        vulnerability = Vulnerability(
            scan_id=scan.id, asset_id=asset.id, cve_id=finding.cve_id, title=finding.title,
            description=description, severity=severity, cvss_score=cvss,
            attack_vector=nvd.get("attack_vector", "UNKNOWN"),
            attack_complexity=nvd.get("attack_complexity", "UNKNOWN"),
            privileges_required=nvd.get("privileges_required", "UNKNOWN"),
            user_interaction=nvd.get("user_interaction", "UNKNOWN"),
            confidentiality_impact=nvd.get("confidentiality_impact", "UNKNOWN"),
            integrity_impact=nvd.get("integrity_impact", "UNKNOWN"),
            availability_impact=nvd.get("availability_impact", "UNKNOWN"),
            cwe_id=nvd.get("cwe") or finding.cwe_id, evidence=finding.evidence,
            source=finding.source,
        )
        s.add(vulnerability); s.flush()
        known_exploited = bool(kev)
        exploitability = nvd.get("exploitability_score", 0)
        s.add(Enrichment(
            vulnerability_id=vulnerability.id, nvd_data=json.dumps(enrichment["nvd"]),
            kev_status="listed" if known_exploited else "not_listed",
            kev_date_added=datetime.fromisoformat(kev["dateAdded"]) if kev and kev.get("dateAdded") else None,
            known_exploited=known_exploited, exploitability_score=exploitability,
        ))
        rule_score, _, _, _, _ = score(cvss, known_exploited, asset.port)
        published = nvd.get("published")
        age = 0
        if published:
            try:
                published_at = datetime.fromisoformat(published.replace("Z", "+00:00"))
                if published_at.tzinfo is None:
                    published_at = published_at.replace(tzinfo=timezone.utc)
                age = max(0, (datetime.now(timezone.utc) - published_at.astimezone(timezone.utc)).days)
            except ValueError:
                pass
        features = {
            "cvss_score": cvss, "known_exploited": int(known_exploited),
            "asset_exposure": 10 if asset.port in (22, 80, 443, 3389) else 5,
            "service_exposure": 10 if asset.service in ("http", "https", "ssh", "rdp") else 5,
            "port": asset.port, "exploitability_score": exploitability,
            "vulnerability_age": age, "attack_vector": vulnerability.attack_vector,
            "attack_complexity": vulnerability.attack_complexity,
            "privileges_required": vulnerability.privileges_required,
            "user_interaction": vulnerability.user_interaction,
            "confidentiality_impact": vulnerability.confidentiality_impact,
            "integrity_impact": vulnerability.integrity_impact,
            "availability_impact": vulnerability.availability_impact,
        }
        ml_score, confidence, model_version = ml_risk(features, rule_score)
        final = round(0.4 * rule_score + 0.6 * ml_score, 2)
        level = "Critical" if final >= 76 else "High" if final >= 51 else "Medium" if final >= 26 else "Low"
        s.add(Risk(vulnerability_id=vulnerability.id, rule_based_score=rule_score, ml_score=ml_score,
                   final_score=final, risk_level=level, confidence=confidence, model_version=model_version))
        action, reason, tool = recommendation(asset.service, known_exploited, level)
        s.add(Recommendation(
            vulnerability_id=vulnerability.id, recommendation=action, priority=level, reason=reason,
            recommended_tool=tool,
            safe_validation="Confirm the affected version or configuration without payload execution or disruption.",
        ))
        count += 1
    return count

def run_live(scan_id: int):
    """Run one controlled scanner job after revalidating authorization."""
    s = SessionLocal()
    scan = s.get(Scan, scan_id)
    try:
        target = s.get(Target, scan.target_id)
        valid_authorization(target)
        if scan.status == "cancelled":
            return
        scan.status = "running"; scan.started_at = datetime.utcnow(); s.commit()
        log.info("scan status=running scan_id=%s target_id=%s mode=live tool=%s", scan.id, target.id, scan.tool)
        findings: list[NormalizedFinding] = []
        asset_count = 0
        if scan.scan_type == "asset_discovery":
            discovered = run_nmap(target.host, target.target_type)
            for item in discovered:
                s.add(Asset(target_id=target.id, **item))
            asset_count = len(discovered)
        elif scan.scan_type == "vulnerability_scan":
            findings = run_nuclei(target.host, target.target_type)
        elif scan.scan_type == "web_scan":
            findings = run_zap_passive(target.host, target.target_type)
        finding_count = store_findings(s, scan, target, findings)
        scan.status = "completed"; scan.completed_at = datetime.utcnow(); s.commit()
        log.info("scan status=completed scan_id=%s target_id=%s assets=%s findings=%s",
                 scan.id, target.id, asset_count, finding_count)
    except (ScannerError, HTTPException) as exc:
        s.rollback()
        scan = s.get(Scan, scan_id)
        scan.status = "failed"; scan.error_message = str(exc); scan.completed_at = datetime.utcnow(); s.commit()
        log.error("scan status=failed scan_id=%s error=%s", scan_id, exc)
    except Exception as exc:
        s.rollback()
        scan = s.get(Scan, scan_id)
        scan.status = "failed"; scan.error_message = "Unexpected scanner or enrichment failure"; scan.completed_at = datetime.utcnow(); s.commit()
        log.exception("scan status=failed scan_id=%s error=%s", scan_id, type(exc).__name__)
    finally:
        s.close()
def run_mock(scan_id:int):
    s=SessionLocal()
    try:
        scan=s.get(Scan,scan_id); target=s.get(Target,scan.target_id); scan.status='running'; scan.started_at=datetime.utcnow(); s.commit()
        log.info("scan status=running scan_id=%s target_id=%s mode=%s tool=%s", scan.id, target.id, scan.mode, scan.tool)
        assets=[]
        for port,service,version in MOCK_ASSETS:
            a=Asset(target_id=target.id,ip=target.host,hostname=target.name,port=port,protocol='tcp',service=service,version='DEMO / MOCK '+version,os='DEMO / MOCK Linux'); s.add(a); s.flush(); assets.append(a)
        if scan.scan_type!='asset_discovery':
            by_port={a.port:a for a in assets}
            for cve,title,cvss,severity,kev,port,source in MOCK_VULNS:
                a=by_port[port]; v=Vulnerability(scan_id=scan.id,asset_id=a.id,cve_id=cve,title='DEMO / MOCK — '+title,description='Synthetic finding for authorized demonstration only.',severity=severity,cvss_score=cvss,attack_vector='NETWORK',attack_complexity='LOW',privileges_required='NONE',user_interaction='NONE',confidentiality_impact='HIGH',integrity_impact='HIGH',availability_impact='HIGH',cwe_id='CWE-20',evidence='DEMO / MOCK evidence; no exploitation performed.',source='DEMO / MOCK '+source); s.add(v); s.flush()
                s.add(Enrichment(vulnerability_id=v.id,kev_status='listed' if kev else 'not_listed',known_exploited=kev,exploitability_score=cvss))
                rs,ms,fs,level,conf=score(cvss,kev,port); s.add(Risk(vulnerability_id=v.id,rule_based_score=rs,ml_score=ms,final_score=fs,risk_level=level,confidence=conf,model_version='demo-baseline-1.0'))
                action,reason,tool=recommendation(a.service,kev,level); s.add(Recommendation(vulnerability_id=v.id,recommendation=action,priority=level,reason=reason,recommended_tool=tool,safe_validation='Confirm version/configuration without payload execution or service disruption.'))
        scan.status='completed'; scan.completed_at=datetime.utcnow(); s.commit()
        log.info("scan status=completed scan_id=%s target_id=%s assets=%s findings=%s",
                 scan.id, target.id, len(assets), 0 if scan.scan_type == "asset_discovery" else len(MOCK_VULNS))
    except Exception as exc:
        log.exception('mock scan failed'); scan.status='failed'; scan.error_message=str(exc); s.commit()
    finally: s.close()

def build_pdf_report(target: Target, scan: Scan, assets: list[Asset], findings: list[dict], audits: list[Audit]) -> io.BytesIO:
    """Build a detailed, non-destructive vulnerability assessment report."""
    out = io.BytesIO()
    doc = SimpleDocTemplate(
        out, pagesize=A4, rightMargin=16*mm, leftMargin=16*mm,
        topMargin=20*mm, bottomMargin=18*mm,
        title="Authorized Vulnerability Assessment Report",
        author="AI-Based Adaptive Penetration Testing Assistant",
    )
    styles = getSampleStyleSheet()
    navy = colors.HexColor("#102A43")
    teal = colors.HexColor("#087F8C")
    light = colors.HexColor("#EAF4F5")
    grey = colors.HexColor("#52606D")
    border = colors.HexColor("#CBD5E1")
    styles.add(ParagraphStyle(name="ReportTitle", parent=styles["Title"], fontName="Helvetica-Bold",
        fontSize=22, leading=27, textColor=navy, alignment=TA_LEFT, spaceAfter=10))
    styles.add(ParagraphStyle(name="Subtitle", parent=styles["Normal"], fontSize=10, leading=15,
        textColor=grey, spaceAfter=18))
    styles.add(ParagraphStyle(name="Section", parent=styles["Heading2"], fontName="Helvetica-Bold",
        fontSize=14, leading=18, textColor=navy, spaceBefore=13, spaceAfter=7))
    styles.add(ParagraphStyle(name="FindingTitle", parent=styles["Heading3"], fontName="Helvetica-Bold",
        fontSize=11, leading=14, textColor=navy, spaceBefore=8, spaceAfter=5))
    styles.add(ParagraphStyle(name="BodySmall", parent=styles["BodyText"], fontSize=8.5, leading=12,
        textColor=colors.HexColor("#243B53")))
    styles.add(ParagraphStyle(name="Tiny", parent=styles["BodyText"], fontSize=7.5, leading=10,
        textColor=grey))
    P = lambda value, style="BodySmall": Paragraph(str(value or "Not available"), styles[style])
    story = []
    completed = scan.completed_at or scan.started_at or datetime.utcnow()
    severity_counts = {x: sum(1 for f in findings if f["severity"].lower() == x) for x in ("critical","high","medium","low")}
    max_risk = max((f["final_risk"] for f in findings), default=0)

    story += [
        P("AUTHORIZED VULNERABILITY ASSESSMENT", "Tiny"),
        P("AI-Based Adaptive Penetration Testing Assistant", "ReportTitle"),
        P("Intelligent Vulnerability Assessment and Risk Prioritization", "Subtitle"),
    ]
    overview = [
        [P("Target"), P(f"{target.name}<br/>{target.host}")],
        [P("Authorization"), P(f"{target.authorization_reference or 'Not provided'}<br/>{target.authorization_status.title()}")],
        [P("Assessment"), P(f"Scan #{scan.id} - {scan.scan_type.replace('_',' ').title()}<br/>{scan.mode.upper()} / {scan.tool}")],
        [P("Completed"), P(completed.strftime("%d %B %Y, %H:%M UTC"))],
    ]
    t = Table(overview, colWidths=[42*mm, 132*mm])
    t.setStyle(TableStyle([("BACKGROUND",(0,0),(0,-1),light),("TEXTCOLOR",(0,0),(0,-1),navy),
        ("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),("GRID",(0,0),(-1,-1),0.5,border),
        ("VALIGN",(0,0),(-1,-1),"TOP"),("LEFTPADDING",(0,0),(-1,-1),7),
        ("RIGHTPADDING",(0,0),(-1,-1),7),("TOPPADDING",(0,0),(-1,-1),6),("BOTTOMPADDING",(0,0),(-1,-1),6)]))
    story += [t, Spacer(1, 8*mm), P("Executive Summary", "Section")]
    posture = ("No vulnerabilities were recorded for this scan. This does not prove that the target is secure; "
               "it means the selected assessment produced no normalized findings.") if not findings else (
               f"The assessment recorded {len(findings)} normalized findings across {len(assets)} asset/service records. "
               f"The highest calculated priority score was {max_risk:.1f}/100. "
               f"{severity_counts['critical']} Critical and {severity_counts['high']} High findings require the earliest review.")
    story += [P(posture), Spacer(1, 3*mm)]
    metrics = [["Assets / Services", "Findings", "Critical", "High", "Known Exploited"],
               [str(len(assets)), str(len(findings)), str(severity_counts["critical"]), str(severity_counts["high"]),
                str(sum(1 for f in findings if f["known_exploited"]))]]
    mt = Table(metrics, colWidths=[35*mm]*5)
    mt.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),navy),("TEXTCOLOR",(0,0),(-1,0),colors.white),
        ("BACKGROUND",(0,1),(-1,1),light),("ALIGN",(0,0),(-1,-1),"CENTER"),("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
        ("FONTNAME",(0,1),(-1,1),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),8),("GRID",(0,0),(-1,-1),0.5,border),
        ("TOPPADDING",(0,0),(-1,-1),7),("BOTTOMPADDING",(0,0),(-1,-1),7)]))
    story += [mt, P("Assessment Scope and Authorization", "Section"),
        P(f"Scope was limited to {target.host} ({target.target_type}). Authorization reference "
          f"{target.authorization_reference or 'was not recorded'} was valid from "
          f"{target.authorization_start or 'not recorded'} to {target.authorization_end or 'not recorded'}. "
          "The platform validates this authorization before accepting an assessment job."),
        P("Methodology", "Section"),
        P("The workflow follows: authorize, discover, scan, normalize, enrich, calculate rule-based risk, "
          "apply ML prioritization, combine scores, recommend safe follow-up, report, and audit. "
          "No destructive exploitation, credential attacks, persistence, privilege escalation, malware, "
          "or arbitrary command execution is performed."),
        P("Evidence Classification", "Section"),
        P("Records labelled DEMO / MOCK are synthetic academic examples. They demonstrate processing and "
          "prioritization logic and must not be presented as observations from a live system."),
        P("Assets and Exposed Services", "Section")]
    if assets:
        asset_rows = [[P("Host"),P("Port"),P("Protocol"),P("Service"),P("Version / OS")]]
        for a in assets:
            asset_rows.append([P(a.ip),P(a.port),P(a.protocol),P(a.service),P(f"{a.version}<br/>{a.os}")])
        at = Table(asset_rows, repeatRows=1, colWidths=[31*mm,15*mm,20*mm,27*mm,82*mm])
        at.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),navy),("TEXTCOLOR",(0,0),(-1,0),colors.white),
            ("GRID",(0,0),(-1,-1),0.4,border),("VALIGN",(0,0),(-1,-1),"TOP"),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,light]),("TOPPADDING",(0,0),(-1,-1),5),("BOTTOMPADDING",(0,0),(-1,-1),5)]))
        story.append(at)
    else:
        story.append(P("No asset or service records were associated with this target at report generation time."))

    story += [P("Vulnerability Summary", "Section")]
    summary_rows = [["Severity","Count"],["Critical",severity_counts["critical"]],["High",severity_counts["high"]],
                    ["Medium",severity_counts["medium"]],["Low",severity_counts["low"]]]
    st = Table(summary_rows, colWidths=[65*mm,35*mm])
    st.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),navy),("TEXTCOLOR",(0,0),(-1,0),colors.white),
        ("GRID",(0,0),(-1,-1),0.5,border),("ALIGN",(1,1),(1,-1),"CENTER"),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,light]),("TOPPADDING",(0,0),(-1,-1),6),("BOTTOMPADDING",(0,0),(-1,-1),6)]))
    story += [st, P("Risk Prioritization Method", "Section"),
        P("Rule-based risk considers CVSS, known exploitation, and exposure. ML risk provides an independent "
          "model score and confidence. Final risk = 0.4 x normalized rule score + 0.6 x normalized ML score. "
          "Bands: Low 0-25, Medium 26-50, High 51-75, Critical 76-100. ML output supports, but does not replace, analyst judgment."),
        P("Detailed Findings", "Section")]
    if not findings:
        story += [P("No normalized vulnerability findings were attached to this scan."),
            P("Recommended next step: verify that the intended vulnerability or web scan was selected, confirm "
              "scanner coverage and asset discovery results, then repeat the authorized assessment. A zero-finding "
              "result should not be interpreted as proof of security.")]
    for index, f in enumerate(findings, 1):
        title = f"{index}. {f['cve'] or 'No CVE'} - {f['title']}"
        detail = [
            [P("Priority"),P(f"{f['priority']} ({f['final_risk']:.1f}/100)")],
            [P("Severity / CVSS"),P(f"{f['severity'].title()} / {f['cvss']:.1f}")],
            [P("Affected service"),P(f"{f['asset']}:{f['port']} / {f['service']}")],
            [P("Source"),P(f["source"])],
            [P("Known exploited"),P("Yes" if f["known_exploited"] else "No")],
            [P("Risk components"),P(f"Rule {f['rule_score']:.1f} | ML {f['ml_score']:.1f} | Confidence {f['confidence']*100:.0f}%")],
            [P("Description"),P(f["description"])],
            [P("Evidence"),P(f["evidence"])],
            [P("Recommended action"),P(f["recommendation"])],
            [P("Reason"),P(f["reason"])],
            [P("Safe validation"),P(f["safe_validation"])],
        ]
        ft = Table(detail, colWidths=[39*mm,136*mm])
        ft.setStyle(TableStyle([("BACKGROUND",(0,0),(0,-1),light),("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),
            ("GRID",(0,0),(-1,-1),0.4,border),("VALIGN",(0,0),(-1,-1),"TOP"),
            ("TOPPADDING",(0,0),(-1,-1),5),("BOTTOMPADDING",(0,0),(-1,-1),5)]))
        story += [KeepTogether([P(title, "FindingTitle"), ft]), Spacer(1, 4*mm)]

    story += [P("Remediation Guidance", "Section"),
        P("1. Address Critical and known-exploited findings first. 2. Confirm affected versions and configurations "
          "without executing destructive payloads. 3. Apply vendor-supported updates or compensating controls. "
          "4. Retest within the approved scope. 5. Record accepted risk and evidence when remediation is deferred."),
        P("Assessment Timeline and Audit", "Section")]
    if audits:
        audit_rows = [[P("Timestamp"),P("Action"),P("User"),P("Details")]]
        for a in audits[-20:]:
            audit_rows.append([P(a.timestamp.strftime("%Y-%m-%d %H:%M")),P(a.action),P(a.user_id),P(a.details)])
        au = Table(audit_rows, repeatRows=1, colWidths=[37*mm,42*mm,18*mm,78*mm])
        au.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),navy),("TEXTCOLOR",(0,0),(-1,0),colors.white),
            ("GRID",(0,0),(-1,-1),0.4,border),("VALIGN",(0,0),(-1,-1),"TOP"),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,light]),("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4)]))
        story.append(au)
    else:
        story.append(P("No audit entries were available for inclusion."))
    story += [P("Limitations", "Section"),
        P("Scanner coverage depends on the selected adapter, configuration, authentication, network reachability, "
          "and available templates. Mock data is not real evidence. CVE and KEV data can become outdated. "
          "False positives and false negatives remain possible. Findings require analyst validation."),
        P("Conclusion", "Section"),
        P("This report supports authorized vulnerability management and prioritization. It is not proof of compromise, "
          "a compliance certification, or permission to test systems outside the recorded scope.")]

    def footer(c, d):
        c.saveState()
        c.setStrokeColor(teal)
        c.setLineWidth(0.7)
        c.line(16*mm, 13*mm, 194*mm, 13*mm)
        c.setFont("Helvetica", 7.5)
        c.setFillColor(grey)
        c.drawString(16*mm, 8*mm, f"Authorized assessment | Scan #{scan.id} | {target.host}")
        c.drawRightString(194*mm, 8*mm, f"Page {d.page}")
        c.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    out.seek(0)
    return out

app=FastAPI(title='AI-Based Adaptive Penetration Testing Assistant',version='1.0.0',description='Authorized assessment only; mock mode by default.')
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def application_startup_log():
    """Confirm that application logging and persistence are active."""
    with SessionLocal() as session:
        log.info(
            "application event=startup status=ready mode=%s database=%s users=%s targets=%s scans=%s",
            "live-enabled" if LIVE_ENABLED else "mock-only",
            DATABASE_URL.split(":", 1)[0],
            session.query(User).count(),
            session.query(Target).count(),
            session.query(Scan).count(),
        )
    log.info("application log_file=%s", str(Path("logs/backend.log").resolve()))

@app.on_event("shutdown")
def application_shutdown_log():
    log.info("application event=shutdown status=complete")

@app.middleware("http")
async def structured_request_log(request: Request, call_next):
    """Emit one visible terminal log for every API request."""
    started = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        duration = (time.perf_counter() - started) * 1000
        log.exception(
            "request method=%s path=%s status=500 duration_ms=%.1f client=%s",
            request.method, request.url.path, duration,
            request.client.host if request.client else "unknown",
        )
        raise
    duration = (time.perf_counter() - started) * 1000
    route = request.scope.get("route")
    path = getattr(route, "path", request.url.path)
    HTTP_REQUESTS.labels(request.method, path, str(response.status_code)).inc()
    HTTP_DURATION.labels(request.method, path).observe(duration / 1000)
    log.info(
        "request method=%s path=%s status=%s duration_ms=%.1f client=%s",
        request.method, request.url.path, response.status_code, duration,
        request.client.host if request.client else "unknown",
    )
    return response

@app.get('/health')
def health(): return {'status':'ok','mode':'live-enabled' if LIVE_ENABLED else 'mock-only','queue':'celery' if CELERY_ENABLED else 'in-process','scanners':scanner_status()}
@app.get('/metrics', include_in_schema=False)
def metrics(): return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
@app.post('/auth/register')
def register(body:Register,request:Request,s:Session=Depends(db)):
    if s.query(User).count() and body.role!='viewer': body.role='viewer'
    if s.query(User).filter((User.username==body.username)|(User.email==body.email)).first(): raise HTTPException(409,'Username or email already exists')
    u=User(username=body.username,email=body.email,password_hash=pwd.hash(body.password),role=body.role); s.add(u); s.flush(); audit(s,u,'user.register',request,details=body.username); s.commit(); return {'access_token':token(u),'token_type':'bearer','user':{'id':u.id,'username':u.username,'role':u.role}}
@app.post('/auth/login')
def login(body:Login,request:Request,s:Session=Depends(db)):
    u=s.query(User).filter((User.username==body.username)|(User.email==body.username)).first()
    if not u or not pwd.verify(body.password,u.password_hash): raise HTTPException(401,'Invalid credentials')
    audit(s,u,'user.login',request); s.commit(); return {'access_token':token(u),'token_type':'bearer'}
@app.get('/auth/me')
def me(u:User=Depends(current)): return {'id':u.id,'username':u.username,'email':u.email,'role':u.role}
@app.post('/targets')
def create_target(body:TargetIn,request:Request,u:User=Depends(roles('admin','analyst')),s:Session=Depends(db)):
    t=Target(**body.model_dump(),created_by=u.id); s.add(t); s.flush(); audit(s,u,'target.create',request,t.id,details=t.host); s.commit(); return t
@app.get('/targets')
def targets(skip:int=0,limit:int=100,u:User=Depends(current),s:Session=Depends(db)): return [target_response(t) for t in s.query(Target).offset(skip).limit(min(limit,100)).all()]
@app.get('/targets/{target_id}')
def target(target_id:int,u:User=Depends(current),s:Session=Depends(db)):
    if not (t:=s.get(Target,target_id)): raise HTTPException(404,'Target not found')
    return target_response(t)
@app.put('/targets/{target_id}')
def update_target(target_id:int,body:TargetIn,request:Request,u:User=Depends(roles('admin','analyst')),s:Session=Depends(db)):
    if not (t:=s.get(Target,target_id)): raise HTTPException(404,'Target not found')
    for k,v in body.model_dump().items(): setattr(t,k,v)
    audit(s,u,'target.update',request,t.id); s.commit(); return t
@app.delete('/targets/{target_id}',status_code=204)
def delete_target(target_id:int,request:Request,u:User=Depends(roles('admin')),s:Session=Depends(db)):
    if not (t:=s.get(Target,target_id)): raise HTTPException(404,'Target not found')
    if s.query(Scan).filter_by(target_id=target_id).first(): raise HTTPException(409,'Targets with assessment history cannot be deleted')
    audit(s,u,'target.delete',request,target_id); s.delete(t); s.commit(); return Response(status_code=204)
@app.post('/targets/{target_id}/authorize')
def authorize(target_id:int,body:AuthorizationIn,request:Request,u:User=Depends(roles('admin')),s:Session=Depends(db)):
    if body.authorization_end<=body.authorization_start: raise HTTPException(422,'Authorization end must follow start')
    if not (t:=s.get(Target,target_id)): raise HTTPException(404,'Target not found')
    t.authorization_status='authorized'; t.authorization_reference=body.authorization_reference; t.authorization_start=body.authorization_start.replace(tzinfo=None); t.authorization_end=body.authorization_end.replace(tzinfo=None); audit(s,u,'target.authorize',request,t.id,details=body.authorization_reference); s.commit(); return t
@app.post('/scans',status_code=202)
def start_scan(body:ScanIn,background:BackgroundTasks,request:Request,u:User=Depends(roles('admin','analyst')),s:Session=Depends(db)):
    if not (t:=s.get(Target,body.target_id)): raise HTTPException(404,'Target not found')
    valid_authorization(t)
    if body.mode=='live':
        if not LIVE_ENABLED: raise HTTPException(403,'Live scanning is disabled by configuration')
        if body.tool=='mock': raise HTTPException(422,'Mock adapter cannot run in live mode')
        expected={'asset_discovery':'nmap','vulnerability_scan':'nuclei','web_scan':'zap'}[body.scan_type]
        if body.tool!=expected: raise HTTPException(422,f'{body.scan_type} requires the {expected} adapter')
        if not scanner_status().get(body.tool): raise HTTPException(503,f'{body.tool} unavailable')
    scan=Scan(**body.model_dump(),status='queued',initiated_by=u.id); s.add(scan); s.flush(); audit(s,u,'scan.start',request,t.id,scan.id,f'{body.mode}:{body.tool}'); s.commit()
    if CELERY_ENABLED:
        from app.tasks import run_scan_task
        run_scan_task.delay(scan.id, body.mode)
    else:
        background.add_task(run_live if body.mode == 'live' else run_mock, scan.id)
    return scan
@app.get('/scans')
def scans(skip:int=0,limit:int=100,u:User=Depends(current),s:Session=Depends(db)): return s.query(Scan).order_by(Scan.id.desc()).offset(skip).limit(min(limit,100)).all()
@app.get('/scans/{scan_id}')
def scan(scan_id:int,u:User=Depends(current),s:Session=Depends(db)):
    if not (x:=s.get(Scan,scan_id)): raise HTTPException(404,'Scan not found')
    return x
@app.post('/scans/{scan_id}/cancel')
def cancel(scan_id:int,request:Request,u:User=Depends(roles('admin','analyst')),s:Session=Depends(db)):
    if not (x:=s.get(Scan,scan_id)): raise HTTPException(404,'Scan not found')
    if x.status not in ('queued','running'): raise HTTPException(409,'Scan is not cancellable')
    x.status='cancelled'; audit(s,u,'scan.cancel',request,x.target_id,x.id); s.commit(); return x
@app.get('/assets')
def assets(skip:int=0,limit:int=100,u:User=Depends(current),s:Session=Depends(db)): return s.query(Asset).offset(skip).limit(min(limit,100)).all()
@app.get('/assets/{asset_id}')
def asset(asset_id:int,u:User=Depends(current),s:Session=Depends(db)):
    if not (x:=s.get(Asset,asset_id)): raise HTTPException(404,'Asset not found')
    return x
@app.get('/vulnerabilities')
def vulnerabilities(severity:str|None=None,source:str|None=None,skip:int=0,limit:int=100,u:User=Depends(current),s:Session=Depends(db)):
    q=s.query(Vulnerability)
    if severity:q=q.filter(func.lower(Vulnerability.severity)==severity.lower())
    if source:q=q.filter(Vulnerability.source.contains(source))
    return q.offset(skip).limit(min(limit,100)).all()
@app.get('/vulnerabilities/{vuln_id}')
def vulnerability(vuln_id:int,u:User=Depends(current),s:Session=Depends(db)):
    v=s.get(Vulnerability,vuln_id)
    if not v: raise HTTPException(404,'Vulnerability not found')
    return {'vulnerability':v,'enrichment':s.query(Enrichment).filter_by(vulnerability_id=v.id).first(),'risk':s.query(Risk).filter_by(vulnerability_id=v.id).first(),'recommendation':s.query(Recommendation).filter_by(vulnerability_id=v.id).first()}
@app.get('/risk-assessments')
def risks(u:User=Depends(current),s:Session=Depends(db)): return s.query(Risk).order_by(Risk.final_score.desc()).all()
@app.get('/risk-assessments/{risk_id}/explanation')
def risk_explanation(risk_id:int,u:User=Depends(current),s:Session=Depends(db)):
    risk=s.get(Risk,risk_id)
    if not risk: raise HTTPException(404,'Risk assessment not found')
    vuln=s.get(Vulnerability,risk.vulnerability_id); asset=s.get(Asset,vuln.asset_id)
    enrichment=s.query(Enrichment).filter_by(vulnerability_id=vuln.id).first()
    fields={
        'cvss_score':vuln.cvss_score,'known_exploited':int(bool(enrichment and enrichment.known_exploited)),
        'asset_exposure':10 if asset.port in (22,80,443,3389) else 5,
        'service_exposure':10 if asset.service in ('http','https','ssh','rdp') else 5,
        'port':asset.port,'exploitability_score':enrichment.exploitability_score if enrichment else 0,
        'vulnerability_age':0,'attack_vector':vuln.attack_vector,'attack_complexity':vuln.attack_complexity,
        'privileges_required':vuln.privileges_required,'user_interaction':vuln.user_interaction,
        'confidentiality_impact':vuln.confidentiality_impact,'integrity_impact':vuln.integrity_impact,
        'availability_impact':vuln.availability_impact,
    }
    try:
        from ml.explain import explain
        result=explain(fields)
    except (FileNotFoundError,ImportError,ValueError) as exc:
        result={'available':False,'reason':str(exc),'factors':[]}
    return {'risk_id':risk.id,'vulnerability_id':vuln.id,'model_version':risk.model_version,
            'final_score':risk.final_score,'explanation':result}
@app.get('/recommendations')
def recommendations(u:User=Depends(current),s:Session=Depends(db)): return s.query(Recommendation).all()
@app.post('/enrichment/{source}')
def enrich(source:Literal['nvd','kev'],request:Request,u:User=Depends(roles('admin','analyst')),s:Session=Depends(db)):
    audit(s,u,f'enrichment.{source}',request,details='Requested; local cache integration point'); s.commit(); return {'status':'accepted','source':source,'message':'Use dataset scripts to refresh the local authoritative cache.'}
@app.get('/dashboard/summary')
def summary(u:User=Depends(current),s:Session=Depends(db)):
    counts={x:s.query(Vulnerability).filter(func.lower(Vulnerability.severity)==x).count() for x in ('critical','high','medium','low')}
    return {'targets':s.query(Target).count(),'assets':s.query(Asset).count(),'vulnerabilities':s.query(Vulnerability).count(),'known_exploited':s.query(Enrichment).filter_by(known_exploited=True).count(),**counts}
@app.get('/dashboard/risk-distribution')
def distribution(u:User=Depends(current),s:Session=Depends(db)): return [{'name':k,'value':v} for k,v in s.query(Risk.risk_level,func.count(Risk.id)).group_by(Risk.risk_level).all()]
@app.get('/dashboard/top-vulnerabilities')
def top(u:User=Depends(current),s:Session=Depends(db)): return [{'vulnerability':v,'risk':r} for v,r in s.query(Vulnerability,Risk).join(Risk,Risk.vulnerability_id==Vulnerability.id).order_by(Risk.final_score.desc()).limit(10)]
@app.get('/audit-logs')
def logs(u:User=Depends(roles('admin')),s:Session=Depends(db)): return s.query(Audit).order_by(Audit.timestamp.desc()).limit(500).all()
@app.get('/integrations/defectdojo/export/{scan_id}')
def defectdojo_export(scan_id:int,u:User=Depends(roles('admin','analyst')),s:Session=Depends(db)):
    scan=s.get(Scan,scan_id)
    if not scan or scan.status!='completed': raise HTTPException(409,'A completed scan is required')
    rows=s.query(Vulnerability,Risk).join(Risk,Risk.vulnerability_id==Vulnerability.id).filter(Vulnerability.scan_id==scan_id).all()
    return {
        'scan_id':scan_id,'scan_type':'Generic Findings Import','minimum_severity':'Info',
        'findings':[{'title':v.title,'description':v.description,'severity':v.severity.title(),
                     'numerical_severity':r.final_score,'cve':v.cve_id,'cvssv3_score':v.cvss_score,
                     'mitigation':(s.query(Recommendation).filter_by(vulnerability_id=v.id).first().recommendation
                                   if s.query(Recommendation).filter_by(vulnerability_id=v.id).first() else ''),
                     'active':True,'verified':False,'dynamic_finding':True} for v,r in rows]
    }
@app.post('/integrations/trivy/import/{target_id}',status_code=201)
def trivy_import(target_id:int,report_body:dict,request:Request,u:User=Depends(roles('admin','analyst')),s:Session=Depends(db)):
    target=s.get(Target,target_id)
    if not target: raise HTTPException(404,'Target not found')
    valid_authorization(target)
    findings=parse_trivy_report(report_body)
    scan=Scan(target_id=target.id,scan_type='software_supply_chain',status='running',initiated_by=u.id,
              tool='trivy',mode='import',started_at=datetime.utcnow())
    s.add(scan); s.flush()
    count=store_findings(s,scan,target,findings)
    scan.status='completed'; scan.completed_at=datetime.utcnow()
    audit(s,u,'trivy.import',request,target.id,scan.id,f'findings:{count}')
    s.commit()
    return {'scan_id':scan.id,'findings_imported':count,'status':'completed'}
@app.get('/reports/{scan_id}')
def report(scan_id:int,format:Literal['pdf','json','csv']='pdf',u:User=Depends(current),s:Session=Depends(db)):
    scan=s.get(Scan,scan_id)
    if not scan: raise HTTPException(404,'Scan not found')
    if scan.status != 'completed': raise HTTPException(409,f'Report is not ready; scan status is {scan.status}')
    target=s.get(Target,scan.target_id); rows=s.query(Vulnerability,Risk).join(Risk,Risk.vulnerability_id==Vulnerability.id).filter(Vulnerability.scan_id==scan_id).all()
    data=[]
    for v,r in rows:
        asset=s.get(Asset,v.asset_id)
        enrichment=s.query(Enrichment).filter_by(vulnerability_id=v.id).first()
        rec=s.query(Recommendation).filter_by(vulnerability_id=v.id).first()
        data.append({'cve':v.cve_id,'title':v.title,'severity':v.severity,'cvss':v.cvss_score,
            'final_risk':r.final_score,'priority':r.risk_level,'source':v.source,
            'rule_score':r.rule_based_score,'ml_score':r.ml_score,'confidence':r.confidence,
            'asset':asset.ip if asset else target.host,'port':asset.port if asset else 0,
            'service':asset.service if asset else 'unknown','description':v.description,'evidence':v.evidence,
            'known_exploited':bool(enrichment and enrichment.known_exploited),
            'recommendation':rec.recommendation if rec else 'Perform safe analyst validation.',
            'reason':rec.reason if rec else 'No generated recommendation was stored.',
            'safe_validation':rec.safe_validation if rec else 'Validate without exploitation or disruption.'})
    if format=='json': return {'project':app.title,'target':target.host,'authorization_reference':target.authorization_reference,'scan':scan_id,'findings':data}
    if format=='csv':
        out=io.StringIO(); w=csv.DictWriter(out,fieldnames=list(data[0]) if data else ['cve','title','severity','cvss','final_risk','priority','source']); w.writeheader(); w.writerows(data)
        return StreamingResponse(iter([out.getvalue()]),media_type='text/csv',headers={'Content-Disposition':f'attachment; filename=scan-{scan_id}.csv'})
    raw_assets=s.query(Asset).filter_by(target_id=target.id).order_by(Asset.ip,Asset.port).all()
    assets=list({(a.ip,a.port,a.protocol,a.service,a.version):a for a in raw_assets}.values())
    raw_audits=s.query(Audit).filter((Audit.scan_id==scan.id)|(Audit.target_id==target.id)).order_by(Audit.timestamp).all()
    audits=list({(a.timestamp.replace(microsecond=0),a.action,a.user_id,a.details):a for a in raw_audits}.values())
    out=build_pdf_report(target,scan,assets,data,audits)
    return StreamingResponse(out,media_type='application/pdf',headers={'Content-Disposition':f'attachment; filename=scan-{scan_id}.pdf'})

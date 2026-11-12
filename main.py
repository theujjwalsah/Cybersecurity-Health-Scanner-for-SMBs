import secrets, re, io, csv, socket, ipaddress
from datetime import datetime
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session
from sqlalchemy import desc
import dns.resolver
from .database import Base, engine, get_db
from .models import User, Domain, Scan, Finding
from .security import hash_password, verify_password, create_token, token_user_id
from .scanner import run_scan, valid_hostname

Base.metadata.create_all(bind=engine)
app = FastAPI(title="CyberHealth API", version="1.0.0",
              description="Authorized, non-destructive external security posture assessment.")
app.mount("/static", StaticFiles(directory="app/static"), name="static")

class Signup(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
class Login(BaseModel):
    email: EmailStr
    password: str
class DomainIn(BaseModel):
    hostname: str

def current_user(authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Please log in.")
    uid = token_user_id(authorization[7:])
    user = db.get(User, uid) if uid else None
    if not user:
        raise HTTPException(401, "Session expired. Please log in again.")
    return user

def owned_domain(domain_id: int, user: User, db: Session):
    d = db.query(Domain).filter(Domain.id == domain_id, Domain.user_id == user.id).first()
    if not d:
        raise HTTPException(404, "Domain not found.")
    return d

@app.get("/")
def root():
    return FileResponse("app/static/index.html")

@app.post("/api/auth/signup")
def signup(data: Signup, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == data.email.lower()).first():
        raise HTTPException(409, "An account with this email already exists.")
    user = User(name=data.name.strip(), email=data.email.lower(), password_hash=hash_password(data.password))
    db.add(user); db.commit(); db.refresh(user)
    return {"token": create_token(user.id), "user": {"id": user.id, "name": user.name, "email": user.email}}

@app.post("/api/auth/login")
def login(data: Login, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email.lower()).first()
    if not user or not verify_password(data.password, user.password_hash):
        raise HTTPException(401, "Invalid email or password.")
    return {"token": create_token(user.id), "user": {"id": user.id, "name": user.name, "email": user.email}}

@app.get("/api/me")
def me(user: User = Depends(current_user)):
    return {"id": user.id, "name": user.name, "email": user.email}

@app.post("/api/domains")
def add_domain(data: DomainIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    host = data.hostname.strip().lower().removeprefix("https://").removeprefix("http://").split("/")[0].rstrip(".")
    if not valid_hostname(host):
        raise HTTPException(400, "Enter a valid hostname, such as example.com.")
    if db.query(Domain).filter(Domain.hostname == host, Domain.user_id == user.id).first():
        raise HTTPException(409, "This domain is already in your account.")
    # The token column remains populated for compatibility with existing databases;
    # public DNS/reachability verification does not require changing the domain's DNS.
    token = "reachability-check=" + secrets.token_urlsafe(24)
    d = Domain(hostname=host, verification_token=token, user_id=user.id)
    db.add(d); db.commit(); db.refresh(d)
    return {"id": d.id, "hostname": host, "verified": False,
            "instructions": "Check public DNS resolution and endpoint reachability."}

@app.post("/api/domains/{domain_id}/verify")
def verify_domain(domain_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    d = owned_domain(domain_id, user, db)
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(d.hostname, None, type=socket.SOCK_STREAM)}
        public_addresses = [addr for addr in addresses if ipaddress.ip_address(addr).is_global]
    except socket.gaierror:
        public_addresses = []
    if not public_addresses:
        raise HTTPException(400, "No public DNS address could be confirmed for this domain.")
    d.verified = True; db.commit()
    return {"verified": True, "hostname": d.hostname, "addresses": sorted(public_addresses),
            "verification_method": "Public DNS resolution"}

@app.get("/api/domains")
def domains(user: User = Depends(current_user), db: Session = Depends(get_db)):
    result = []
    for d in db.query(Domain).filter(Domain.user_id == user.id).order_by(desc(Domain.created_at)).all():
        latest = db.query(Scan).filter(Scan.domain_id == d.id).order_by(desc(Scan.created_at)).first()
        result.append({"id": d.id, "hostname": d.hostname, "verified": d.verified,
                       "created_at": d.created_at.isoformat(), "latest_score": latest.score if latest else None})
    return result

@app.delete("/api/domains/{domain_id}")
def delete_domain(domain_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    d = owned_domain(domain_id, user, db); db.delete(d); db.commit()
    return {"deleted": True}

@app.post("/api/domains/{domain_id}/scan")
def scan_domain(domain_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    d = owned_domain(domain_id, user, db)
    if not d.verified:
        raise HTTPException(403, "Confirm public DNS reachability before scanning.")
    try:
        result = run_scan(d.hostname)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    scan = Scan(domain_id=d.id, score=result["score"], status="completed")
    db.add(scan); db.flush()
    for f in result["findings"]:
        db.add(Finding(scan_id=scan.id, **f))
    db.commit(); db.refresh(scan)
    return {"id": scan.id, "score": scan.score, "findings_count": len(result["findings"]),
            "checked_at": scan.created_at.isoformat(), "summary": result["summary"]}

@app.get("/api/dashboard")
def dashboard(user: User = Depends(current_user), db: Session = Depends(get_db)):
    ds = db.query(Domain).filter(Domain.user_id == user.id).all()
    domain_ids = [d.id for d in ds]
    scans = db.query(Scan).filter(Scan.domain_id.in_(domain_ids)).order_by(desc(Scan.created_at)).all() if domain_ids else []
    latest_by_domain = {}
    for s in scans:
        latest_by_domain.setdefault(s.domain_id, s)
    scores = [s.score for s in latest_by_domain.values()]
    all_findings = db.query(Finding).join(Scan).filter(Scan.domain_id.in_(domain_ids)).all() if domain_ids else []
    open_findings = [f for f in all_findings if f.status != "resolved"]
    counts = {x: sum(1 for f in open_findings if f.severity == x) for x in ["critical","high","medium","low"]}
    return {"health_score": round(sum(scores)/len(scores)) if scores else None,
            "domains": len(ds), "verified_domains": sum(1 for d in ds if d.verified),
            "scans": len(scans), "open_findings": len(open_findings), "severity": counts,
            "recent_scans": [{"id": s.id, "domain": s.domain.hostname, "score": s.score, "created_at": s.created_at.isoformat()} for s in scans[:8]]}

@app.get("/api/findings")
def findings(user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.query(Finding).join(Scan).join(Domain).filter(Domain.user_id == user.id).order_by(desc(Finding.created_at)).all()
    return [{"id": f.id, "scan_id": f.scan_id, "domain": f.scan.domain.hostname, "title": f.title,
             "category": f.category, "severity": f.severity, "description": f.description,
             "evidence": f.evidence, "recommendation": f.recommendation, "status": f.status,
             "created_at": f.created_at.isoformat()} for f in rows]

@app.patch("/api/findings/{finding_id}/resolve")
def resolve_finding(finding_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    f = db.query(Finding).join(Scan).join(Domain).filter(Finding.id == finding_id, Domain.user_id == user.id).first()
    if not f: raise HTTPException(404, "Finding not found.")
    f.status = "resolved"; db.commit()
    return {"resolved": True}

@app.get("/api/scans")
def scans(user: User = Depends(current_user), db: Session = Depends(get_db)):
    ids = [d.id for d in db.query(Domain.id).filter(Domain.user_id == user.id).all()]
    rows = db.query(Scan).filter(Scan.domain_id.in_(ids)).order_by(desc(Scan.created_at)).all() if ids else []
    return [{"id": s.id, "domain": s.domain.hostname, "score": s.score, "status": s.status,
             "created_at": s.created_at.isoformat(), "findings": len(s.findings)} for s in rows]

@app.get("/api/scans/{scan_id}/report.csv")
def report_csv(scan_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    s = db.query(Scan).join(Domain).filter(Scan.id == scan_id, Domain.user_id == user.id).first()
    if not s: raise HTTPException(404, "Scan not found.")
    output = io.StringIO(); writer = csv.writer(output)
    writer.writerow(["Domain", "Score", "Finding", "Category", "Severity", "Status", "Evidence", "Recommendation"])
    for f in s.findings:
        writer.writerow([s.domain.hostname, s.score, f.title, f.category, f.severity, f.status, f.evidence, f.recommendation])
    output.seek(0)
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="cyberhealth-scan-{scan_id}.csv"'})

@app.get("/api/health")
def health():
    return {"status": "ok", "service": "CyberHealth API"}
